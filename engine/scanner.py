"""AST-based detection rules for the in-scope files (target_app/SCOPE.md).

Each rule matches a code pattern, not a line number, and reports the exact span it found.
One finding per (file, type): the first matching site.
"""

import ast
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from engine.models import PATCHABLE_TYPES, Finding

# file -> (first_line, last_line) to scan, or None for the whole file
IN_SCOPE: dict[str, tuple[int, int] | None] = {
    "ai_agent_deepseek.py": None,
    "app.py": (2328, 2476),
}

LLM_SINK = re.compile(r"(api|llm|complet|deepseek|openai|chat_model)", re.I)
USER_INPUT = re.compile(r"(message|prompt|query|input)", re.I)
OVERRIDE_PHRASES = re.compile(
    r"ignore (previous )?instructions|follow the new instructions|comply|prioritize user requests|change your role", re.I
)

Span = tuple[int, int]


def _calls(node: ast.AST) -> Iterator[ast.Call]:
    return (n for n in ast.walk(node) if isinstance(n, ast.Call))


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _functions(tree: ast.AST) -> Iterator[ast.FunctionDef]:
    return (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))


def _dict_keys(node: ast.AST) -> set[str]:
    return {k.value for d in ast.walk(node) if isinstance(d, ast.Dict) for k in d.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def rule_prompt_injection(tree: ast.AST) -> Span | None:
    """User-controlled text formatted into a prompt that is sent to an LLM call."""
    for fn in _functions(tree):
        user_params = {a.arg for a in fn.args.args if a.arg != "self" and USER_INPUT.search(a.arg)}
        if not user_params:
            continue
        for assign in (n for n in ast.walk(fn) if isinstance(n, ast.Assign) and isinstance(n.value, ast.JoinedStr)):
            uses_input = any(isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and v.value.id in user_params for v in assign.value.values)
            target = assign.targets[0]
            if not (uses_input and isinstance(target, ast.Name)):
                continue
            sent = any(LLM_SINK.search(_call_name(c)) and any(isinstance(a, ast.Name) and a.id == target.id for a in c.args) for c in _calls(fn))
            if not sent:
                continue
            # An `x or self._is_prompt_injection_request(...)` condition that grants extra access widens the span.
            grants = [
                n.lineno for n in ast.walk(fn)
                if isinstance(n, ast.If) and isinstance(n.test, ast.BoolOp) and isinstance(n.test.op, ast.Or)
                and any(isinstance(v, ast.Call) and "injection" in _call_name(v) for v in n.test.values)
            ]
            return (min([assign.lineno, *grants]), assign.end_lineno or assign.lineno)
    return None


def rule_broken_auth(tree: ast.AST) -> Span | None:
    """A function receives the caller's identity (user_context) but runs parameterised lookups without ever using it."""
    for fn in _functions(tree):
        if "user_context" not in {a.arg for a in fn.args.args}:
            continue
        body_reads_identity = any(isinstance(n, ast.Name) and n.id == "user_context" and isinstance(n.ctx, ast.Load) for n in ast.walk(fn))
        if body_reads_identity:
            continue
        for branch in (n for n in ast.walk(fn) if isinstance(n, ast.If)):
            lookups = [c for c in _calls(branch) if _call_name(c) == "execute_query" and len(c.args) >= 2]
            if lookups:
                return (branch.lineno, branch.end_lineno or branch.lineno)
    return None


def rule_info_disclosure(tree: ast.AST) -> Span | None:
    """A function returns the system prompt, or an unauthenticated route exposes get_system_info()."""
    for fn in _functions(tree):
        returns_prompt = any(isinstance(r, ast.Return) and r.value is not None and "system_prompt" in _dict_keys(r.value) for r in ast.walk(fn))
        decorators = {_call_name(d) if isinstance(d, ast.Call) else getattr(d, "id", "") for d in fn.decorator_list}
        unauth_route = "route" in decorators and "token_required" not in decorators and "get_system_info" in {_call_name(c) for c in _calls(fn)} and "system_info" in fn.name
        if returns_prompt or unauth_route:
            return (fn.lineno, fn.end_lineno or fn.lineno)
    return None


def rule_verbose_errors(tree: ast.AST) -> Span | None:
    """An exception handler returns the raw exception text or secrets to the caller."""
    for h in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and n.name):
        for ret in (n for n in ast.walk(h) if isinstance(n, ast.Return) and n.value is not None):
            echoes_exc = any(
                isinstance(c, ast.Call) and _call_name(c) == "str" and any(isinstance(a, ast.Name) and a.id == h.name for a in c.args)
                for c in ast.walk(ret)
            ) and any(isinstance(n, ast.JoinedStr) for n in ast.walk(ret))
            leaks = _dict_keys(ret) & {"api_key_preview", "system_info"}
            if echoes_exc and leaks:
                return (h.lineno, h.end_lineno or h.lineno)
    return None


def rule_role_override(tree: ast.AST) -> Span | None:
    """The system prompt itself tells the model to obey instruction or role overrides."""
    for a in (n for n in ast.walk(tree) if isinstance(n, ast.Assign)):
        t = a.targets[0]
        if isinstance(t, ast.Attribute) and t.attr == "system_prompt" and isinstance(a.value, ast.Constant) and isinstance(a.value.value, str):
            hits = [a.lineno + i for i, line in enumerate(a.value.value.split("\n")) if OVERRIDE_PHRASES.search(line)]
            if hits:
                return (min(hits), max(hits))
    return None


RULES: list[tuple[str, str, str, Callable[[ast.AST], Span | None], dict[str, tuple[str, str]]]] = [
    # type, severity, cwe, rule, per-file (title, severity_rationale)
    ("AI_PROMPT_INJECTION", "CRITICAL", "CWE-77", rule_prompt_injection, {
        "ai_agent_deepseek.py": (
            "User text goes straight into the model prompt",
            'Anyone can type instructions that the assistant obeys. Typing "ignore" also unlocks a dump of every customer record into the conversation.',
        ),
    }),
    ("AI_BROKEN_AUTH", "HIGH", "CWE-862", rule_broken_auth, {
        "ai_agent_deepseek.py": (
            "Assistant looks up any customer's balance",
            "A signed-in customer can ask about someone else by name and the assistant fetches their account number and balance. Nothing checks who is asking.",
        ),
    }),
    ("AI_INFO_DISCLOSURE", "MEDIUM", "CWE-200", rule_info_disclosure, {
        "ai_agent_deepseek.py": (
            "System prompt and model config are exposed",
            "get_system_info() returns the full system prompt, the model name and the API endpoint to anyone who can call it.",
        ),
        "app.py": (
            "System info endpoint needs no login",
            "/api/ai/system-info has no authentication and returns get_system_info(), including the system prompt, to any visitor.",
        ),
    }),
    ("VERBOSE_ERROR_DISCLOSURE", "MEDIUM", "CWE-209", rule_verbose_errors, {
        "ai_agent_deepseek.py": (
            "Error replies leak an API key preview",
            "When the model call fails, the reply includes internal details, the full system info and the first ten characters of the API key.",
        ),
        "app.py": (
            "Chat errors return raw exception text",
            "The AI chat routes send the raw exception message and the full system info back to the caller whenever something fails.",
        ),
    }),
    ("AI_ROLE_OVERRIDE", "LOW", "CWE-1427", rule_role_override, {
        "ai_agent_deepseek.py": (
            "System prompt tells the model to obey overrides",
            "The model is told to follow any request to ignore its instructions or change role. Reported for context; behavioural fixes are out of scope.",
        ),
    }),
]


def scan_repository(repo_path: str) -> list[Finding]:
    """Statically scan the in-scope files under repo_path."""
    findings: list[Finding] = []
    root = Path(repo_path)
    for rel, window in IN_SCOPE.items():
        path = root / rel
        if not path.is_file():
            continue
        source = path.read_text()
        tree = ast.parse(source, filename=rel)
        lines = source.splitlines()
        lo, hi = window or (1, len(lines))
        if window:
            tree = ast.Module(body=[n for n in tree.body if n.lineno <= hi and (n.end_lineno or n.lineno) >= lo], type_ignores=[])
        for vtype, severity, cwe, rule, texts in RULES:
            if rel not in texts:
                continue
            span = rule(tree)
            if not span or span[0] < lo or span[0] > hi:
                continue
            start, end = span[0], min(span[1], hi)
            title, rationale = texts[rel]
            findings.append({
                "file_path": rel,
                "line_number": start,
                "end_line": end,
                "severity": severity,  # type: ignore[typeddict-item]
                "type": vtype,  # type: ignore[typeddict-item]
                "cwe": cwe,
                "title": title,
                "severity_rationale": rationale,
                "original_code": "\n".join(lines[start - 1 : end]),
                "patchable": vtype in PATCHABLE_TYPES,
            })
    return findings

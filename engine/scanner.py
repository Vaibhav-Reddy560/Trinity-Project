"""AST-based scanner. Which files and rule packs apply comes from the target profile.

Two rule packs:
- "ai": LLM-app weaknesses (prompt injection, unscoped lookups, prompt/config exposure).
  One finding per (file, type): the first matching site.
- "generic": any Python codebase (engine/generic_rules.py), every occurrence.
Rules match code patterns, not line numbers, and report the exact span they found.
"""

import ast
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from engine import ai, generic_rules
from engine.generic_rules import Hit
from engine.models import Finding
from engine.patcher import can_patch, clear_caches, has_patcher
from engine.targets import cases_for_profile, in_scope_files, load_profile

MAX_SNIPPET_LINES = 40

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


def _guarded(fn: ast.FunctionDef, params: set[str], before: int) -> bool:
    """An early exit on the user's text before the prompt is built: if PATTERN.search(message): return ..."""
    return any(
        isinstance(n, ast.If) and n.lineno < before
        and any(isinstance(x, ast.Name) and x.id in params for x in ast.walk(n.test))
        and any(isinstance(b, (ast.Return, ast.Raise)) for b in n.body)
        for n in ast.walk(fn)
    )


def prompt_injection_sites(tree: ast.AST) -> Iterator[Span]:
    """User-controlled text formatted into a prompt that is sent to an LLM call, with no input guard first."""
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
            if not sent or _guarded(fn, user_params, assign.lineno):
                continue
            # An `x or self._is_prompt_injection_request(...)` condition that grants extra access widens the span.
            grants = [
                n.lineno for n in ast.walk(fn)
                if isinstance(n, ast.If) and isinstance(n.test, ast.BoolOp) and isinstance(n.test.op, ast.Or)
                and any(isinstance(v, ast.Call) and "injection" in _call_name(v) for v in n.test.values)
            ]
            yield (min([assign.lineno, *grants]), assign.end_lineno or assign.lineno)


def broken_auth_sites(tree: ast.AST) -> Iterator[Span]:
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
                yield (branch.lineno, branch.end_lineno or branch.lineno)


def info_disclosure_sites(tree: ast.AST) -> Iterator[Span]:
    """A function returns the system prompt, or an unauthenticated route exposes get_system_info()."""
    for fn in _functions(tree):
        returns_prompt = any(isinstance(r, ast.Return) and r.value is not None and "system_prompt" in _dict_keys(r.value) for r in ast.walk(fn))
        decorators = {_call_name(d) if isinstance(d, ast.Call) else getattr(d, "id", "") for d in fn.decorator_list}
        unauth_route = "route" in decorators and "token_required" not in decorators and "get_system_info" in {_call_name(c) for c in _calls(fn)} and "system_info" in fn.name
        if returns_prompt or unauth_route:
            yield (fn.lineno, fn.end_lineno or fn.lineno)


def verbose_errors_sites(tree: ast.AST) -> Iterator[Span]:
    """An exception handler returns the raw exception text or secrets to the caller."""
    for h in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and n.name):
        for ret in (n for n in ast.walk(h) if isinstance(n, ast.Return) and n.value is not None):
            echoes_exc = any(
                isinstance(c, ast.Call) and _call_name(c) == "str" and any(isinstance(a, ast.Name) and a.id == h.name for a in c.args)
                for c in ast.walk(ret)
            ) and any(isinstance(n, ast.JoinedStr) for n in ast.walk(ret))
            leaks = _dict_keys(ret) & {"api_key_preview", "system_info"}
            if echoes_exc and leaks:
                yield (h.lineno, h.end_lineno or h.lineno)


def role_override_sites(tree: ast.AST) -> Iterator[Span]:
    """The system prompt itself tells the model to obey instruction or role overrides."""
    for a in (n for n in ast.walk(tree) if isinstance(n, ast.Assign)):
        t = a.targets[0]
        if isinstance(t, ast.Attribute) and t.attr == "system_prompt" and isinstance(a.value, ast.Constant) and isinstance(a.value.value, str):
            hits = [a.lineno + i for i, line in enumerate(a.value.value.split("\n")) if OVERRIDE_PHRASES.search(line)]
            if hits:
                yield (min(hits), max(hits))


# The scanner reports the first site per file (one finding per type); the proof checks count every site,
# so fixing the first one doesn't make the next one look new.
def rule_prompt_injection(tree: ast.AST) -> Span | None:
    return next(prompt_injection_sites(tree), None)


def rule_broken_auth(tree: ast.AST) -> Span | None:
    return next(broken_auth_sites(tree), None)


def rule_info_disclosure(tree: ast.AST) -> Span | None:
    return next(info_disclosure_sites(tree), None)


def rule_verbose_errors(tree: ast.AST) -> Span | None:
    return next(verbose_errors_sites(tree), None)


def rule_role_override(tree: ast.AST) -> Span | None:
    return next(role_override_sites(tree), None)


# type, severity, cwe, rule, default (title, rationale). Profiles may override the wording per file.
AI_RULES: list[tuple[str, str, str, Callable[[ast.AST], Span | None], tuple[str, str]]] = [
    ("AI_PROMPT_INJECTION", "CRITICAL", "CWE-77", rule_prompt_injection, (
        "User text goes straight into the model prompt",
        "Text from the user is formatted into the prompt sent to the model with no guard, so instructions hidden in it are followed.",
    )),
    ("AI_BROKEN_AUTH", "HIGH", "CWE-862", rule_broken_auth, (
        "Lookups ignore who is asking",
        "The function receives the caller's identity but runs its lookups without using it, so one user can read another's data.",
    )),
    ("AI_INFO_DISCLOSURE", "MEDIUM", "CWE-200", rule_info_disclosure, (
        "System prompt or model config exposed",
        "The system prompt and model configuration are returned to callers, which helps attackers craft targeted prompt attacks.",
    )),
    ("VERBOSE_ERROR_DISCLOSURE", "MEDIUM", "CWE-209", rule_verbose_errors, (
        "Errors return internal details",
        "When something fails, the raw exception text and internal configuration are sent back to the caller.",
    )),
    ("AI_ROLE_OVERRIDE", "LOW", "CWE-1427", rule_role_override, (
        "Prompt tells the model to obey overrides",
        "The system prompt instructs the model to follow requests to ignore its instructions or change role.",
    )),
]


AI_SITES: dict[str, Callable[[ast.AST], Iterator[Span]]] = {
    "AI_PROMPT_INJECTION": prompt_injection_sites, "AI_BROKEN_AUTH": broken_auth_sites, "AI_INFO_DISCLOSURE": info_disclosure_sites,
    "VERBOSE_ERROR_DISCLOSURE": verbose_errors_sites, "AI_ROLE_OVERRIDE": role_override_sites,
}


def _enclosing(tree: ast.AST, line: int) -> str:
    best, start = "<module>", 0
    for fn in _functions(tree):
        if fn.lineno <= line <= (fn.end_lineno or fn.lineno) and fn.lineno >= start:
            best, start = fn.name, fn.lineno
    return best


def _ai_hits(tree: ast.AST) -> Iterator[tuple[str, str, str, Hit]]:
    """Every site of each AI rule. A span inside an earlier one (an elif of the same lookup) is the same weakness.
    The first site's anchor is empty, so IDs from before every site was reported stay the same."""
    for vtype, severity, cwe, _, (title, rationale) in AI_RULES:
        kept: list[Span] = []
        for lo, hi in AI_SITES[vtype](tree):
            if any(a <= lo and hi <= b for a, b in kept):
                continue
            anchor = "" if not kept else f"{_enclosing(tree, lo)}#{sum(1 for a, _ in kept if _enclosing(tree, a) == _enclosing(tree, lo))}"
            kept.append((lo, hi))
            yield vtype, severity, cwe, Hit(lo, hi, title, rationale, anchor)


def _generic_hits(tree: ast.AST) -> Iterator[tuple[str, str, str, Hit]]:
    ctx = generic_rules.Context(tree)
    for vtype, severity, cwe, rule in generic_rules.GENERIC_RULES:
        seen: set[str] = set()
        for hit in rule(tree, ctx):
            if hit.anchor not in seen:
                seen.add(hit.anchor)
                yield vtype, severity, cwe, hit


PACKS = {"ai": _ai_hits, "generic": _generic_hits}


def flagged(tree: ast.AST, packs: list[str]) -> list[tuple[str, int, int]]:
    """(type, start, end) of every rule hit in a parsed file, every site included. The proof checks compare these
    before and after a fix."""
    out = [(vtype, hit.start, hit.end) for vtype, _, _, hit in _generic_hits(tree)] if "generic" in packs else []
    if "ai" in packs:
        out += [(vtype, lo, hi) for vtype, sites in AI_SITES.items() for lo, hi in dict.fromkeys(sites(tree))]
    return out


def _is_test_file(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return any(p in ("test", "tests") for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def scan_repository(repo_path: str, profile: dict | None = None, stats: dict | None = None,
                    ai_fixes: bool | None = None) -> list[Finding]:
    """Statically scan the profile's in-scope files under repo_path. Code is parsed, never run.

    If `stats` is given it is filled with files_scanned, files_skipped and parse_errors.
    `ai_fixes` says whether Claude may fix what no rule-based patch covers (default: AI is configured).
    """
    profile = profile or load_profile()
    root = Path(repo_path)
    clear_caches()
    ai_on = ai.enabled() if ai_fixes is None else ai_fixes
    provable = {t for c in cases_for_profile(profile) if c["kind"] == "security" for t in c["types"]}
    texts = profile.get("texts", {})
    findings: list[Finding] = []
    counts = {"files_scanned": 0, "files_skipped": 0, "parse_errors": 0}

    for rel, window in in_scope_files(profile, root):
        path = root / rel
        if not path.is_file():
            continue
        try:
            source = path.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except (SyntaxError, ValueError):
            counts["parse_errors"] += 1
            continue
        counts["files_scanned"] += 1
        lines = source.splitlines()
        lo, hi = window or (1, len(lines))
        if window:
            tree = ast.Module(body=[n for n in tree.body if n.lineno <= hi and (n.end_lineno or n.lineno) >= lo], type_ignores=[])

        for pack in profile["rule_packs"]:
            for vtype, severity, cwe, hit in PACKS[pack](tree):
                if hit.start < lo or hit.start > hi:
                    continue
                if vtype == "HARDCODED_CREDENTIALS" and _is_test_file(rel):
                    continue  # test fixtures are full of throwaway credentials
                end = min(hit.end, hi, hit.start + MAX_SNIPPET_LINES - 1)
                title, rationale = texts.get(f"{rel}:{vtype}", (hit.title, hit.rationale))
                code = "\n".join(lines[hit.start - 1 : end])
                fixer = "rule" if has_patcher(vtype) and can_patch(vtype, source, code, hit.start, root) else "ai" if ai_on else None
                findings.append({
                    "file_path": rel,
                    "line_number": hit.start,
                    "end_line": end,
                    "severity": severity,  # type: ignore[typeddict-item]
                    "type": vtype,  # type: ignore[typeddict-item]
                    "cwe": cwe,
                    "title": title,
                    "severity_rationale": rationale,
                    "original_code": code,
                    "patchable": fixer is not None,
                    "provable": vtype in provable,
                    "fixer": fixer,  # type: ignore[typeddict-item]
                    "detected_by": "rule",
                    "anchor": hit.anchor,
                })

    counts["files_skipped"] = 0 if profile["kind"] == "profile" else _skipped(root)
    if stats is not None:
        stats.update(counts)
    return findings


def _skipped(root: Path) -> int:
    from engine.targets import iter_python_files
    return iter_python_files(root)[1]

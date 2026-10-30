"""Syntax-preserving fixes with LibCST. Formatting, comments and imports outside the edit stay intact."""

import difflib
from pathlib import Path

import libcst as cst
import libcst.matchers as m

from engine.harness import log
from engine.models import PatchResult, Vuln


class PatchError(Exception):
    pass


def _commented(stmt: cst.BaseStatement, text: str) -> cst.BaseStatement:
    note = cst.EmptyLine(comment=cst.Comment(f"# PatchProof: {text}"))
    return stmt.with_changes(leading_lines=[*stmt.leading_lines, note])  # type: ignore[attr-defined]


class _InFunction(cst.CSTTransformer):
    target = ""

    def __init__(self) -> None:
        self.stack: list[str] = []

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        self.stack.append(node.name.value)

    def leave_FunctionDef(self, original: cst.FunctionDef, updated: cst.FunctionDef) -> cst.FunctionDef:
        self.stack.pop()
        return updated

    @property
    def inside(self) -> bool:
        return bool(self.stack) and self.stack[-1] == self.target


# Matches instruction-override attempts, not innocent words: "ignore the late fee" passes,
# "ignore previous instructions" does not. Deliberately stricter than upstream's keyword list.
INJECTION_PATTERN = r'''PATCHPROOF_INJECTION_PATTERN = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b[^.?!]{0,40}\b(instructions?|rules|prompt|guidelines|programming|restrictions)\b"
    r"|\bsystem prompt\b|\byou are now\b|\bact as\b|\bchange your (role|behaviou?r)\b|\bnew instructions\b"
    r"|\bdeveloper mode\b|\bjailbreak\b|\breveal your\b",
    re.IGNORECASE,
)
'''

INJECTION_GUARD = '''if PATCHPROOF_INJECTION_PATTERN.search(user_message):
    return {
        "response": "I can't help with that request. I can only answer questions about your own account.",
        "blocked": True,
        "timestamp": datetime.now().isoformat(),
        "model": self.model,
        "database_accessed": False,
    }
'''


class PromptInjectionPatch(_InFunction):
    """chat(): refuse injection attempts up front, stop injection phrases granting DB access, fence user text."""

    target = "chat"
    marker = "PATCHPROOF_INJECTION_PATTERN"

    def __init__(self) -> None:
        super().__init__()
        self.done = {"guard": False, "grant": False, "fence": False}

    def leave_If(self, original: cst.If, updated: cst.If) -> cst.If:
        grant = m.BooleanOperation(operator=m.Or(), right=m.Call(func=m.Attribute(attr=m.Name("_is_prompt_injection_request"))))
        if self.inside and m.matches(updated.test, grant):
            self.done["grant"] = True
            return updated.with_changes(test=updated.test.left)  # type: ignore[attr-defined]
        return updated

    def leave_FormattedString(self, original: cst.FormattedString, updated: cst.FormattedString) -> cst.FormattedString:
        if not self.inside:
            return updated
        parts: list[cst.BaseFormattedStringContent] = []
        for p in updated.parts:
            if isinstance(p, cst.FormattedStringExpression) and m.matches(p.expression, m.Name("user_message")):
                parts += [cst.FormattedStringText("<user_input>"), p, cst.FormattedStringText("</user_input>")]
                self.done["fence"] = True
            else:
                parts.append(p)
        return updated.with_changes(parts=parts)

    def leave_Try(self, original: cst.Try, updated: cst.Try) -> cst.Try:
        if not self.inside or self.done["guard"]:
            return updated
        guard = _commented(cst.parse_statement(INJECTION_GUARD), "refuse prompt-injection attempts before they reach the model")
        self.done["guard"] = True
        return updated.with_changes(body=updated.body.with_changes(body=[guard, *updated.body.body]))

    def leave_Module(self, original: cst.Module, updated: cst.Module) -> cst.Module:
        body = list(updated.body)
        after_imports = 0
        has_re = False
        for i, stmt in enumerate(body):
            if m.matches(stmt, m.SimpleStatementLine(body=[m.OneOf(m.Import(), m.ImportFrom())])):
                after_imports = i + 1
                has_re |= m.matches(stmt, m.SimpleStatementLine(body=[m.Import(names=[m.ImportAlias(name=m.Name("re"))])]))
        const = cst.parse_statement(INJECTION_PATTERN).with_changes(leading_lines=[
            cst.EmptyLine(),
            cst.EmptyLine(comment=cst.Comment("# PatchProof: messages that try to override or extract the assistant's instructions")),
        ])
        new = [const] if has_re else [cst.parse_statement("import re\n"), const]
        body[after_imports:after_imports] = new
        return updated.with_changes(body=body)


ROW_FILTER = [
    "rows_before = len(results)",
    "results = [row for row in results if own_account in map(str, row)]",
    'if len(results) != rows_before:\n    database_context += "FORBIDDEN: rows outside the signed-in account were withheld\\n"\n',
]
SCOPE_TO_CALLER = ['if not user_context:\n    return ""\n', 'own_account = str(user_context.get("account_number"))']


class BrokenAuthPatch(_InFunction):
    """_get_database_context(): anonymous gets nothing; every query result keeps only the caller's own rows."""

    target = "_get_database_context"
    marker = "own_account = str(user_context"

    def __init__(self) -> None:
        super().__init__()
        self.done = {"scope": False, "filters": False}

    def leave_SimpleStatementLine(self, original: cst.SimpleStatementLine, updated: cst.SimpleStatementLine):
        lookup = m.SimpleStatementLine(body=[m.Assign(targets=[m.AssignTarget(target=m.Name("results"))], value=m.Call(func=m.Name("execute_query")))])
        if not (self.inside and m.matches(updated, lookup)):
            return updated
        self.done["filters"] = True
        stmts = [cst.parse_statement(s) for s in ROW_FILTER]
        stmts[0] = _commented(stmts[0], "keep only rows that belong to the signed-in account")
        return cst.FlattenSentinel([updated, *stmts])

    def leave_Try(self, original: cst.Try, updated: cst.Try) -> cst.Try:
        if not self.inside or self.done["scope"]:
            return updated
        stmts = [cst.parse_statement(s) for s in SCOPE_TO_CALLER]
        stmts[0] = _commented(stmts[0], "anonymous chats get no database access; lookups are scoped to the caller")
        self.done["scope"] = True
        return updated.with_changes(body=updated.body.with_changes(body=[*stmts, *updated.body.body]))


PATCHERS: dict[str, tuple[type[_InFunction], str]] = {
    "AI_PROMPT_INJECTION": (
        PromptInjectionPatch,
        "Refuses injection attempts before they reach the model, stops injection phrases from unlocking database access, "
        "and fences the remaining user text in <user_input> delimiters.",
    ),
    "AI_BROKEN_AUTH": (
        BrokenAuthPatch,
        "Anonymous chats get no database context, and every lookup keeps only rows that belong to the signed-in account. "
        "Withheld rows are logged as FORBIDDEN in the context sent to the model.",
    ),
}


def _fail(reason: str) -> PatchResult:
    return {"success": False, "patched_code": None, "diff": None, "patch_rationale": None, "log": [log("ERROR", f"Patch failed: {reason}")]}


def apply_patch(workspace: str, vuln: Vuln) -> PatchResult:
    """Rewrite the affected file in `workspace` with the LibCST transformer for the vuln type."""
    if vuln["type"] not in PATCHERS:
        return _fail("no automatic patch exists for this finding type")
    transformer_cls, rationale = PATCHERS[vuln["type"]]
    path = Path(workspace) / vuln["file_path"]
    before = path.read_text()
    if transformer_cls.marker in before:
        return _fail("this fix is already present in the workspace")

    transformer = transformer_cls()
    after = cst.parse_module(before).visit(transformer).code
    missing = [k for k, ok in transformer.done.items() if not ok]  # type: ignore[attr-defined]
    if missing:
        return _fail(f"expected code pattern not found ({', '.join(missing)})")
    try:
        compile(after, str(path), "exec")
    except SyntaxError as e:
        return _fail(f"patched code does not compile: {e}")

    path.write_text(after)
    diff = "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{vuln['file_path']}", tofile=f"b/{vuln['file_path']}",
    ))
    added = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
    return {
        "success": True,
        "patched_code": after,
        "diff": diff,
        "patch_rationale": rationale,
        "log": [log("SUCCESS", f"Patch applied to {vuln['file_path']}: +{added} / -{removed} lines, compiles cleanly")],
    }

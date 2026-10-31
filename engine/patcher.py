"""Syntax-preserving fixes with LibCST. Formatting, comments and imports outside the edit stay intact.

Rule-based patches come first; when none applies and AI is on, the model (Claude or Gemini) writes the fix (engine/ai.py).
Either way a patch is only written after it passes the static proof checks in engine/checks.py.
"""

import ast
import difflib
import functools
import re
import string
import textwrap
from collections.abc import Callable, Sequence
from pathlib import Path

import libcst as cst
import libcst.matchers as m
from libcst.metadata import MetadataWrapper, PositionProvider

from engine.generic_rules import (
    FILE_OPENERS, HTTP_CLIENTS, HTTP_METHODS, SQL_CALL_NAME, SQL_EXEC_ATTRS, Hit, _secret_value, dotted, url_helpers,
)
from engine.generic_rules import find as generic_find
from engine.harness import log
from engine.languages import is_python
from engine.models import LogLine, PatchResult, Vuln
from engine.targets import iter_python_files, load_profile


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


# ---------- Generic, site-targeted patches (any Python codebase) ----------

_render = cst.Module([]).code_for_node
PCT_DRIVERS = ("psycopg2", "psycopg", "pymysql", "MySQLdb", "mysql.connector", "pg8000")
_project_imports_cache: dict[str, str] = {}


@functools.lru_cache(maxsize=16)
def _ast(source: str) -> ast.Module:
    return ast.parse(source)


@functools.lru_cache(maxsize=16)
def _wrapper(source: str) -> MetadataWrapper:
    return MetadataWrapper(cst.parse_module(source))


@functools.lru_cache(maxsize=128)
def _hits(vuln_type: str, source: str) -> tuple[Hit, ...]:
    return tuple(generic_find(vuln_type, _ast(source)))


def clear_caches() -> None:
    _project_imports_cache.clear()
    for cached in (_ast, _wrapper, _hits):
        cached.cache_clear()


def _imports(source: str, module: str) -> bool:
    return re.search(rf"^\s*(import|from)\s+{re.escape(module)}\b", source, re.M) is not None


def _project_imports(root: Path) -> str:
    key = str(root)
    if key not in _project_imports_cache:
        lines: list[str] = []
        for rel in iter_python_files(root)[0]:
            try:
                text = (root / rel).read_text(errors="replace")
            except OSError:
                continue
            lines += [ln for ln in text.splitlines() if ln.lstrip().startswith(("import ", "from "))]
        _project_imports_cache[key] = "\n".join(lines)
    return _project_imports_cache[key]


def _style(source: str, root: Path | None = None) -> str:
    """SQL placeholder style from the DB driver: the module's own imports first, then the rest of the
    project (vuln-bank's app.py calls an execute_query() helper whose module imports psycopg2)."""
    for src in (source, _project_imports(root) if root else ""):
        if any(_imports(src, d) for d in PCT_DRIVERS):
            return "%s"
        if _imports(src, "sqlite3"):
            return "?"
    return "?"


def _literal(text: str) -> str:
    """A Python string literal for `text`, double-quoted unless the text itself contains double quotes."""
    q = "'" if '"' in text and "'" not in text else '"'
    body = text.replace("\\", "\\\\").replace(q, "\\" + q).replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f"{q}{body}{q}"


# A string built from code, split into ("text", value) and ("expr", expression source) pieces.
Segments = list[tuple[str, str]]


def _coalesce(segments: Segments) -> Segments:
    out: Segments = []
    for kind, val in segments:
        if kind == "text" and out and out[-1][0] == "text":
            out[-1] = ("text", out[-1][1] + val)
        elif kind == "expr" or val:
            out.append((kind, val))
    return out


def _str_value(node: cst.CSTNode) -> str | None:
    if not isinstance(node, (cst.SimpleString, cst.ConcatenatedString)):
        return None
    try:
        value = ast.literal_eval(_render(node))
    except (ValueError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


def _fstring_segments(fs: cst.FormattedString) -> Segments | None:
    """Text keeps its source spelling, so a rewritten f-string keeps its layout."""
    if fs.prefix.lower() != "f":
        return None
    out: Segments = []
    for part in fs.parts:
        if isinstance(part, cst.FormattedStringText):
            out.append(("text", part.value.replace("{{", "{").replace("}}", "}")))
        elif part.conversion or part.format_spec:
            return None
        else:
            out.append(("expr", _render(part.expression)))
    return out


def _flatten_add(node: cst.BaseExpression) -> list[cst.BaseExpression]:
    if isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Add) and not node.lpar:
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _concat_segments(node: cst.BaseExpression) -> Segments | None:
    parts = _flatten_add(node)
    if len(parts) < 2:
        return None
    out: Segments = []
    for p in parts:
        text = _str_value(p)
        if text is not None:
            out.append(("text", text))
        elif isinstance(p, cst.FormattedString):
            inner = _fstring_segments(p)
            if inner is None or any(k == "text" and "\\" in v for k, v in inner):
                return None
            out += inner
        else:
            out.append(("expr", _render(p)))
    return out if any(k == "text" for k, _ in out) else None


PCT_TOKEN = re.compile(r"%([%sdifr])")


def _percent_segments(node: cst.BaseExpression) -> Segments | None:
    if not (isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Modulo)):
        return None
    fmt = _str_value(node.left)
    if fmt is None:
        return None
    if isinstance(node.right, cst.Tuple):
        if any(isinstance(e, cst.StarredElement) for e in node.right.elements):
            return None
        args = [e.value for e in node.right.elements]
    else:
        args = [node.right]
    out: Segments = []
    pos = used = 0
    for token in PCT_TOKEN.finditer(fmt):
        text = fmt[pos:token.start()]
        if "%" in text:
            return None  # %(name)s, %5d and friends are left alone
        out.append(("text", text))
        if token.group(1) == "%":
            out.append(("text", "%"))
        elif used < len(args):
            out.append(("expr", _render(args[used])))
            used += 1
        else:
            return None
        pos = token.end()
    tail = fmt[pos:]
    if "%" in tail or not used or used != len(args):
        return None
    return [*out, ("text", tail)]


def _format_segments(node: cst.BaseExpression) -> Segments | None:
    if not (isinstance(node, cst.Call) and isinstance(node.func, cst.Attribute) and node.func.attr.value == "format"):
        return None
    fmt = _str_value(node.func.value)
    if fmt is None or any(a.star for a in node.args):
        return None
    positional = [a.value for a in node.args if a.keyword is None]
    named = {a.keyword.value: a.value for a in node.args if a.keyword is not None}
    try:
        fields = list(string.Formatter().parse(fmt))
    except ValueError:
        return None
    out: Segments = []
    auto = 0
    for text, field, spec, conv in fields:
        out.append(("text", text))
        if field is None:
            continue
        if spec or conv:
            return None
        if field == "" and auto < len(positional):
            expr, auto = positional[auto], auto + 1
        elif field.isdigit() and int(field) < len(positional):
            expr = positional[int(field)]
        elif field in named:
            expr = named[field]
        else:
            return None
        out.append(("expr", _render(expr)))
    return out


def _segments(node: cst.BaseExpression) -> tuple[Segments | None, bool]:
    """Pieces of a string built by f-string, + concatenation, % formatting or str.format(), and whether the
    pasted values were converted to text along the way (all but + concatenation do that)."""
    if isinstance(node, cst.FormattedString):
        return _fstring_segments(node), True
    if isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Add):
        return _concat_segments(node), False
    if isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Modulo):
        return _percent_segments(node), True
    return _format_segments(node), True


def _fstring(word: Segments) -> str | None:
    exprs = [v for k, v in word if k == "expr"]
    q = "'" if any('"' in e for e in exprs) else '"'
    if any(q in e for e in exprs) or any(k == "text" and (q in v or "\\" in v) for k, v in word):
        return None
    return "f" + q + "".join(v.replace("{", "{{").replace("}", "}}") if k == "text" else "{" + v + "}" for k, v in word) + q


def _merge_params(segments: Segments, style: str) -> tuple[str, list[str]] | None:
    """Swap each pasted value for a placeholder. Quotes around a value go (the driver quotes it) and LIKE
    wildcards glued to it move into the parameter. None for shapes that can't be rewritten safely."""
    out: list[list[str]] = []
    params: list[str] = []
    strip_next = 0
    for i, (kind, val) in enumerate(segments):
        if kind == "text":
            out.append(["text", val[strip_next:]])
            strip_next = 0
            continue
        prev = out[-1][1] if out and out[-1][0] == "text" else ""
        nxt = segments[i + 1][1] if i + 1 < len(segments) and segments[i + 1][0] == "text" else ""
        left = 2 if prev.endswith("'%") else 1 if prev.endswith("'") else 0
        right = 2 if nxt.startswith("%'") else 1 if nxt.startswith("'") else 0
        if bool(left) != bool(right):
            return None  # a quote on one side only: the value is part of a larger literal
        if left == 2 or right == 2:
            param = _fstring([*([("text", "%")] if left == 2 else []), ("expr", val), *([("text", "%")] if right == 2 else [])])
            if param is None:
                return None
        else:
            param = val
        if left:
            out[-1][1] = prev[:-left]
        strip_next = right
        out.append(["param", ""])
        params.append(param)
    if not params:
        return None
    body = "".join(style if kind == "param" else text.replace("%", "%%") if style == "%s" else text for kind, text in out)
    return body, params


def _tuple_src(params: list[str]) -> str:
    return "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"


def parameterize(fs: cst.FormattedString, style: str) -> tuple[str, str] | None:
    """f"... '{a}' ... LIKE '%{b}%'" -> ('"... ? ... LIKE ?"', '(a, f"%{b}%")'), or None if unsupported."""
    segments = _fstring_segments(fs)
    merged = _merge_params(_coalesce(segments), style) if segments else None
    return (f"{fs.quote}{merged[0]}{fs.quote}", _tuple_src(merged[1])) if merged else None


def _query(node: cst.BaseExpression, style: str) -> tuple[str, str] | None:
    """(SQL literal source, params tuple source) for a query built from pasted values."""
    if isinstance(node, cst.FormattedString):
        return parameterize(node, style)
    segments, _ = _segments(node)
    merged = _merge_params(_coalesce(segments), style) if segments else None
    return (_literal(merged[0]), _tuple_src(merged[1])) if merged else None


class _Site(cst.CSTTransformer):
    """Rewrites code within lines [start, end]. Subclasses set the rationale, imports and helper they need."""

    METADATA_DEPENDENCIES = (PositionProvider,)
    RATIONALE = ""
    IMPORTS: tuple[str, ...] = ()
    HELPER: tuple[str, str, str] | None = None  # (function name, source, comment)

    def __init__(self, start: int, end: int) -> None:
        super().__init__()
        self.start, self.end = start, end
        self.changed = False

    def in_site(self, node: cst.CSTNode) -> bool:
        pos = self.get_metadata(PositionProvider, node)
        return pos.start.line >= self.start and pos.end.line <= self.end

    def complete(self) -> bool:
        return self.changed

    def describe(self) -> str:
        return self.RATIONALE

    def leave_Module(self, original: cst.Module, updated: cst.Module) -> cst.Module:
        if not self.changed:
            return updated
        if self.HELPER and f"def {self.HELPER[0]}(" not in updated.code:
            name, source, comment = self.HELPER
            body = list(updated.body)
            at = _after_imports(body)
            body.insert(at, cst.parse_statement(source).with_changes(leading_lines=[
                cst.EmptyLine(), cst.EmptyLine(), cst.EmptyLine(comment=cst.Comment(f"# PatchProof: {comment}")),
            ]))
            if at + 1 < len(body) and not body[at + 1].leading_lines:
                body[at + 1] = body[at + 1].with_changes(leading_lines=[cst.EmptyLine(), cst.EmptyLine()])
            updated = updated.with_changes(body=body)
        return add_imports(updated, list(self.IMPORTS))


def _comma() -> cst.Comma:
    return cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))


def _kwarg(name: str, value: str) -> cst.Arg:
    eq = cst.AssignEqual(whitespace_before=cst.SimpleWhitespace(""), whitespace_after=cst.SimpleWhitespace(""))
    return cst.Arg(value=cst.parse_expression(value), keyword=cst.Name(name), equal=eq)


def _find_kw(call: cst.Call, name: str) -> cst.Arg | None:
    return next((a for a in call.args if a.keyword is not None and a.keyword.value == name), None)


def _drop_arg(args: Sequence[cst.Arg], drop: cst.Arg) -> list[cst.Arg]:
    out = [a for a in args if a is not drop]
    if out and args[-1] is drop:
        out[-1] = out[-1].with_changes(comma=drop.comma)
    return out


def _append_arg(args: Sequence[cst.Arg], new: cst.Arg) -> list[cst.Arg]:
    if not args:
        return [new]
    last = args[-1]
    return [*args[:-1], last.with_changes(comma=_comma()), new.with_changes(comma=last.comma)]


def _cst_dotted(node: cst.BaseExpression) -> str:
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        base = _cst_dotted(node.value)
        return f"{base}.{node.attr.value}" if base else node.attr.value
    return ""


def _is_import(stmt: cst.CSTNode) -> bool:
    return m.matches(stmt, m.SimpleStatementLine(body=[m.OneOf(m.Import(), m.ImportFrom())]))


def _after_imports(body: Sequence[cst.CSTNode]) -> int:
    at = 0
    for i, stmt in enumerate(body):
        if _is_import(stmt):
            at = i + 1
    if at == 0 and body and m.matches(body[0], m.SimpleStatementLine(body=[m.Expr(m.SimpleString())])):
        at = 1  # after the module docstring
    return at


def _bound(stmt: ast.stmt) -> set[str]:
    if isinstance(stmt, (ast.Import, ast.ImportFrom)):
        return {(a.asname or a.name).split(".")[0] for a in stmt.names}
    return set()


def add_imports(module: cst.Module, statements: list[str]) -> cst.Module:
    """Add each import statement after the module's last top-level import, unless its names are already bound."""
    if not statements:
        return module
    bound = set().union(*(_bound(s) for s in ast.parse(module.code).body))
    new = []
    for text in statements:
        parsed = ast.parse(text.strip()).body
        if len(parsed) != 1 or not isinstance(parsed[0], (ast.Import, ast.ImportFrom)):
            raise PatchError(f"not a single import statement: {text!r}")
        if _bound(parsed[0]) - bound:
            new.append(cst.parse_statement(text.strip() + "\n"))
            bound |= _bound(parsed[0])
    if not new:
        return module
    body = list(module.body)
    at = _after_imports(body)
    body[at:at] = new
    return module.with_changes(body=body)


def _sql_call(func: cst.BaseExpression) -> bool:
    name = _cst_dotted(func).split(".")[-1]
    return name in SQL_EXEC_ATTRS or bool(SQL_CALL_NAME.search(name))


def _query_names(source: str, start: int, end: int) -> set[str]:
    """Names passed as the only positional argument to a SQL call at the site: their assignments get rewritten."""
    names = set()
    for call in ast.walk(_ast(source)):
        if (isinstance(call, ast.Call) and start <= call.lineno <= end and len(call.args) == 1
                and isinstance(call.args[0], ast.Name)):
            name = dotted(call.func).split(".")[-1]
            if name in SQL_EXEC_ATTRS or SQL_CALL_NAME.search(name):
                names.add(call.args[0].id)
    return names


class ParameterizeQuery(_Site):
    """Turn a query built from pasted values (f-string, +, % or .format) into placeholders plus a params tuple."""

    RATIONALE = ("Rewrites the query to use bound parameters, so input reaches the database as data and can never change "
                 "the SQL itself. Quotes around values are dropped (the driver handles them) and LIKE wildcards move into "
                 "the parameter value.")

    def __init__(self, start: int, end: int, style: str, query_names: set[str]) -> None:
        super().__init__(start, end)
        self.style = style
        self.query_names = query_names
        self.pending: dict[str, str] = {}

    def complete(self) -> bool:
        return self.changed and not self.pending

    def leave_Assign(self, original: cst.Assign, updated: cst.Assign) -> cst.Assign:
        if not self.in_site(original) or len(updated.targets) != 1 or not isinstance(updated.targets[0].target, cst.Name):
            return updated
        name = updated.targets[0].target.value
        res = _query(updated.value, self.style) if name in self.query_names else None
        if not res:
            return updated
        self.pending[name] = res[1]
        return updated.with_changes(value=cst.parse_expression(res[0]))

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        if not self.in_site(original) or not _sql_call(updated.func) or not updated.args:
            return updated
        first, rest = updated.args[0], list(updated.args[1:])
        if first.keyword is not None or first.star or any(a.keyword is None for a in rest):
            return updated
        if isinstance(first.value, cst.Name) and first.value.value in self.pending:
            sql, params = first.value, self.pending.pop(first.value.value)
        else:
            res = _query(first.value, self.style)
            if not res:
                return updated
            sql, params = cst.parse_expression(res[0]), res[1]
        self.changed = True
        return updated.with_changes(args=[
            first.with_changes(value=sql, comma=_comma()), cst.Arg(cst.parse_expression(params), comma=first.comma), *rest,
        ])


SHELL_SYNTAX = re.compile(r"[|&;<>()$`\\*?\[\]{}~!#'\"\n]")
SUBPROCESS_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}


def _argv(node: cst.BaseExpression) -> str | None:
    """Source of an argument list equivalent to a shell command string. The program must be fixed text, values
    must be whole words (or glued to fixed text), and any shell syntax means no rewrite."""
    segments, converted = _segments(node)
    if not segments:
        return None
    words: list[Segments] = [[]]
    for kind, val in _coalesce(segments):
        if kind == "expr":
            words[-1].append((kind, val))
            continue
        if SHELL_SYNTAX.search(val):
            return None
        for piece in re.split(r"(\s+)", val):
            if piece.isspace():
                words.append([])
            elif piece:
                words[-1].append(("text", piece))
    words = [w for w in words if w]
    if not words or any(k != "text" for k, _ in words[0]):
        return None
    out = []
    for w in words:
        if all(k == "text" for k, _ in w):
            out.append(_literal("".join(v for _, v in w)))
        elif len(w) == 1:
            out.append(f"str({w[0][1]})" if converted else w[0][1])
        else:
            word = _fstring(w)
            if word is None:
                return None
            out.append(word)
    return "[" + ", ".join(out) + "]"


class ShellToArgv(_Site):
    RATIONALE = ("Runs the program with an argument list instead of a shell command string, so each value is passed as a "
                 "single argument and characters like ; | && or $( ) are never interpreted by a shell. The program and its "
                 "fixed options are unchanged.")
    IMPORTS = ("import subprocess",)

    @staticmethod
    def _command(call: cst.Call) -> str | None:
        return _argv(call.args[0].value) if call.args and call.args[0].keyword is None else None

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.BaseExpression:
        if not self.in_site(original):
            return updated
        func, name, new = updated.func, _cst_dotted(updated.func), None
        if (isinstance(func, cst.Attribute) and func.attr.value == "read" and not updated.args
                and isinstance(func.value, cst.Call) and _cst_dotted(func.value.func) == "os.popen"):
            argv = self._command(func.value)
            new = argv and f"subprocess.run({argv}, capture_output=True, text=True).stdout"
        elif name in SUBPROCESS_FUNCS:
            shell, argv = _find_kw(updated, "shell"), self._command(updated)
            if shell is None or not m.matches(shell.value, m.Name("True")) or not argv:
                return updated
            args = _drop_arg(updated.args, shell)
            args[0] = args[0].with_changes(value=cst.parse_expression(argv))
            self.changed = True
            return updated.with_changes(args=args)
        elif name == "os.system":
            argv = self._command(updated)
            new = argv and f"subprocess.call({argv})"
        elif name == "subprocess.getoutput":
            argv = self._command(updated)
            new = argv and f'subprocess.run({argv}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout.rstrip("\\n")'
        if not new:
            return updated
        self.changed = True
        return cst.parse_expression(new)


SAFE_JOIN_HELPER = (
    "def _patchproof_safe_join(base, *parts):\n"
    "    root = os.path.realpath(base)\n"
    "    path = os.path.realpath(os.path.join(root, *parts))\n"
    "    if os.path.commonpath([root, path]) != root:\n"
    "        raise PermissionError(\"Path escapes the allowed directory\")\n"
    "    return path\n"
)


def _path_split(node: cst.BaseExpression) -> tuple[str, str] | None:
    """(base, rest) sources for a path built as f"{BASE}/{name}", BASE + "/" + name or "/srv/files/" + name."""
    if isinstance(node, cst.FormattedString):
        segments, converted = _fstring_segments(node), True
    elif isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Add):
        segments, converted = _concat_segments(node) or [("expr", _render(p)) for p in _flatten_add(node)], False
    else:
        return None
    segments = _coalesce(segments or [])
    if len(segments) < 2 or any(k == "text" and "\\" in v for k, v in segments):
        return None
    kind, head = segments[0]
    rest = segments[1:]
    if kind == "text":
        if "/" not in head:
            return None
        cut = head.rindex("/") + 1
        base = _literal(head[:cut])
        rest = ([("text", head[cut:])] if head[cut:] else []) + rest
    else:
        base = head
        if rest[0][0] == "text":
            tail = rest[0][1].lstrip("/")
            rest = ([("text", tail)] if tail else []) + rest[1:]
    if not any(k == "expr" for k, _ in rest):
        return None
    if len(rest) == 1:
        return base, f"str({rest[0][1]})" if converted else rest[0][1]
    part = _fstring(rest)
    return (base, part) if part else None


class SafeJoin(_Site):
    """Route a file path built from input through a helper that refuses anything outside the base folder."""

    RATIONALE = ("Routes the path through _patchproof_safe_join, which resolves it and refuses anything outside the "
                 "intended folder, so ../ sequences and absolute paths are rejected while normal file names still work.")
    IMPORTS = ("import os",)
    HELPER = ("_patchproof_safe_join", SAFE_JOIN_HELPER, "resolve file paths and refuse anything outside the intended folder")

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        if not self.in_site(original) or _cst_dotted(updated.func) not in FILE_OPENERS or not updated.args:
            return updated
        first = updated.args[0].value
        if isinstance(first, cst.Call) and _cst_dotted(first.func) in ("os.path.join", "posixpath.join"):
            new_first: cst.BaseExpression = first.with_changes(func=cst.Name("_patchproof_safe_join"))
        else:
            split = _path_split(first)
            if not split:
                return updated
            new_first = cst.parse_expression(f"_patchproof_safe_join({split[0]}, {split[1]})")
        self.changed = True
        return updated.with_changes(args=[updated.args[0].with_changes(value=new_first), *updated.args[1:]])


class LiteralEval(_Site):
    RATIONALE = ("Replaces eval() with ast.literal_eval(), which only accepts Python literals such as numbers, strings, "
                 "lists and dicts. Data still parses; code no longer runs.")
    IMPORTS = ("import ast",)

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        if (self.in_site(original) and m.matches(updated.func, m.Name("eval")) and len(updated.args) == 1
                and updated.args[0].keyword is None and not updated.args[0].star):
            self.changed = True
            return updated.with_changes(func=cst.parse_expression("ast.literal_eval"))
        return updated


class SafeYaml(_Site):
    RATIONALE = "Loads YAML with yaml.safe_load(), which builds plain data only and never constructs Python objects."

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        if not self.in_site(original) or _cst_dotted(updated.func) != "yaml.load" or not updated.args:
            return updated
        data = updated.args[0]
        if data.keyword is not None:
            return updated
        self.changed = True
        return updated.with_changes(func=cst.parse_expression("yaml.safe_load"), args=[data.with_changes(comma=cst.MaybeSentinel.DEFAULT)])


class VerifyTLS(_Site):
    RATIONALE = ("Removes verify=False so the HTTP client checks the server's certificate again (the library default). "
                 "If the server uses a private CA, pass its bundle path with verify= instead of turning checks off.")

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        verify = _find_kw(updated, "verify") if self.in_site(original) else None
        if verify is None or not m.matches(verify.value, m.Name("False")):
            return updated
        self.changed = True
        return updated.with_changes(args=_drop_arg(updated.args, verify))


class DebugFromEnv(_Site):
    RATIONALE = ("Debug mode now has to be switched on explicitly with FLASK_DEBUG=1 in the environment, so a deployed "
                 "app never exposes the interactive debugger by accident. Local development works as before with that variable set.")
    IMPORTS = ("import os",)

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        if not self.in_site(original) or not (isinstance(updated.func, cst.Attribute) and updated.func.attr.value == "run"):
            return updated
        debug = _find_kw(updated, "debug")
        if debug is None or not m.matches(debug.value, m.Name("True")):
            return updated
        self.changed = True
        new = debug.with_changes(value=cst.parse_expression('os.environ.get("FLASK_DEBUG") == "1"'))
        return updated.with_changes(args=[new if a is debug else a for a in updated.args])


def _env_name(label: str) -> str:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", label)
    return re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").upper() or "SECRET"


def _is_secret(label: str, node: cst.BaseExpression) -> bool:
    value = _str_value(node)
    return value is not None and _secret_value(label, ast.Constant(value))


class SecretFromEnv(_Site):
    IMPORTS = ("import os",)

    def __init__(self, start: int, end: int) -> None:
        super().__init__(start, end)
        self.names: list[str] = []

    def _env(self, name: str) -> cst.BaseExpression:
        self.names.append(name)
        self.changed = True
        return cst.parse_expression(f"os.environ[{_literal(name)}]")

    def describe(self) -> str:
        names = ", ".join(dict.fromkeys(self.names))
        return (f"Reads {names} from the environment instead of the source code, so the secret is no longer in the code or "
                "its copies. Set it where the app is deployed: the app now refuses to start without it rather than falling "
                "back to a known value. Rotate the old value, because it stays in version-control history.")

    def leave_Assign(self, original: cst.Assign, updated: cst.Assign) -> cst.Assign:
        if not self.in_site(original):
            return updated
        for t in updated.targets:
            label = t.target.value if isinstance(t.target, cst.Name) else t.target.attr.value if isinstance(t.target, cst.Attribute) else ""
            if label and _is_secret(label, updated.value):
                return updated.with_changes(value=self._env(_env_name(label)))
        return updated

    def leave_DictElement(self, original: cst.DictElement, updated: cst.DictElement) -> cst.DictElement:
        key = _str_value(updated.key) if self.in_site(original) else None
        if key and _is_secret(key, updated.value):
            return updated.with_changes(value=self._env(_env_name(key)))
        return updated

    def leave_Arg(self, original: cst.Arg, updated: cst.Arg) -> cst.Arg:
        if self.in_site(original) and updated.keyword is not None and _is_secret(updated.keyword.value, updated.value):
            return updated.with_changes(value=self._env(_env_name(updated.keyword.value)))
        return updated

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.BaseExpression:
        if (not self.in_site(original) or _cst_dotted(updated.func) not in ("os.getenv", "os.environ.get")
                or len(updated.args) != 2 or any(a.keyword for a in updated.args)):
            return updated
        name = _str_value(updated.args[0].value)
        if name and _is_secret(name, updated.args[1].value):
            return self._env(name)
        return updated


SAFE_URL_HELPER = (
    "def _patchproof_safe_url(url):\n"
    "    parts = urllib.parse.urlsplit(str(url))\n"
    "    if parts.scheme not in (\"http\", \"https\") or not parts.hostname:\n"
    "        raise PermissionError(\"Only http and https URLs are allowed\")\n"
    "    port = parts.port or (443 if parts.scheme == \"https\" else 80)\n"
    "    for info in socket.getaddrinfo(parts.hostname, port):\n"
    "        if not ipaddress.ip_address(info[4][0].split(\"%\")[0]).is_global:\n"
    "            raise PermissionError(\"URL points to an internal or private address\")\n"
    "    return url\n"
)


class SafeUrl(_Site):
    IMPORTS = ("import ipaddress", "import socket", "import urllib.parse")
    HELPER = ("_patchproof_safe_url", SAFE_URL_HELPER, "refuse URLs that point at internal or private addresses")

    def __init__(self, start: int, end: int, helpers: dict[str, int]) -> None:
        super().__init__(start, end)
        self.helpers = helpers  # module functions that pass a parameter into an HTTP request (FETCH = lambda url: ...)
        self.redirects_off = False

    def describe(self) -> str:
        redirects = ("Redirects are no longer followed, so a public URL can't bounce the request to an internal one."
                     if self.redirects_off else
                     "This HTTP client follows redirects, so also refuse redirects to internal hosts where it is configured.")
        return ("Checks the URL before the server fetches it: only http and https are allowed, and hosts that resolve to "
                f"loopback, private, link-local (cloud metadata) or other non-public addresses are refused. {redirects} "
                "Public URLs work as before.")

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        name = _cst_dotted(updated.func)
        if not self.in_site(original):
            return updated
        if isinstance(updated.func, cst.Name) and name in self.helpers:
            skip = self.helpers[name]  # wrap the URL where it enters the helper
        elif HTTP_CLIENTS.search(name) and name.split(".")[-1] in HTTP_METHODS:
            skip = 1 if name.split(".")[-1] == "request" else 0  # requests.request(method, url, ...)
        else:
            return updated
        args = list(updated.args)
        positional = [i for i, a in enumerate(args) if a.keyword is None and not a.star]
        idx = positional[skip] if len(positional) > skip else next(
            (i for i, a in enumerate(args) if a.keyword is not None and a.keyword.value == "url"), None)
        if idx is None or m.matches(args[idx].value, m.Call(func=m.Name("_patchproof_safe_url"))):
            return updated
        args[idx] = args[idx].with_changes(value=cst.Call(func=cst.Name("_patchproof_safe_url"), args=[cst.Arg(args[idx].value)]))
        if name.startswith("requests."):
            redirects = next((a for a in args if a.keyword is not None and a.keyword.value == "allow_redirects"), None)
            if redirects is None:
                args = _append_arg(args, _kwarg("allow_redirects", "False"))
            else:
                args = [a.with_changes(value=cst.Name("False")) if a is redirects else a for a in args]
            self.redirects_off = True
        self.changed = True
        return updated.with_changes(args=args)


def _jwt_key(source: str) -> tuple[str | None, str | None]:
    """Signing key and algorithm from a jwt.encode() call in the module, when the key is a module-level name."""
    tree = _ast(source)
    names = {t.id for s in tree.body if isinstance(s, ast.Assign) for t in s.targets if isinstance(t, ast.Name)}
    names |= set().union(*(_bound(s) for s in tree.body))
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and dotted(call.func).endswith("jwt.encode") and len(call.args) >= 2):
            continue
        root = call.args[1]
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            root = root.value
        if isinstance(root, ast.Name) and root.id in names:
            alg = next((k.value for k in call.keywords if k.arg == "algorithm"), call.args[2] if len(call.args) > 2 else None)
            return ast.unparse(call.args[1]), alg.value if isinstance(alg, ast.Constant) and isinstance(alg.value, str) else None
    return None, None


class VerifyJwt(_Site):
    def __init__(self, start: int, end: int, key: str | None, alg: str | None) -> None:
        super().__init__(start, end)
        self.key, self.alg = key, alg or "HS256"

    def describe(self) -> str:
        return (f"Decodes the token with signature checking on, using the same key and the {self.alg} algorithm the app signs "
                "tokens with. Forged or unsigned tokens (including alg \"none\") now raise an error instead of being trusted.")

    def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.Call:
        if not self.in_site(original) or not _cst_dotted(updated.func).endswith("jwt.decode"):
            return updated
        positional = [a for a in updated.args if a.keyword is None and not a.star]
        if not positional or len(positional) > 2 or any(a.star for a in updated.args):
            return updated
        key = _render(positional[1].value) if len(positional) > 1 else self.key
        if not key:
            return updated
        options = _find_kw(updated, "options")
        if options is not None and not (isinstance(options.value, cst.Dict) and all(
                isinstance(e, cst.DictElement) and _str_value(e.key) == "verify_signature" for e in options.value.elements)):
            return updated
        algs = _find_kw(updated, "algorithms")
        algs_src = _render(algs.value) if algs is not None and "none" not in _render(algs.value).lower() else f"[{_literal(self.alg)}]"
        others = [a for a in updated.args if a.keyword is not None and a.keyword.value not in ("options", "verify", "algorithms")]
        args = [positional[0], cst.Arg(cst.parse_expression(key)), _kwarg("algorithms", algs_src), *others]
        args = [a.with_changes(comma=_comma() if i < len(args) - 1 else cst.MaybeSentinel.DEFAULT) for i, a in enumerate(args)]
        self.changed = True
        return updated.with_changes(args=args)


GENERIC_PATCHERS: dict[str, Callable[[str, int, int, Path | None], _Site]] = {
    "SQL_INJECTION": lambda src, s, e, root: ParameterizeQuery(s, e, _style(src, root), _query_names(src, s, e)),
    "COMMAND_INJECTION": lambda src, s, e, root: ShellToArgv(s, e),
    "PATH_TRAVERSAL": lambda src, s, e, root: SafeJoin(s, e),
    "CODE_INJECTION": lambda src, s, e, root: LiteralEval(s, e),
    "INSECURE_DESERIALIZATION": lambda src, s, e, root: SafeYaml(s, e),
    "TLS_VERIFY_DISABLED": lambda src, s, e, root: VerifyTLS(s, e),
    "DEBUG_MODE": lambda src, s, e, root: DebugFromEnv(s, e),
    "HARDCODED_CREDENTIALS": lambda src, s, e, root: SecretFromEnv(s, e),
    "SSRF": lambda src, s, e, root: SafeUrl(s, e, url_helpers(_ast(src))),
    "INSECURE_JWT": lambda src, s, e, root: VerifyJwt(s, e, *_jwt_key(src)),
}


def has_patcher(vuln_type: str) -> bool:
    return vuln_type in PATCHERS or vuln_type in GENERIC_PATCHERS


def _locate(vuln_type: str, source: str, original_code: str, near: int) -> tuple[int, int] | None:
    """Current span of the flagged code, matched by content so earlier patches that shift lines don't matter.
    Identical code can appear in several functions (vuln-bank has three copies of one query), so the match
    nearest the recorded line wins. If another fix already edited these lines (the SSRF guard on a call that
    also sets verify=False), the most similar site wins, but only when it is nearly identical."""
    lines = source.splitlines()
    want = original_code.strip()
    spans = [(h.start, h.end, "\n".join(lines[h.start - 1 : h.end]).strip()) for h in _hits(vuln_type, source)]
    exact = [(s, e) for s, e, code in spans if code == want]
    if exact:
        return min(exact, key=lambda span: abs(span[0] - near))
    scored = sorted(((difflib.SequenceMatcher(None, code, want).ratio(), -abs(s - near), s, e) for s, e, code in spans), reverse=True)
    return (scored[0][2], scored[0][3]) if scored and scored[0][0] >= 0.8 else None


def _transform_site(vuln_type: str, source: str, original_code: str, near: int, root: Path | None = None) -> tuple[str, str] | None:
    span = _locate(vuln_type, source, original_code, near)
    if span is None:
        return None
    transformer = GENERIC_PATCHERS[vuln_type](source, *span, root)
    after = _wrapper(source).visit(transformer).code
    if not transformer.complete():
        return None
    try:
        compile(after, "<patch>", "exec")
    except SyntaxError:
        return None
    return after, transformer.describe()


def can_patch(vuln_type: str, source: str, original_code: str, near: int, root: Path | None = None) -> bool:
    if vuln_type in PATCHERS:
        return True
    if vuln_type in GENERIC_PATCHERS:
        return _transform_site(vuln_type, source, original_code, near, root) is not None
    return False


def rule_patch(source: str, vuln: Vuln, root: Path | None = None) -> tuple[str, str] | str:
    """(patched source, rationale) from a rule-based patch, or the reason none applies."""
    vtype = vuln["type"]
    if not is_python(vuln["file_path"]):
        return "rule-based patches are written for Python; this file's fix comes from the AI model"
    if vtype in GENERIC_PATCHERS:
        res = _transform_site(vtype, source, vuln["original_code"], vuln["line_number"], root)
        return res or "the flagged code is no longer present, or this form of it can't be rewritten safely by a rule"
    if vtype not in PATCHERS:
        return "no rule-based patch exists for this finding type"
    transformer_cls, rationale = PATCHERS[vtype]
    if transformer_cls.marker in source:
        return "this fix is already present in the workspace"
    transformer = transformer_cls()
    after = cst.parse_module(source).visit(transformer).code
    missing = [k for k, ok in transformer.done.items() if not ok]  # type: ignore[attr-defined]
    if missing:
        return f"expected code pattern not found ({', '.join(missing)})"
    try:
        compile(after, "<patch>", "exec")
    except SyntaxError as e:
        return f"patched code does not compile: {e}"
    return after, rationale


class _ReplaceFunction(cst.CSTTransformer):
    def __init__(self, qualname: str, new: cst.FunctionDef) -> None:
        super().__init__()
        self.qualname, self.new, self.stack, self.done = qualname, new, [], False

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        self.stack.append(node.name.value)

    def leave_ClassDef(self, original: cst.ClassDef, updated: cst.ClassDef) -> cst.ClassDef:
        self.stack.pop()
        return updated

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        self.stack.append(node.name.value)

    def leave_FunctionDef(self, original: cst.FunctionDef, updated: cst.FunctionDef) -> cst.FunctionDef:
        name = ".".join(self.stack)
        self.stack.pop()
        if name != self.qualname or self.done:
            return updated
        self.done = True
        # Only the body is taken from the replacement: the def line (name, parameters, return type) stays the original.
        # Decorators may be added (an auth fix adds @login_required) but never dropped or changed.
        old = [_render(d.decorator) for d in updated.decorators]
        new = [_render(d.decorator) for d in self.new.decorators]
        keeps = iter(new)
        decorators = self.new.decorators if all(d in keeps for d in old) else updated.decorators
        return updated.with_changes(body=self.new.body, decorators=decorators)


def _normalize(code: str) -> str:
    """Model output to parseable source: drop markdown fences, then remove the first line's indentation from every
    line. textwrap.dedent can't, when a multi-line string in the function has lines at column 0."""
    lines = code.strip("\n").split("\n")
    if lines and lines[0].lstrip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    first = next((ln for ln in lines if ln.strip()), "")
    pad = first[: len(first) - len(first.lstrip())]
    return "\n".join(ln[len(pad):] if pad and ln.startswith(pad) else ln for ln in lines).strip("\n") + "\n"


def _as_function(new: cst.Module, name: str) -> cst.FunctionDef:
    """The replacement function: a whole def named `name`, or bare body statements (wrapped in a stand-in def)."""
    defs = [st for st in new.body if isinstance(st, cst.FunctionDef)]
    if len(new.body) == 1 and defs and defs[0].name.value == name:
        return defs[0]
    if defs or any(isinstance(st, cst.ClassDef) for st in new.body):
        raise PatchError(f"the replacement must be exactly one function named {name}")
    return cst.parse_statement(f"def {name}():\n    pass\n").with_changes(body=cst.IndentedBlock(body=list(new.body)))


def replace_region(source: str, qualname: str | None, lo: int, hi: int, replacement: str, imports: list[str]) -> str:
    """Swap one function's body (by qualified name) or the top-level statements on lines lo..hi for `replacement`,
    then add any new imports. Used for AI fixes; everything outside the region is left byte-for-byte."""
    new = cst.parse_module(_normalize(replacement))
    imports = [_normalize(i).strip() for i in imports if i.strip()]
    module = cst.parse_module(source)
    if qualname:
        swap = _ReplaceFunction(qualname, _as_function(new, qualname.split(".")[-1]))
        module = module.visit(swap)
        if not swap.done:
            raise PatchError(f"{qualname}() was not found in the file")
    else:
        wrapper = MetadataWrapper(module)
        pos = wrapper.resolve(PositionProvider)
        body = list(wrapper.module.body)
        idx = [i for i, st in enumerate(body) if pos[st].start.line <= hi and pos[st].end.line >= lo]
        if not idx or not new.body:
            raise PatchError("the flagged statements were not found, or the replacement is empty")
        stmts = list(new.body)
        if not stmts[0].leading_lines:
            stmts[0] = stmts[0].with_changes(leading_lines=body[idx[0]].leading_lines)
        body[idx[0] : idx[-1] + 1] = stmts
        module = wrapper.module.with_changes(body=body)
    return add_imports(module, imports).code


def replace_lines(source: str, lo: int, hi: int, replacement: str, imports: list[str]) -> str:
    """Swap lines lo..hi (1-based, inclusive) of a non-Python file for `replacement`, re-indented to the first original
    line, then add any new import lines after the file's existing ones. Nothing else in the file changes."""
    from engine.checks import IMPORT_LIKE

    lines = source.split("\n")
    if not 1 <= lo <= hi <= len(lines):
        raise PatchError(f"lines {lo}-{hi} are outside the file")
    body = _normalize(replacement).rstrip("\n").split("\n")
    if not any(ln.strip() for ln in body):
        raise PatchError("the replacement is empty")
    pad = re.match(r"[ \t]*", lines[lo - 1]).group(0)  # type: ignore[union-attr]
    lines[lo - 1 : hi] = [pad + ln if ln.strip() else ln for ln in body]
    known = {ln.strip() for ln in lines}
    add = [i for i in (_normalize(x).strip() for x in imports) if i and i not in known]
    if add:
        at = 0
        for index, line in enumerate(lines[:120]):
            if IMPORT_LIKE.match(line) and not line.lstrip().startswith("<?php") or (index == 0 and line.startswith(("#!", "<?php"))):
                at = index + 1
        lines[at:at] = add
    return "\n".join(lines)


def unified_diff(rel: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile=f"a/{rel}", tofile=f"b/{rel}",
    ))


def _fail(reason: str, lines: list[LogLine], checks: list[dict] | None = None) -> PatchResult:
    return {"success": False, "patched_code": None, "diff": None, "patch_rationale": None, "fix_source": None,
            "checks": checks or [], "base_code": None, "behaviour_change": None,
            "log": [*lines, log("ERROR", f"Patch failed: {reason}")]}


def _result(path: Path, rel: str, before: str, after: str, rationale: str, source: str, checks: list[dict],
            lines: list[LogLine], behaviour: str | None = None) -> PatchResult:
    path.write_text(after)
    diff = unified_diff(rel, before, after)
    added = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
    who = "Rule-based patch" if source == "rule" else "AI fix"
    passed = sum(1 for c in checks if c["passed"])
    return {
        "success": True, "patched_code": after, "diff": diff, "patch_rationale": rationale, "fix_source": source,
        "checks": checks, "base_code": before, "behaviour_change": behaviour,
        "log": [*lines, log("SUCCESS", f"{who} applied to {rel}: +{added} / -{removed} lines, {passed}/{len(checks)} static checks passed")],
    }


def apply_patch(workspace: str, vuln: Vuln, profile: dict | None = None, use_ai: bool | None = None) -> PatchResult:
    """Fix the flagged code in `workspace`: a rule-based LibCST patch when one applies, otherwise a fix written by
    the AI model. Either way it must pass the static proof checks (engine/checks.py) before the file is written."""
    from engine import ai
    from engine.checks import failed, static_checks

    profile = profile or load_profile()
    path = Path(workspace) / vuln["file_path"]
    before = path.read_text()
    lines: list[LogLine] = []

    res = rule_patch(before, vuln, Path(workspace))
    if isinstance(res, tuple):
        after, rationale = res
        checks = static_checks(before, after, vuln, profile["rule_packs"])
        bad = failed(checks)
        if not bad:
            return _result(path, vuln["file_path"], before, after, rationale, "rule", checks, lines)
        lines.append(log("WARN", "Rule-based patch rejected by its checks: " + "; ".join(f"{c['label']}: {c['detail']}" for c in bad)))
    else:
        lines.append(log("INFO", f"No rule-based patch: {res}"))

    if not (ai.enabled() if use_ai is None else use_ai):
        return _fail("no rule-based patch applies and AI fixes are off (add an AI key to .env)", lines)
    outcome = ai.propose_fix(before, vuln, profile)
    lines += outcome["log"]
    if outcome["after"] is None:
        return _fail(outcome["reason"], lines, outcome["checks"])
    return _result(path, vuln["file_path"], before, outcome["after"], outcome["rationale"], "ai", outcome["checks"],
                   lines, outcome["behaviour_change"])

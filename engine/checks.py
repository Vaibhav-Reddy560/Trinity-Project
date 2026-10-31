"""Static proof checks. Every fix, rule-based or written by Claude, must pass them before it is applied:

- compiles: the patched file parses and compiles
- fixed: the rule that flagged the code no longer flags it
- no_new: nothing in the file is newly flagged
- scoped: only the flagged function (or flagged top-level statements) changed, plus imports and PatchProof helpers
- signature: the function keeps its name, parameters and decorators, so callers keep working

Practice targets add exploit and regression runs on top (verifier.py).
"""

import ast
import copy
import difflib
import functools
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from engine import lang_rules
from engine.languages import is_python, language_of
from engine.models import Check

LABELS = {
    "compiles": "Patched code compiles",
    "fixed": "Weakness no longer detected",
    "no_new": "No new weaknesses introduced",
    "scoped": "Change stays inside the flagged code",
    "signature": "Function signature unchanged",
    "ai_recheck": "AI re-check: weakness resolved",
    "exploit": "Exploit blocked",
    "regression": "Normal behaviour preserved",
}

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef


def check(cid: str, passed: bool | None, detail: str) -> Check:
    return {"id": cid, "label": LABELS[cid], "passed": passed, "detail": detail}


def failed(checks: list[Check]) -> list[Check]:
    return [c for c in checks if c["passed"] is False]


@dataclass
class Region:
    """What a fix may change: one function (by qualified name, e.g. Agent.chat), or top-level statements lo..hi."""

    qualname: str | None
    lo: int
    hi: int

    @property
    def where(self) -> str:
        return f"{self.qualname}()" if self.qualname else f"the top-level statements on lines {self.lo}-{self.hi}"


def functions(tree: ast.AST) -> dict[str, FuncNode]:
    out: dict[str, FuncNode] = {}

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                if not isinstance(child, ast.ClassDef):
                    out[name] = child
                walk(child, name + ".")
            else:
                walk(child, prefix)

    walk(tree, "")
    return out


def start_line(node: ast.AST) -> int:
    return min([node.lineno, *(d.lineno for d in getattr(node, "decorator_list", []))])  # type: ignore[attr-defined]


def locate(source: str, vuln: dict) -> tuple[int, int]:
    """Current lines of the flagged code, matched by content (earlier fixes may have shifted it), else as recorded."""
    want = [ln.strip() for ln in vuln["original_code"].strip().splitlines()]
    lines = [ln.strip() for ln in source.splitlines()]
    n = len(want)
    starts = [i for i in range(len(lines) - n + 1) if n and lines[i:i + n] == want]
    if starts:
        best = min(starts, key=lambda i: abs(i + 1 - vuln["line_number"]))
        return best + 1, best + n
    return vuln["line_number"], vuln["end_line"]


def region_for(tree: ast.Module, lo: int, hi: int) -> Region:
    """The innermost function holding lines lo..hi, else the top-level statements that overlap them."""
    inner: tuple[str, FuncNode] | None = None
    for qual, fn in functions(tree).items():
        if start_line(fn) <= lo and hi <= (fn.end_lineno or fn.lineno):
            if inner is None or start_line(fn) >= start_line(inner[1]):
                inner = (qual, fn)
    if inner:
        return Region(inner[0], start_line(inner[1]), inner[1].end_lineno or inner[1].lineno)
    stmts = [s for s in tree.body if start_line(s) <= hi and (s.end_lineno or s.lineno) >= lo]
    if not stmts:
        return Region(None, lo, hi)
    return Region(None, start_line(stmts[0]), max(s.end_lineno or s.lineno for s in stmts))


def _scope_of(tree: ast.Module):
    spans = sorted(((start_line(fn), fn.end_lineno or fn.lineno, q) for q, fn in functions(tree).items()), key=lambda s: s[0])

    def scope(line: int) -> str:
        best = "<module>"
        for lo, hi, q in spans:
            if lo <= line <= hi:
                best = q  # later starts are nested deeper
        return best

    return scope


def _flagged(tree: ast.Module, source: str, packs: list[str]) -> list[tuple[str, str, str]]:
    """(type, scope, code) of every rule hit."""
    return list(_flagged_cached(source, tuple(packs)))


@functools.lru_cache(maxsize=64)
def _flagged_cached(source: str, packs: tuple[str, ...]) -> tuple[tuple[str, str, str], ...]:
    """Rescans are deterministic, so they are cached by file content: verify reuses the scans made when the patch was
    checked, and one fix's "after" is the next fix's "before" in the same file."""
    from engine.scanner import flagged

    tree = _parse(source)
    lines = source.splitlines()
    scope = _scope_of(tree)
    return tuple((t, scope(s), "\n".join(lines[s - 1 : e]).strip()) for t, s, e in flagged(tree, list(packs)))


@functools.lru_cache(maxsize=64)
def _parse(source: str) -> ast.Module:
    return ast.parse(source)  # callers never mutate it: _skeleton works on a deep copy


def _allowed_addition(stmt: ast.stmt) -> bool:
    return (isinstance(stmt, (ast.Import, ast.ImportFrom))
            or (isinstance(stmt, ast.FunctionDef) and stmt.name.startswith("_patchproof"))
            or (isinstance(stmt, ast.Assign) and all(isinstance(t, ast.Name) and t.id.startswith("PATCHPROOF_") for t in stmt.targets)))


class _Blank(ast.NodeTransformer):
    """Replace one function, found by qualified name, with `pass`."""

    def __init__(self, target: str) -> None:
        self.target, self.stack = target, []

    def _visit(self, node):
        name = ".".join([*self.stack, node.name])
        if name == self.target:
            return ast.Pass()
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()
        return node

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _visit


def _skeleton(tree: ast.Module, qualname: str | None) -> list[ast.stmt]:
    tree = copy.deepcopy(tree)
    if qualname:
        tree = _Blank(qualname).visit(tree)
    return [s for s in tree.body if not _allowed_addition(s)]


def _scoped(t0: ast.Module, t1: ast.Module, region: Region) -> Check:
    if region.qualname and region.qualname not in functions(t1):
        return check("scoped", False, f"{region.qualname}() was removed or renamed.")
    a, b = _skeleton(t0, region.qualname), _skeleton(t1, region.qualname)
    da, db = [ast.dump(s) for s in a], [ast.dump(s) for s in b]
    if region.qualname:
        if da == db:
            return check("scoped", True, f"Only {region.where} changed, plus imports or PatchProof helpers.")
        i = next((i for i, (x, y) in enumerate(zip(da, db)) if x != y), min(len(da), len(db)))
        near = f" near line {start_line(a[i])}" if i < len(a) else ""
        return check("scoped", False, f"Code outside {region.where} changed{near}.")
    p = 0
    while p < min(len(da), len(db)) and da[p] == db[p]:
        p += 1
    s = 0
    while s < min(len(da), len(db)) - p and da[-1 - s] == db[-1 - s]:
        s += 1
    outside = [st for st in a[p : len(a) - s] if start_line(st) < region.lo or (st.end_lineno or st.lineno) > region.hi]
    if outside:
        return check("scoped", False, f"Top-level code outside lines {region.lo}-{region.hi} changed near line {start_line(outside[0])}.")
    return check("scoped", True, f"Only {region.where} changed, plus imports or PatchProof helpers.")


def _signature(t0: ast.Module, t1: ast.Module, qualname: str) -> Check:
    f0, f1 = functions(t0)[qualname], functions(t1).get(qualname)
    if f1 is None:
        return check("signature", False, f"{qualname}() no longer exists.")
    changes = []
    if type(f0) is not type(f1):
        changes.append("async/sync")
    if ast.dump(f0.args) != ast.dump(f1.args):
        changes.append("parameters")
    kept = iter([ast.dump(d) for d in f1.decorator_list])
    if not all(d in kept for d in (ast.dump(d) for d in f0.decorator_list)):
        changes.append("decorators")
    if changes:
        return check("signature", False, f"{qualname}() changed its {' and '.join(changes)}, which can break callers.")
    added = len(f1.decorator_list) - len(f0.decorator_list)
    extra = f" It gains {added} decorator{'s' if added > 1 else ''}, such as an access check." if added else ""
    return check("signature", True, f"{qualname}() keeps its name, parameters and decorators, so callers keep working.{extra}")


# ---------- other languages: no syntax tree, so the checks work on text ----------

IMPORT_LIKE = re.compile(
    r"^\s*(?:import\b|from\s+\S+\s+import\b|(?:const|let|var)\s+[\w{}\s,*]+\s*=\s*require\s*\(|require(?:_once)?\b|include(?:_once)?\b|"
    r"use\s+[\w\\]+|using\s+[\w.]+;|#include\b|package\b|@?require\b|<\?php|require_relative\b|load\b)")
SYNTAX_TOOLS = {"javascript": ({".js", ".mjs", ".cjs"}, ["node", "--check"]), "php": ({".php"}, ["php", "-l"]),
                "ruby": ({".rb"}, ["ruby", "-c"]), "shell": ({".sh", ".bash"}, ["bash", "-n"]), "go": ({".go"}, ["gofmt", "-e"])}


def _balance(text: str) -> tuple[int, int, int]:
    text = re.sub(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)(?:^|\s)(?://|#).*$", "", text)
    return text.count("(") - text.count(")"), text.count("{") - text.count("}"), text.count("[") - text.count("]")


def _syntax(after: str, rel: str, lang: str | None) -> tuple[bool | None, str]:
    """Run the language's own syntax check when it is installed; else compare bracket balance with the original."""
    suffix = Path(rel).suffix.lower()
    tool = SYNTAX_TOOLS.get(lang or "")
    if tool and suffix in tool[0] and shutil.which(tool[1][0]):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ("check" + suffix)
            target.write_text(after)
            try:
                run = subprocess.run([*tool[1], str(target)], capture_output=True, text=True, timeout=15)
            except (subprocess.TimeoutExpired, OSError):
                return None, f"{tool[1][0]} could not be run"
            if run.returncode == 0 and not (tool[1][0] == "gofmt" and run.stderr.strip()):
                return True, f"{tool[1][0]} accepts the patched file."
            return False, (run.stderr.strip() or run.stdout.strip()).splitlines()[0][:200] if (run.stderr or run.stdout).strip() else f"{tool[1][0]} rejected the file."
    return None, "No syntax checker for this language is installed here, so brackets are compared instead."


def _text_hits(source: str, lang: str | None) -> list[tuple[str, str]]:
    """(type, stripped first line) of every pattern-rule hit in a non-Python file."""
    if lang is None:
        return []
    lines = source.splitlines()
    return [(t, lines[h.start - 1].strip()) for t, _, _, h in lang_rules.scan_source(source, lang)]


def text_checks(before: str, after: str, vuln: dict) -> list[Check]:
    rel = vuln["file_path"]
    lang = language_of(rel)
    out: list[Check] = []
    ok, how = _syntax(after, rel, lang)
    delta = tuple(a - b for a, b in zip(_balance(after), _balance(before)))
    if ok is False:
        out.append(check("compiles", False, f"Syntax error: {how}"))
        return out
    if ok is None and any(delta):
        out.append(check("compiles", False, f"Brackets no longer balance after the fix (change in (), {{}}, []: {delta}). {how}"))
        return out
    out.append(check("compiles", True, how if ok else "Brackets balance exactly as in the original. " + how.split(", so")[0] + "."))

    lo, hi = locate(before, vuln)
    b_hits, a_hits = _text_hits(before, lang), _text_hits(after, lang)
    first = vuln["original_code"].strip().splitlines()[0].strip() if vuln["original_code"].strip() else ""
    if vuln.get("detected_by", "rule") == "rule":
        n0 = sum(1 for t, _ in b_hits if t == vuln["type"])
        n1 = sum(1 for t, _ in a_hits if t == vuln["type"])
        same = any(t == vuln["type"] and line == first for t, line in a_hits)
        if n1 < n0 and not same:
            out.append(check("fixed", True, f"Rescanned: the rule no longer flags this code ({n0} hits before, {n1} after in the file)."))
        else:
            out.append(check("fixed", False, "Rescanned: the rule still flags this code."))
    else:
        out.append(check("fixed", None, "Found by the AI deep scan, so no rule can re-check it. The model re-checks it at verification."))
    new = Counter(t for t, _ in a_hits) - Counter(t for t, _ in b_hits)
    out.append(check("no_new", not new, f"Newly flagged after the fix: {', '.join(new)}." if new else
                     f"Rescanned the whole file: nothing new is flagged ({len(a_hits)} findings remain, all pre-existing)." if a_hits else
                     "Rescanned the whole file: nothing is flagged."))

    bl, al = before.splitlines(), after.splitlines()
    stray = None
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, bl, al, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        inside = lo - 1 <= i1 and i2 <= hi
        imports = tag == "insert" and all(IMPORT_LIKE.match(x) for x in al[j1:j2])
        if not (inside or imports or (tag == "insert" and lo - 1 <= i1 <= hi)):
            stray = i1 + 1
            break
    out.append(check("scoped", stray is None,
                     f"Only lines {lo}-{hi} changed, plus new imports." if stray is None else f"Code outside lines {lo}-{hi} changed near line {stray}."))
    return out


def static_checks(before: str, after: str, vuln: dict, packs: list[str]) -> list[Check]:
    if not is_python(vuln["file_path"]):
        return text_checks(before, after, vuln)
    try:
        compile(after, vuln["file_path"], "exec")
    except SyntaxError as e:
        return [check("compiles", False, f"Line {e.lineno}: {e.msg}.")]
    out = [check("compiles", True, "The patched file parses and compiles.")]
    t0, t1 = _parse(before), _parse(after)
    region = region_for(t0, *locate(before, vuln))
    h0, h1 = _flagged(t0, before, packs), _flagged(t1, after, packs)

    if vuln.get("detected_by", "rule") == "rule":
        key = (vuln["type"], region.qualname or "<module>")
        n0 = sum(1 for t, sc, _ in h0 if (t, sc) == key)
        n1 = sum(1 for t, sc, _ in h1 if (t, sc) == key)
        same = any((t, sc) == key and code == vuln["original_code"].strip() for t, sc, code in h1)
        if n1 < n0 and not same:
            out.append(check("fixed", True, f"Rescanned: the rule no longer flags this code in {region.where}."))
        else:
            out.append(check("fixed", False, f"Rescanned: the rule still flags this code in {region.where}."))
    else:
        out.append(check("fixed", None, "Found by the AI deep scan, so no rule can re-check it. Claude re-checks it at verification."))

    new = Counter((t, sc) for t, sc, _ in h1) - Counter((t, sc) for t, sc, _ in h0)
    if new:
        listed = ", ".join(f"{t} in {'module level' if sc == '<module>' else sc + '()'}" for t, sc in new)
        out.append(check("no_new", False, f"Newly flagged after the fix: {listed}."))
    else:
        left = f"the {len(h1)} remaining finding{'s were' if len(h1) != 1 else ' was'} already there" if h1 else "nothing is flagged at all"
        out.append(check("no_new", True, f"Rescanned the whole file: nothing new is flagged ({left})."))

    out.append(_scoped(t0, t1, region))
    if region.qualname:
        out.append(_signature(t0, t1, region.qualname))
    return out

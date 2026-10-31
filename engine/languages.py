"""Which source files PatchProof reads, and in which language. Python gets full syntax-tree analysis; every other
language gets pattern rules (engine/lang_rules.py), the AI deep scan, and AI fixes under language-neutral proof checks."""

from pathlib import Path

LANGUAGES = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"},
    "php": {".php", ".phtml"},
    "java": {".java", ".kt", ".scala", ".groovy"},
    "go": {".go"},
    "ruby": {".rb", ".erb"},
    "csharp": {".cs", ".cshtml", ".razor"},
    "html": {".html", ".htm"},
    "rust": {".rs"},
    "c": {".c", ".h", ".cc", ".cpp", ".hpp"},
    "shell": {".sh", ".bash"},
}
EXT_TO_LANG = {ext: lang for lang, exts in LANGUAGES.items() for ext in exts}
LANG_LABEL = {
    "python": "Python", "javascript": "JavaScript/TypeScript", "php": "PHP", "java": "Java/Kotlin", "go": "Go",
    "ruby": "Ruby", "csharp": "C#", "html": "HTML", "rust": "Rust", "c": "C/C++", "shell": "Shell",
}
# Files that are output, vendored or minified: never real source.
GENERATED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".chunk.js", ".map", ".d.ts")


def language_of(rel: str) -> str | None:
    name = Path(rel).name.lower()
    if name.endswith(GENERATED_SUFFIXES):
        return None
    return EXT_TO_LANG.get(Path(rel).suffix.lower())


def is_python(rel: str) -> bool:
    return Path(rel).suffix.lower() == ".py"


def is_test_file(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1].lower()
    return (
        any(p in ("test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "mocks") for p in parts[:-1])
        or name.startswith("test_") or name.endswith(("_test.py", "_test.go", ".test.js", ".test.ts", ".test.tsx", ".test.jsx",
                                                      ".spec.js", ".spec.ts", "test.java", "tests.java", "_spec.rb"))
        or name == "conftest.py"
    )

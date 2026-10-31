"""Target profiles: what to scan, which rules apply, and how (if at all) exploits run.

Curated profiles live in target_app/profiles/*.json and point at code shipped in this repo,
so their exploits may run. A "project" profile is built on the fly for any local folder or
cloned repository; project code is only parsed, never imported or executed.
"""

import hashlib
import json
from pathlib import Path

from engine.languages import language_of

REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = REPO_ROOT / "target_app" / "profiles"
DEFAULT_PROFILE = "vuln-bank"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", ".env", "__pycache__", "site-packages",
    "dist", "build", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode",
    "vendor", "bower_components", "coverage", ".next", ".nuxt", ".gradle", ".terraform", "Pods", ".cache", "target",
}
MAX_FILES = 3000
MAX_FILE_BYTES = 1_000_000
ALL_SOURCE = "**/*"  # every source file in a language PatchProof reads (engine/languages.py)
ALL_PYTHON = ALL_SOURCE  # the old name, kept for profiles written before other languages were supported


def list_profiles() -> list[dict]:
    return sorted((json.loads(p.read_text()) for p in PROFILES_DIR.glob("*.json")), key=lambda p: p["id"] != DEFAULT_PROFILE)


def load_profile(profile_id: str = DEFAULT_PROFILE) -> dict:
    path = PROFILES_DIR / f"{profile_id}.json"
    if not path.is_file():
        raise KeyError(profile_id)
    return json.loads(path.read_text())


def project_profile(root: Path, name: str, source: str) -> dict:
    return {
        "id": "project-" + hashlib.sha1(str(root.resolve()).encode()).hexdigest()[:8],
        "kind": "project",
        "name": name,
        "summary": "Your project, scanned statically. Its code is read, never run.",
        "module": "Whole project (every language)",
        "source": source,
        "commit": None,
        "path": str(root.resolve()),
        "in_scope": [{"file": ALL_SOURCE, "lines": None, "role": "Every source file: scanned, fixed in a copy and proven by static checks"}],
        "out_of_scope": [
            "Dependencies, virtual environments, vendored code and build output",
            "Exploits: your code is never run, so fixes are proven by static checks instead",
        ],
        "rule_packs": ["ai", "generic"],
        "harness": None,
    }


def source_root(profile: dict) -> Path:
    """Where the target's original code lives (a repo-relative snapshot, or an absolute project path)."""
    p = Path(profile["path"])
    return p if p.is_absolute() else REPO_ROOT / p


def cases_for_profile(profile: dict) -> list[dict]:
    harness = profile.get("harness")
    if not harness:
        return []
    return json.loads((REPO_ROOT / harness["cases"]).read_text())["cases"]


def harness_files(profile: dict) -> set[str] | None:
    """Files the target's exploit and regression cases actually run. Only fixes there can be proven by them."""
    harness = profile.get("harness") or {}
    return set(harness["files"]) if "files" in harness else None


def harness_env(profile: dict) -> dict[str, str]:
    """Configuration the practice app reads from its environment, supplied to every case the way a deployment would."""
    harness = profile.get("harness")
    if not harness:
        return {}
    return json.loads((REPO_ROOT / harness["cases"]).read_text()).get("env", {})


def iter_python_files(root: Path) -> tuple[list[str], int]:
    """Python files only. Kept for callers that need just those; scanning uses iter_source_files."""
    files, skipped = iter_source_files(root)
    return [f for f in files if f.endswith(".py")], skipped


def iter_source_files(root: Path) -> tuple[list[str], int]:
    """Relative paths of every source file in a supported language, plus how many were skipped for size or the cap."""
    found: list[str] = []
    skipped = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS and not entry.name.endswith(".egg-info"):
                    stack.append(entry)
            elif language_of(entry.name):
                if entry.stat().st_size > MAX_FILE_BYTES or len(found) >= MAX_FILES:
                    skipped += 1
                else:
                    found.append(entry.relative_to(root).as_posix())
    return sorted(found), skipped


def in_scope_files(profile: dict, root: Path) -> list[tuple[str, tuple[int, int] | None]]:
    files: list[tuple[str, tuple[int, int] | None]] = []
    for entry in profile["in_scope"]:
        if entry["file"] == ALL_SOURCE:
            files += [(rel, None) for rel in iter_source_files(root)[0]]
        else:
            files.append((entry["file"], tuple(entry["lines"]) if entry["lines"] else None))
    seen: set[str] = set()
    return [f for f in files if not (f[0] in seen or seen.add(f[0]))]  # a file listed twice is scanned once

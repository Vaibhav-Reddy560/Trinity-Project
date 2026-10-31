"""Target profiles: what to scan, which rules apply, and how (if at all) exploits run.

Curated profiles live in target_app/profiles/*.json and point at code shipped in this repo,
so their exploits may run. A "project" profile is built on the fly for any local folder or
cloned repository; project code is only parsed, never imported or executed.
"""

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = REPO_ROOT / "target_app" / "profiles"
DEFAULT_PROFILE = "vuln-bank"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", ".env", "__pycache__", "site-packages",
    "dist", "build", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode",
}
MAX_FILES = 3000
MAX_FILE_BYTES = 1_000_000
ALL_PYTHON = "**/*.py"


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
        "module": "Whole project (Python)",
        "source": source,
        "commit": None,
        "path": str(root.resolve()),
        "in_scope": [{"file": ALL_PYTHON, "lines": None, "role": "Static scan only: findings are detected, not proven"}],
        "out_of_scope": [
            "Non-Python files",
            "Dependencies, virtual environments and build output",
            "Exploits and automatic patches: these only run on curated practice targets",
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


def harness_env(profile: dict) -> dict[str, str]:
    """Configuration the practice app reads from its environment, supplied to every case the way a deployment would."""
    harness = profile.get("harness")
    if not harness:
        return {}
    return json.loads((REPO_ROOT / harness["cases"]).read_text()).get("env", {})


def iter_python_files(root: Path) -> tuple[list[str], int]:
    """Relative paths of Python files to scan, plus how many were skipped for size or the file cap."""
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
            elif entry.suffix == ".py":
                if entry.stat().st_size > MAX_FILE_BYTES or len(found) >= MAX_FILES:
                    skipped += 1
                else:
                    found.append(entry.relative_to(root).as_posix())
    return sorted(found), skipped


def in_scope_files(profile: dict, root: Path) -> list[tuple[str, tuple[int, int] | None]]:
    files: list[tuple[str, tuple[int, int] | None]] = []
    for entry in profile["in_scope"]:
        if entry["file"] == ALL_PYTHON:
            files += [(rel, None) for rel in iter_python_files(root)[0]]
        else:
            files.append((entry["file"], tuple(entry["lines"]) if entry["lines"] else None))
    return files

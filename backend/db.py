"""TinyDB storage: the `vulnerabilities` table (PROJECT_CONTEXT.md §5), the active target, and its workspace."""

import hashlib
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from tinydb import Query, TinyDB

from engine.patcher import unified_diff
from engine.targets import iter_python_files, load_profile, source_root

ROOT = Path(__file__).resolve().parent
PRISTINE_DIR = ROOT.parent / "target_app" / "vuln-bank"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
WORKSPACE_MARKER = ".patchproof-target"

_lock = threading.RLock()
_db: TinyDB | None = None
DATA_DIR = Path(os.environ.get("PATCHPROOF_DATA_DIR", ROOT / "data"))


def configure(data_dir: Path) -> None:
    """Point storage at another directory (used by tests)."""
    global DATA_DIR, _db
    with _lock:
        if _db is not None:
            _db.close()
        DATA_DIR, _db = Path(data_dir), None


def _database() -> TinyDB:
    global _db
    if _db is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _db = TinyDB(DATA_DIR / "patchproof.json", indent=2)
    return _db


def _table():
    return _database().table("vulnerabilities")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------- active target ----------

def _meta(key: str) -> dict | None:
    with _lock:
        row = _database().table("meta").get(Query().key == key)
    return row["value"] if row else None


def _set_meta(key: str, value: dict | None) -> None:
    with _lock:
        _database().table("meta").upsert({"key": key, "value": value}, Query().key == key)


def active_target() -> dict:
    return _meta("active_target") or load_profile()


def set_active_target(profile: dict) -> None:
    _set_meta("active_target", profile)


def scan_stats() -> dict | None:
    return _meta("scan_stats")


def set_scan_stats(stats: dict | None) -> None:
    _set_meta("scan_stats", stats)


def select_error() -> dict | None:
    return _meta("select_error")


def set_select_error(message: str | None) -> None:
    _set_meta("select_error", {"message": message, "at": now()} if message else None)


def deep_scan_report() -> dict | None:
    return _meta("deep_scan")


def set_deep_scan_report(report: dict | None) -> None:
    _set_meta("deep_scan", report)


def projects_dir() -> Path:
    return DATA_DIR / "projects"


# ---------- findings ----------

def vuln_id(file_path: str, vuln_type: str, anchor: str = "") -> str:
    # Stable across rescans and line shifts. Single-site rules have no anchor, so the ID is per (file, type).
    key = f"{file_path}:{vuln_type}" + (f":{anchor}" if anchor else "")
    return "vuln_" + hashlib.sha1(key.encode()).hexdigest()[:6]


def _upgrade(row: dict) -> dict:
    """Records saved before fixes were proven by checks: there, patchable meant "exploit case and rule-based patch"."""
    if "fixer" not in row:
        row = {**row, "provable": row["patchable"], "fixer": "rule" if row["patchable"] else None, "detected_by": "rule",
               "fix_source": "rule" if row.get("diff") else None, "checks": [], "ai_review": None, "behaviour_change": None,
               "base_code": None}
    return row


def list_vulns() -> list[dict]:
    with _lock:
        rows = [_upgrade(dict(r)) for r in _table().all()]
    return sorted(rows, key=lambda v: (SEVERITY_ORDER[v["severity"]], v["file_path"], v["line_number"]))


def get_vuln(vid: str) -> dict | None:
    with _lock:
        row = _table().get(Query().id == vid)
    return _upgrade(dict(row)) if row else None


def add_findings(findings: list[dict]) -> int:
    """Insert findings not seen before. Existing records keep their pipeline state; untouched ones get
    fresh fix availability (AI may have been switched on since the last scan)."""
    added = 0
    with _lock:
        table = _table()
        for f in findings:
            f = dict(f)
            vid = vuln_id(f["file_path"], f["type"], f.pop("anchor", ""))
            existing = table.get(Query().id == vid)
            if existing:
                if existing["status"] == "OPEN" and not existing["diff"]:
                    table.update({k: f[k] for k in ("patchable", "provable", "fixer")}, Query().id == vid)
                continue
            t = now()
            table.insert({
                "id": vid, **f,
                "status": "OPEN", "patched_code": None, "diff": None, "patch_rationale": None,
                "poc_status": "NOT_RUN", "regression_status": "NOT_RUN",
                "poc_log": [], "verification_log": [],
                "fix_source": None, "checks": [], "ai_review": None, "behaviour_change": None, "base_code": None,
                "created_at": t, "updated_at": t,
            })
            added += 1
    return added


def update_vuln(vid: str, **fields) -> None:
    with _lock:
        _table().update({**fields, "updated_at": now()}, Query().id == vid)


def clear() -> None:
    with _lock:
        _table().truncate()


# ---------- workspace ----------

def workspace_dir() -> Path:
    """The writable copy every fix is applied to. The target's own code (and your project folder) is never modified."""
    return DATA_DIR / "workspace"


def reset_workspace() -> None:
    """Replace the working copy with the target's original source. Projects copy only their Python files."""
    target = active_target()
    ws, src = workspace_dir(), source_root(target)
    with _lock:
        if ws.exists():
            shutil.rmtree(ws)
        if target["kind"] == "project":
            for rel in iter_python_files(src)[0]:
                (ws / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src / rel, ws / rel)
            ws.mkdir(parents=True, exist_ok=True)
        else:
            shutil.copytree(src, ws, ignore=shutil.ignore_patterns("static", "templates", "tests", "__pycache__"))
        (ws / WORKSPACE_MARKER).write_text(target["id"])


def combined_diff() -> str:
    """One unified diff of every fixed file: original source against the workspace copy."""
    src, ws = source_root(active_target()), workspace_dir()
    files = sorted({v["file_path"] for v in list_vulns() if v["diff"]})
    return "".join(
        unified_diff(rel, (src / rel).read_text(errors="replace"), (ws / rel).read_text(errors="replace"))
        for rel in files if (src / rel).is_file() and (ws / rel).is_file()
    )


def ensure_workspace() -> None:
    target = active_target()
    marker = workspace_dir() / WORKSPACE_MARKER
    if not marker.is_file() or marker.read_text() != target["id"]:
        reset_workspace()

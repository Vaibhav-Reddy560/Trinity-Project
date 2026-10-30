"""TinyDB storage for the `vulnerabilities` table (PROJECT_CONTEXT.md §5) and the workspace copy."""

import hashlib
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from tinydb import Query, TinyDB

ROOT = Path(__file__).resolve().parent
PRISTINE_DIR = ROOT.parent / "target_app" / "vuln-bank"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

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


def workspace_dir() -> Path:
    return DATA_DIR / "workspace"


def _table():
    global _db
    if _db is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _db = TinyDB(DATA_DIR / "patchproof.json", indent=2)
    return _db.table("vulnerabilities")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def vuln_id(file_path: str, vuln_type: str) -> str:
    # Stable across rescans, so links to a finding survive a reset and a new scan.
    return "vuln_" + hashlib.sha1(f"{file_path}:{vuln_type}".encode()).hexdigest()[:6]


def list_vulns() -> list[dict]:
    with _lock:
        rows = [dict(r) for r in _table().all()]
    return sorted(rows, key=lambda v: (SEVERITY_ORDER[v["severity"]], v["file_path"] != "ai_agent_deepseek.py", v["line_number"]))


def get_vuln(vid: str) -> dict | None:
    with _lock:
        row = _table().get(Query().id == vid)
    return dict(row) if row else None


def add_findings(findings: list[dict]) -> int:
    """Insert findings not seen before; existing records keep their pipeline state."""
    added = 0
    with _lock:
        table = _table()
        for f in findings:
            vid = vuln_id(f["file_path"], f["type"])
            if table.contains(Query().id == vid):
                continue
            t = now()
            table.insert({
                "id": vid, **f,
                "status": "OPEN", "patched_code": None, "diff": None, "patch_rationale": None,
                "poc_status": "NOT_RUN", "regression_status": "NOT_RUN",
                "poc_log": [], "verification_log": [],
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


def reset_workspace() -> None:
    """Replace the working copy with the pristine snapshot (which is never modified)."""
    ws = workspace_dir()
    with _lock:
        if ws.exists():
            shutil.rmtree(ws)
        shutil.copytree(PRISTINE_DIR, ws, ignore=shutil.ignore_patterns("static", "templates", "tests", "__pycache__"))


def ensure_workspace() -> None:
    if not (workspace_dir() / "ai_agent_deepseek.py").is_file():
        reset_workspace()

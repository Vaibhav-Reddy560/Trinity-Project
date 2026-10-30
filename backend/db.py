from pathlib import Path

from tinydb import TinyDB

DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "patchproof.json"
WORKSPACE_DIR = DATA_DIR / "workspace"
PRISTINE_DIR = Path(__file__).parent.parent / "target_app" / "vuln-bank"


def get_db() -> TinyDB:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return TinyDB(DB_PATH, indent=2)


def vulns_table():
    return get_db().table("vulnerabilities")

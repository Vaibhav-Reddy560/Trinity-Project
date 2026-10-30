"""Background jobs: call one engine function, store the result. One job runs at a time."""

import logging
import threading
from collections.abc import Callable

from backend import db
from engine import apply_patch, run_poc, scan_repository, verify_fix

log = logging.getLogger("patchproof.jobs")

_state = {"busy": False, "action": None}
_state_lock = threading.Lock()


def try_begin(action: str) -> bool:
    with _state_lock:
        if _state["busy"]:
            return False
        _state.update(busy=True, action=action)
        return True


def status() -> dict:
    with _state_lock:
        return dict(_state)


def run(job: Callable[..., None], *args) -> None:
    try:
        job(*args)
    except Exception:
        log.exception("job %s failed", job.__name__)
        if args:
            db.update_vuln(args[0], verification_log=[{"ts": db.now(), "level": "ERROR", "msg": "Internal error while running this step. See the API log."}])
    finally:
        with _state_lock:
            _state.update(busy=False, action=None)


def _ws() -> str:
    return str(db.workspace_dir())


def scan() -> None:
    db.ensure_workspace()
    db.add_findings(scan_repository(_ws()))


def poc(vid: str) -> None:
    vuln = db.get_vuln(vid)
    result = run_poc(_ws(), vuln)
    poc_status = "EXPLOITABLE" if result["exploitable"] else "BLOCKED"
    if vuln["diff"]:
        # Replaying against patched code: poc_log keeps the original pre-patch evidence.
        header = {"ts": db.now(), "level": "INFO", "msg": "Exploit replayed against the patched copy"}
        db.update_vuln(vid, poc_status=poc_status, verification_log=[*vuln["verification_log"], header, *result["log"]])
    else:
        db.update_vuln(vid, poc_status=poc_status, poc_log=result["log"])


def patch(vid: str) -> None:
    result = apply_patch(_ws(), db.get_vuln(vid))
    if result["success"]:
        db.update_vuln(
            vid, status="PATCHED", patched_code=result["patched_code"], diff=result["diff"],
            patch_rationale=result["patch_rationale"], regression_status="NOT_RUN", verification_log=result.get("log", []),
        )
    else:
        db.update_vuln(vid, status="FAILED", verification_log=result.get("log", []))


def verify(vid: str) -> None:
    result = verify_fix(_ws(), db.get_vuln(vid))
    ok = result["security_blocked"] and result["regression_passed"]
    db.update_vuln(
        vid,
        status="VERIFIED" if ok else "FAILED",
        poc_status="BLOCKED" if result["security_blocked"] else "EXPLOITABLE",
        regression_status="PASSED" if result["regression_passed"] else "FAILED",
        verification_log=result["log"],
    )


def run_all() -> None:
    """Scan, then prove, patch and verify every patchable finding in severity order."""
    scan()
    for v in db.list_vulns():
        if not v["patchable"] or v["status"] == "VERIFIED" or (v["status"] == "FAILED" and v["diff"]):
            continue
        if v["status"] != "PATCHED":
            poc(v["id"])
            if db.get_vuln(v["id"])["poc_status"] != "EXPLOITABLE":
                continue
            patch(v["id"])
            if db.get_vuln(v["id"])["status"] != "PATCHED":
                continue
        verify(v["id"])


def reset() -> None:
    db.reset_workspace()
    db.clear()

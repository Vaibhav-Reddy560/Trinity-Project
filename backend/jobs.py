"""Background jobs: call one engine function, store the result. One job runs at a time."""

import hashlib
import logging
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path

from backend import db
from engine import ai, apply_patch, run_poc, scan_repository, verify_fix
from engine.targets import iter_python_files, load_profile, project_profile, source_root

log = logging.getLogger("patchproof.jobs")

GIT_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+$")
CLONE_TIMEOUT_S = 120

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
        if args and isinstance(args[0], str) and args[0].startswith("vuln_"):
            db.update_vuln(args[0], verification_log=[{"ts": db.now(), "level": "ERROR", "msg": "Internal error while running this step. See the API log."}])
    finally:
        with _state_lock:
            _state.update(busy=False, action=None)


def _ws() -> str:
    return str(db.workspace_dir())


def _entry(level: str, msg: str) -> dict:
    return {"ts": db.now(), "level": level, "msg": msg}


def scan() -> None:
    db.ensure_workspace()
    target = db.active_target()
    stats: dict = {}
    db.add_findings(scan_repository(_ws(), target, stats))
    if target["kind"] == "project":
        stats["files_skipped"] = iter_python_files(source_root(target))[1]
    db.set_scan_stats(stats)


def poc(vid: str) -> None:
    vuln = db.get_vuln(vid)
    result = run_poc(_ws(), vuln, db.active_target())
    poc_status = "EXPLOITABLE" if result["exploitable"] else "BLOCKED"
    if vuln["diff"]:
        # Replaying against patched code: poc_log keeps the original pre-patch evidence.
        header = {"ts": db.now(), "level": "INFO", "msg": "Exploit replayed against the patched copy"}
        db.update_vuln(vid, poc_status=poc_status, verification_log=[*vuln["verification_log"], header, *result["log"]])
    else:
        db.update_vuln(vid, poc_status=poc_status, poc_log=result["log"])


def patch(vid: str) -> None:
    vuln = db.get_vuln(vid)
    path = Path(_ws()) / vuln["file_path"]
    if vuln["diff"]:
        # Retrying a fix that failed verification: put the file back as it was before that fix.
        if path.read_text() != vuln["patched_code"]:
            db.update_vuln(vid, verification_log=[*vuln["verification_log"], _entry(
                "ERROR", "Can't retry: another fix changed this file since. Reset the workspace to start over.")])
            return
        path.write_text(vuln["base_code"])
        db.update_vuln(vid, diff=None, patched_code=None, patch_rationale=None, fix_source=None, behaviour_change=None)
    result = apply_patch(_ws(), db.get_vuln(vid), db.active_target())
    if result["success"]:
        db.update_vuln(
            vid, status="PATCHED", patched_code=result["patched_code"], diff=result["diff"],
            patch_rationale=result["patch_rationale"], fix_source=result["fix_source"], checks=result["checks"],
            base_code=result["base_code"], behaviour_change=result["behaviour_change"],
            regression_status="NOT_RUN", verification_log=result["log"],
        )
    else:
        db.update_vuln(vid, status="FAILED", checks=result["checks"], verification_log=result["log"])


def verify(vid: str) -> None:
    vuln = db.get_vuln(vid)
    result = verify_fix(_ws(), vuln, db.active_target())
    ok = not any(c["passed"] is False for c in result["checks"])
    fields: dict = {"status": "VERIFIED" if ok else "FAILED", "checks": result["checks"], "verification_log": result["log"]}
    if result["security_blocked"] is not None:
        fields["poc_status"] = "BLOCKED" if result["security_blocked"] else "EXPLOITABLE"
    if result["regression_passed"] is not None:
        fields["regression_status"] = "PASSED" if result["regression_passed"] else "FAILED"
    if not vuln["provable"] and result.get("baseline_log"):
        fields["poc_log"] = result["baseline_log"]  # no exploit to record, so "before" is the regression baseline
    db.update_vuln(vid, **fields)


def _fix(v: dict) -> None:
    """Prove (when the target can), patch and verify one finding."""
    if v["status"] != "PATCHED":
        if v["provable"]:
            poc(v["id"])
            if db.get_vuln(v["id"])["poc_status"] != "EXPLOITABLE":
                return
        patch(v["id"])
        if db.get_vuln(v["id"])["status"] != "PATCHED":
            return
    verify(v["id"])


def run_all() -> None:
    """Scan, then prove, patch and verify in severity order: every provable finding first, then every other
    finding a rule-based patch covers. AI fixes run one at a time from the finding page (they cost API calls)."""
    scan()
    todo = [v for v in db.list_vulns() if v["patchable"] and v["status"] in ("OPEN", "PATCHED")]
    for v in [v for v in todo if v["provable"]] + [v for v in todo if not v["provable"] and v["fixer"] == "rule"]:
        _fix(v)


# ---------- AI ----------

def ai_fix_all() -> None:
    """Fix every open finding, one at a time: a rule-based patch where one applies, otherwise the AI model's, and
    verify each. Every fix still has to pass every check; the ones that don't are left as they were."""
    for v in db.list_vulns():
        if v["status"] == "OPEN":
            _fix(v)


def review(vid: str) -> None:
    vuln = db.get_vuln(vid)
    source = (Path(_ws()) / vuln["file_path"]).read_text()
    try:
        db.update_vuln(vid, ai_review=ai.review(source, vuln))
    except ai.AIError as e:
        db.update_vuln(vid, ai_review={"error": str(e), "model": ai.model(), "reviewed_at": db.now()})


def review_all() -> None:
    todo = [v for v in db.list_vulns() if v["detected_by"] == "rule" and (not v["ai_review"] or v["ai_review"].get("error"))]
    items = [((Path(_ws()) / v["file_path"]).read_text(), v) for v in todo]
    for v, result in zip(todo, ai.review_many(items)):
        db.update_vuln(v["id"], ai_review={**result, "model": ai.model(), "reviewed_at": db.now()} if "error" in result else result)


def deep_scan() -> None:
    db.ensure_workspace()
    report = ai.deep_scan(_ws(), db.active_target(), db.list_vulns())
    added = db.add_findings(report["findings"])
    db.set_deep_scan_report({"at": db.now(), "files": report["files"], "added": added, "dropped": report["dropped"],
                             "errors": report["errors"], "model": report["model"]})


def reset() -> None:
    db.reset_workspace()
    db.clear()
    db.set_scan_stats(None)
    db.set_deep_scan_report(None)


# ---------- choosing a target ----------

def validate_selection(profile_id: str | None, path: str | None, git_url: str | None) -> str | None:
    """Cheap checks done before accepting the request. Returns an error message, or None if OK."""
    if sum(x is not None for x in (profile_id, path, git_url)) != 1:
        return "Send exactly one of id, path or git_url."
    if profile_id is not None:
        try:
            load_profile(profile_id)
        except KeyError:
            return f"Unknown target {profile_id!r}."
    if path is not None:
        p = Path(path).expanduser()
        if not p.is_absolute() or not p.is_dir():
            return "Folder not found. Give the full path to a folder on this machine, e.g. /Users/you/code/my-app."
    if git_url is not None and not GIT_URL.match(git_url.strip()):
        return "Use a public https:// Git URL, e.g. https://github.com/owner/repo."
    return None


def _clone(url: str) -> Path:
    dest = db.projects_dir() / hashlib.sha1(url.encode()).hexdigest()[:10]
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--no-tags", "--single-branch", "--", url, str(dest)],
        capture_output=True, text=True, timeout=CLONE_TIMEOUT_S, env=env,
    )
    if proc.returncode != 0:
        detail = (proc.stderr.strip().splitlines() or ["git clone failed"])[-1]
        raise RuntimeError(f"Could not clone {url}: {detail}")
    return dest


def select_target(profile_id: str | None, path: str | None, git_url: str | None) -> None:
    """Switch the active target, start from its pristine code with no findings, and scan it."""
    try:
        if profile_id is not None:
            target = load_profile(profile_id)
        elif path is not None:
            root = Path(path).expanduser().resolve()
            target = project_profile(root, root.name, str(root))
        else:
            url = git_url.strip()
            target = project_profile(_clone(url), url.rstrip("/").removesuffix(".git").split("/")[-1], url)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        db.set_select_error(str(e) if isinstance(e, RuntimeError) else f"Cloning took longer than {CLONE_TIMEOUT_S}s.")
        return
    db.set_select_error(None)
    db.set_active_target(target)
    db.clear()
    db.set_scan_stats(None)
    db.set_deep_scan_report(None)
    db.reset_workspace()
    scan()

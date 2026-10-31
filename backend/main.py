from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from backend import db, jobs
from engine import ai
from engine.targets import REPO_ROOT, cases_for_profile, list_profiles

ai.load_env_file(REPO_ROOT / ".env")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.ensure_workspace()
    yield


app = FastAPI(title="PatchProof API", version="1.2.0", lifespan=lifespan)
api = APIRouter(prefix="/api/v1")


def _accept(bg: BackgroundTasks, action: str, job: Callable[..., None], *args, vuln_id: str | None = None) -> JSONResponse:
    if not jobs.try_begin(action):
        raise HTTPException(409, f"Another action ({jobs.status()['action']}) is still running. Wait for it to finish.")
    bg.add_task(jobs.run, job, *args)
    body = {"accepted": True, "action": action}
    if vuln_id:
        body["vuln_id"] = vuln_id
    return JSONResponse(body, status_code=202)


def _live(v: dict) -> dict:
    """Fix availability as of now: AI may have been switched on or off since the scan."""
    if v["fixer"] != "rule" and v["status"] == "OPEN" and not v["diff"]:
        fixer = "ai" if ai.enabled() else None
        v = {**v, "fixer": fixer, "patchable": fixer is not None}
    return v


def _vuln_or_404(vuln_id: str) -> dict:
    v = db.get_vuln(vuln_id)
    if v is None:
        raise HTTPException(404, f"Finding {vuln_id} does not exist. Run a scan to refresh the list.")
    return _live(v)


def _target_info(profile: dict, active: bool = False) -> dict:
    info = {k: profile.get(k) for k in ("id", "kind", "name", "summary", "module", "source", "commit", "in_scope", "out_of_scope")}
    info["provable"] = bool(profile.get("harness"))
    info["harness"] = (profile.get("harness") or {}).get("kind")
    if active:
        info["cases"] = [
            {k: c.get(k) for k in ("id", "kind", "types", "user", "message", "expected")} for c in cases_for_profile(profile)
        ]
        info["stats"] = db.scan_stats()
        info["deep_scan"] = db.deep_scan_report()
    return info


@app.get("/")
def root():
    return {"status": "PatchProof API Online"}


@api.get("/health")
def health():
    return {"status": "ok", **jobs.status(), "ai": ai.status()}


@api.get("/targets")
def targets():
    return {
        "active": _target_info(db.active_target(), active=True),
        "profiles": [_target_info(p) for p in list_profiles()],
        "error": db.select_error(),
    }


class TargetSelection(BaseModel):
    id: str | None = None
    path: str | None = None
    git_url: str | None = None


@api.post("/targets/select", status_code=202)
def select_target(body: TargetSelection, bg: BackgroundTasks):
    problem = jobs.validate_selection(body.id, body.path, body.git_url)
    if problem:
        raise HTTPException(404 if problem.startswith("Unknown target") else 422, problem)
    return _accept(bg, "select", jobs.select_target, body.id, body.path, body.git_url)


@api.get("/vulns")
def list_vulns():
    return {"vulns": [_live(v) for v in db.list_vulns()]}


@api.get("/vulns/{vuln_id}")
def get_vuln(vuln_id: str):
    return _vuln_or_404(vuln_id)


@api.post("/scan", status_code=202)
def scan(bg: BackgroundTasks):
    return _accept(bg, "scan", jobs.scan)


def _require_ai() -> None:
    status = ai.status()
    if not status["enabled"]:
        raise HTTPException(409, f"AI is off. {status['reason']}")


@api.post("/poc/{vuln_id}", status_code=202)
def poc(vuln_id: str, bg: BackgroundTasks):
    v = _vuln_or_404(vuln_id)
    if not v["provable"]:
        if db.active_target()["kind"] == "project":
            raise HTTPException(409, "This project is never run, so no exploit is attempted. Its fixes are proven by static checks.")
        raise HTTPException(409, "This target has no exploit case for this finding type. Its fix is proven by static checks and the regression suite.")
    return _accept(bg, "poc", jobs.poc, vuln_id, vuln_id=vuln_id)


@api.post("/patch/{vuln_id}", status_code=202)
def patch(vuln_id: str, bg: BackgroundTasks):
    v = _vuln_or_404(vuln_id)
    if v["status"] in ("PATCHED", "VERIFIED"):
        raise HTTPException(409, "This finding is already patched. Reset the workspace to patch it again.")
    if v["fixer"] == "ai" or not v["patchable"]:
        _require_ai()
    if v["provable"] and v["poc_status"] != "EXPLOITABLE" and not v["diff"]:
        raise HTTPException(409, "Run the exploit first. Only proven weaknesses can be patched.")
    return _accept(bg, "patch", jobs.patch, vuln_id, vuln_id=vuln_id)


@api.post("/verify/{vuln_id}", status_code=202)
def verify(vuln_id: str, bg: BackgroundTasks):
    v = _vuln_or_404(vuln_id)
    if v["status"] != "PATCHED":
        raise HTTPException(409, "Apply the patch before verifying.")
    return _accept(bg, "verify", jobs.verify, vuln_id, vuln_id=vuln_id)


@api.post("/ai/review/{vuln_id}", status_code=202)
def ai_review(vuln_id: str, bg: BackgroundTasks):
    _vuln_or_404(vuln_id)
    _require_ai()
    return _accept(bg, "review", jobs.review, vuln_id, vuln_id=vuln_id)


@api.post("/ai/review-all", status_code=202)
def ai_review_all(bg: BackgroundTasks):
    _require_ai()
    return _accept(bg, "review-all", jobs.review_all)


@api.post("/ai/fix-all", status_code=202)
def ai_fix_all(bg: BackgroundTasks):
    _require_ai()
    return _accept(bg, "fix-all", jobs.ai_fix_all)


@api.post("/ai/deep-scan", status_code=202)
def ai_deep_scan(bg: BackgroundTasks):
    _require_ai()
    return _accept(bg, "deep-scan", jobs.deep_scan)


@api.get("/patches")
def patches():
    """Every applied fix as one unified diff (original source against the patched copy), ready for `git apply`."""
    return PlainTextResponse(db.combined_diff(), media_type="text/x-diff")


@api.post("/run-all", status_code=202)
def run_all(bg: BackgroundTasks):
    return _accept(bg, "run-all", jobs.run_all)


@api.post("/reset", status_code=202)
def reset(bg: BackgroundTasks):
    return _accept(bg, "reset", jobs.reset)


app.include_router(api)

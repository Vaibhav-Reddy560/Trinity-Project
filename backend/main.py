from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from backend import db, jobs


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.ensure_workspace()
    yield


app = FastAPI(title="PatchProof API", version="1.0.0", lifespan=lifespan)
api = APIRouter(prefix="/api/v1")


def _accept(bg: BackgroundTasks, action: str, job: Callable[..., None], vuln_id: str | None = None) -> JSONResponse:
    if not jobs.try_begin(action):
        raise HTTPException(409, f"Another action ({jobs.status()['action']}) is still running. Wait for it to finish.")
    bg.add_task(jobs.run, job, *([vuln_id] if vuln_id else []))
    body = {"accepted": True, "action": action}
    if vuln_id:
        body["vuln_id"] = vuln_id
    return JSONResponse(body, status_code=202)


def _vuln_or_404(vuln_id: str) -> dict:
    v = db.get_vuln(vuln_id)
    if v is None:
        raise HTTPException(404, f"Finding {vuln_id} does not exist. Run a scan to refresh the list.")
    return v


@app.get("/")
def root():
    return {"status": "PatchProof API Online"}


@api.get("/health")
def health():
    return {"status": "ok", **jobs.status()}


@api.get("/vulns")
def list_vulns():
    return {"vulns": db.list_vulns()}


@api.get("/vulns/{vuln_id}")
def get_vuln(vuln_id: str):
    return _vuln_or_404(vuln_id)


@api.post("/scan", status_code=202)
def scan(bg: BackgroundTasks):
    return _accept(bg, "scan", jobs.scan)


@api.post("/poc/{vuln_id}", status_code=202)
def poc(vuln_id: str, bg: BackgroundTasks):
    v = _vuln_or_404(vuln_id)
    if not v["patchable"]:
        raise HTTPException(409, "Report-only findings have no exploit case.")
    return _accept(bg, "poc", jobs.poc, vuln_id)


@api.post("/patch/{vuln_id}", status_code=202)
def patch(vuln_id: str, bg: BackgroundTasks):
    v = _vuln_or_404(vuln_id)
    if not v["patchable"]:
        raise HTTPException(409, "Auto-patching is not available for this finding type.")
    if v["status"] in ("PATCHED", "VERIFIED") or (v["status"] == "FAILED" and v["diff"]):
        raise HTTPException(409, "This finding is already patched. Reset the workspace to patch it again.")
    if v["poc_status"] != "EXPLOITABLE":
        raise HTTPException(409, "Run the exploit first. Only proven weaknesses can be patched.")
    return _accept(bg, "patch", jobs.patch, vuln_id)


@api.post("/verify/{vuln_id}", status_code=202)
def verify(vuln_id: str, bg: BackgroundTasks):
    v = _vuln_or_404(vuln_id)
    if v["status"] != "PATCHED":
        raise HTTPException(409, "Apply the patch before verifying.")
    return _accept(bg, "verify", jobs.verify, vuln_id)


@api.post("/run-all", status_code=202)
def run_all(bg: BackgroundTasks):
    return _accept(bg, "run-all", jobs.run_all)


@api.post("/reset", status_code=202)
def reset(bg: BackgroundTasks):
    return _accept(bg, "reset", jobs.reset)


app.include_router(api)

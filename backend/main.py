from fastapi import APIRouter, FastAPI
from tinydb import TinyDB  # noqa: F401  (storage layer lives in backend/db.py)

app = FastAPI(title="PatchProof API", version="0.1.0")
api = APIRouter(prefix="/api/v1")


@app.get("/")
def root():
    return {"status": "PatchProof API Online"}


@api.get("/health")
def health():
    return {"status": "ok"}


app.include_router(api)

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_root_online():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"status": "PatchProof API Online"}


def test_health():
    assert client.get("/api/v1/health").json() == {"status": "ok"}

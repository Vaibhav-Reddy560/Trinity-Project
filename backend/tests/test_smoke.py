import pytest
from fastapi.testclient import TestClient

from backend import db
from backend.main import app


@pytest.fixture
def client(tmp_path):
    db.configure(tmp_path)
    with TestClient(app) as c:
        yield c


def test_root_online(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"status": "PatchProof API Online"}


def test_health_reports_idle(client):
    body = client.get("/api/v1/health").json()
    assert {k: body[k] for k in ("status", "busy", "action")} == {"status": "ok", "busy": False, "action": None}
    assert body["ai"]["enabled"] is False and body["ai"]["model"] == "claude-opus-5-5"

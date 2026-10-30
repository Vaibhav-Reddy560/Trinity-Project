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
    assert client.get("/api/v1/health").json() == {"status": "ok", "busy": False, "action": None}

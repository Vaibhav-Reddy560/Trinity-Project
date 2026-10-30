import pytest
from fastapi.testclient import TestClient

from backend import db
from backend.main import app

API = "/api/v1"
SCHEMA_KEYS = {
    "id", "file_path", "line_number", "end_line", "severity", "type", "cwe", "title", "severity_rationale",
    "status", "patchable", "original_code", "patched_code", "diff", "patch_rationale", "poc_status",
    "regression_status", "poc_log", "verification_log", "created_at", "updated_at",
}


@pytest.fixture
def client(tmp_path):
    db.configure(tmp_path)
    with TestClient(app) as c:
        yield c


def vulns(client) -> list[dict]:
    return client.get(f"{API}/vulns").json()["vulns"]


def by_type(client, vtype: str, file_path: str = "ai_agent_deepseek.py") -> dict:
    return next(v for v in vulns(client) if v["type"] == vtype and v["file_path"] == file_path)


def test_scan_populates_findings_in_contract_shape(client):
    assert vulns(client) == []
    r = client.post(f"{API}/scan")
    assert r.status_code == 202 and r.json() == {"accepted": True, "action": "scan"}

    found = vulns(client)
    assert len(found) == 7
    assert all(set(v) == SCHEMA_KEYS for v in found)
    assert found[0]["type"] == "AI_PROMPT_INJECTION" and found[0]["severity"] == "CRITICAL"
    assert all(v["status"] == "OPEN" and v["poc_status"] == "NOT_RUN" for v in found)
    assert client.get(f"{API}/vulns/{found[0]['id']}").json() == found[0]


def test_unknown_finding_is_404(client):
    assert client.get(f"{API}/vulns/vuln_nope").status_code == 404
    for action in ("poc", "patch", "verify"):
        assert client.post(f"{API}/{action}/vuln_nope").status_code == 404


def test_full_pipeline_for_one_finding(client):
    client.post(f"{API}/scan")
    vid = by_type(client, "AI_BROKEN_AUTH")["id"]

    assert client.post(f"{API}/patch/{vid}").status_code == 409
    assert client.post(f"{API}/verify/{vid}").status_code == 409

    r = client.post(f"{API}/poc/{vid}")
    assert r.status_code == 202 and r.json() == {"accepted": True, "action": "poc", "vuln_id": vid}
    v = client.get(f"{API}/vulns/{vid}").json()
    assert v["poc_status"] == "EXPLOITABLE"
    assert any(line["msg"].startswith("Bob's account 4001000022 shown to alice") for line in v["poc_log"])

    assert client.post(f"{API}/patch/{vid}").status_code == 202
    v = client.get(f"{API}/vulns/{vid}").json()
    assert v["status"] == "PATCHED" and v["diff"].startswith("--- a/ai_agent_deepseek.py")
    assert client.post(f"{API}/patch/{vid}").status_code == 409

    assert client.post(f"{API}/verify/{vid}").status_code == 202
    v = client.get(f"{API}/vulns/{vid}").json()
    assert (v["status"], v["poc_status"], v["regression_status"]) == ("VERIFIED", "BLOCKED", "PASSED")


def test_replaying_exploit_after_fix_keeps_original_evidence(client):
    client.post(f"{API}/scan")
    vid = by_type(client, "AI_PROMPT_INJECTION")["id"]
    client.post(f"{API}/poc/{vid}")
    before = client.get(f"{API}/vulns/{vid}").json()["poc_log"]
    client.post(f"{API}/patch/{vid}")
    client.post(f"{API}/verify/{vid}")

    assert client.post(f"{API}/poc/{vid}").status_code == 202
    v = client.get(f"{API}/vulns/{vid}").json()
    assert v["poc_log"] == before
    assert v["poc_status"] == "BLOCKED" and v["status"] == "VERIFIED"
    assert any(line["msg"] == "Exploit replayed against the patched copy" for line in v["verification_log"])


def test_report_only_findings_reject_pipeline_actions(client):
    client.post(f"{API}/scan")
    vid = by_type(client, "AI_INFO_DISCLOSURE")["id"]
    assert client.post(f"{API}/poc/{vid}").status_code == 409
    assert client.post(f"{API}/patch/{vid}").status_code == 409


def test_run_all_verifies_every_patchable_finding(client):
    assert client.post(f"{API}/run-all").status_code == 202
    found = vulns(client)
    patchable = [v for v in found if v["patchable"]]
    assert len(patchable) == 2
    assert all(v["status"] == "VERIFIED" for v in patchable)
    assert all(v["status"] == "OPEN" for v in found if not v["patchable"])


def test_rescan_keeps_state_and_does_not_duplicate(client):
    client.post(f"{API}/run-all")
    client.post(f"{API}/scan")
    found = vulns(client)
    assert len(found) == 7
    assert by_type(client, "AI_PROMPT_INJECTION")["status"] == "VERIFIED"


def test_reset_clears_findings_and_restores_code(client):
    client.post(f"{API}/run-all")
    assert "PATCHPROOF_INJECTION_PATTERN" in (db.workspace_dir() / "ai_agent_deepseek.py").read_text()
    assert client.post(f"{API}/reset").status_code == 202
    assert vulns(client) == []
    restored = (db.workspace_dir() / "ai_agent_deepseek.py").read_text()
    assert restored == (db.PRISTINE_DIR / "ai_agent_deepseek.py").read_text()


def test_only_one_action_runs_at_a_time(client):
    from backend import jobs

    assert jobs.try_begin("scan")
    try:
        r = client.post(f"{API}/scan")
        assert r.status_code == 409
        assert client.get(f"{API}/health").json() == {"status": "ok", "busy": True, "action": "scan"}
    finally:
        jobs.run(lambda: None)

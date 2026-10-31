from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import db, jobs
from backend.main import app

API = "/api/v1"


@pytest.fixture
def client(tmp_path):
    db.configure(tmp_path / "data")
    with TestClient(app) as c:
        yield c


def vulns(client) -> list[dict]:
    return client.get(f"{API}/vulns").json()["vulns"]


def test_default_target_is_vuln_bank_with_its_cases(client):
    body = client.get(f"{API}/targets").json()
    assert body["active"]["id"] == "vuln-bank" and body["active"]["provable"]
    assert len(body["active"]["cases"]) == 8
    assert [p["id"] for p in body["profiles"]] == ["vuln-bank", "notes-api"]
    assert body["error"] is None


def test_switch_to_notes_api_and_fix_everything(client):
    r = client.post(f"{API}/targets/select", json={"id": "notes-api"})
    assert r.status_code == 202 and r.json() == {"accepted": True, "action": "select"}
    assert client.get(f"{API}/targets").json()["active"]["id"] == "notes-api"
    found = {v["type"]: v for v in vulns(client)}
    assert set(found) == {"SQL_INJECTION", "PATH_TRAVERSAL", "HARDCODED_CREDENTIALS"}

    client.post(f"{API}/run-all")
    after = {v["type"]: v for v in vulns(client)}
    assert all(v["status"] == "VERIFIED" for v in after.values()), {t: v["verification_log"][-1:] for t, v in after.items()}
    assert after["SQL_INJECTION"]["poc_status"] == "BLOCKED", "provable findings are exploited first, then re-run blocked"
    assert after["HARDCODED_CREDENTIALS"]["poc_status"] == "NOT_RUN", "no exploit case: proven by static checks and regressions"


def test_switching_back_restores_the_other_targets_code(client):
    client.post(f"{API}/targets/select", json={"id": "notes-api"})
    assert (db.workspace_dir() / "notes_app.py").is_file()
    client.post(f"{API}/targets/select", json={"id": "vuln-bank"})
    assert (db.workspace_dir() / "ai_agent_deepseek.py").is_file()
    assert not (db.workspace_dir() / "notes_app.py").exists()
    assert len(vulns(client)) == 8


def test_scan_a_local_project_without_running_or_changing_it(client, tmp_path: Path):
    project = tmp_path / "my-app"
    project.mkdir()
    source = "import os\nimport sqlite3\n\ndef find(conn, name):\n    return conn.execute(f\"SELECT * FROM u WHERE n = '{name}'\")\n"
    (project / "app.py").write_text(source)

    assert client.post(f"{API}/targets/select", json={"path": str(project)}).status_code == 202
    active = client.get(f"{API}/targets").json()["active"]
    assert active["kind"] == "project" and active["name"] == "my-app" and not active["provable"]
    assert active["stats"]["files_scanned"] == 1

    [finding] = vulns(client)
    assert finding["type"] == "SQL_INJECTION" and finding["fixer"] == "rule" and not finding["provable"]
    r = client.post(f"{API}/poc/{finding['id']}")
    assert r.status_code == 409 and "never run" in r.json()["detail"]

    client.post(f"{API}/run-all")  # fixes the copy, proven by static checks
    [fixed] = vulns(client)
    assert fixed["status"] == "VERIFIED" and fixed["poc_status"] == "NOT_RUN", fixed["verification_log"]
    assert {c["id"] for c in fixed["checks"]} == {"compiles", "fixed", "no_new", "scoped", "signature"}
    diff = client.get(f"{API}/patches").text
    assert diff.startswith("--- a/app.py\n+++ b/app.py\n") and "(name,)" in diff
    assert (project / "app.py").read_text() == source, "your project folder is never modified"
    client.post(f"{API}/reset")
    assert vulns(client) == [] and (project / "app.py").read_text() == source


@pytest.mark.parametrize("body, status", [
    ({}, 422),
    ({"id": "vuln-bank", "path": "/tmp"}, 422),
    ({"id": "nope"}, 404),
    ({"path": "relative/folder"}, 422),
    ({"path": "/definitely/not/a/folder"}, 422),
    ({"git_url": "git@github.com:owner/repo.git"}, 422),
    ({"git_url": "file:///etc"}, 422),
    ({"git_url": "https://github.com/owner/repo; rm -rf /"}, 422),
])
def test_invalid_selections_are_rejected_up_front(client, body, status):
    r = client.post(f"{API}/targets/select", json=body)
    assert r.status_code == status
    assert client.get(f"{API}/targets").json()["active"]["id"] == "vuln-bank"


def test_failed_clone_keeps_the_current_target(client, monkeypatch):
    def boom(url):
        raise RuntimeError(f"Could not clone {url}: repository not found")

    monkeypatch.setattr(jobs, "_clone", boom)
    r = client.post(f"{API}/targets/select", json={"git_url": "https://github.com/owner/missing"})
    assert r.status_code == 202
    body = client.get(f"{API}/targets").json()
    assert body["active"]["id"] == "vuln-bank"
    assert "repository not found" in body["error"]["message"]


def test_notes_api_fixes_a_finding_with_no_exploit_case(client):
    client.post(f"{API}/targets/select", json={"id": "notes-api"})
    secret = next(v for v in vulns(client) if v["type"] == "HARDCODED_CREDENTIALS")
    assert secret["fixer"] == "rule" and not secret["provable"]
    assert client.post(f"{API}/poc/{secret['id']}").status_code == 409
    assert client.post(f"{API}/patch/{secret['id']}").status_code == 202, "no exploit to run first"
    assert client.post(f"{API}/verify/{secret['id']}").status_code == 202
    done = next(v for v in vulns(client) if v["id"] == secret["id"])
    assert done["status"] == "VERIFIED" and done["fix_source"] == "rule" and done["regression_status"] == "PASSED"
    assert next(c for c in done["checks"] if c["id"] == "regression")["passed"]
    assert done["poc_log"][0]["msg"].startswith("Baseline"), "with no exploit to record, 'before' is the regression baseline"


def test_ai_actions_need_a_key(client, monkeypatch):
    for var in ("PATCHPROOF_AI", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    assert client.get(f"{API}/health").json()["ai"]["enabled"] is False
    client.post(f"{API}/scan")
    info = next(v for v in vulns(client) if v["type"] == "AI_INFO_DISCLOSURE")
    assert not info["patchable"]
    for path in ("ai/deep-scan", "ai/review-all", f"ai/review/{info['id']}", f"patch/{info['id']}"):
        r = client.post(f"{API}/{path}")
        assert r.status_code == 409 and "ANTHROPIC_API_KEY" in r.json()["detail"], path


EXEC_APP = 'def run(code):\n    scope = {}\n    exec(code, scope)\n    return scope.get("result")\n'


def test_ai_review_deep_scan_and_fix_on_a_local_project(client, tmp_path: Path):
    from engine import ai
    from engine.tests.test_fixes import IDOR_APP, Script

    def idor_answer(text: str) -> dict:
        if "note = NOTES[note_id]" not in text:
            return {"findings": []}
        return {"findings": [{"type": "BROKEN_ACCESS_CONTROL", "severity": "HIGH", "cwe": "CWE-639", "title": "Any user reads any note",
                              "rationale": "No ownership check.", "line_start": 7, "line_end": 7, "evidence_line": "note = NOTES[note_id]"}]}

    project = tmp_path / "my-app"
    project.mkdir()
    (project / "runner.py").write_text(EXEC_APP)
    (project / "notes.py").write_text(IDOR_APP)
    script = Script(
        review=[{"verdict": "confirmed", "confidence": "high", "reasoning": "code comes from the caller",
                 "attack_scenario": "a caller sends code", "fix_hint": "parse literals only"}],
        deep_scan=[idor_answer, idor_answer],  # files are scanned in parallel, so answer by content, not by order
        fix=[{"replacement": "def run(code):\n    return ast.literal_eval(code)\n", "new_imports": ["import ast"],
              "rationale": "Parses literals instead of running code.", "behaviour_change": "Only literals are accepted."}],
    )
    ai.set_responder(script)
    assert client.get(f"{API}/health").json()["ai"]["enabled"] is True

    client.post(f"{API}/targets/select", json={"path": str(project)})
    [exec_finding] = vulns(client)
    assert exec_finding["type"] == "CODE_INJECTION" and exec_finding["fixer"] == "ai"

    assert client.post(f"{API}/ai/review/{exec_finding['id']}").status_code == 202
    assert client.get(f"{API}/vulns/{exec_finding['id']}").json()["ai_review"]["verdict"] == "confirmed"

    assert client.post(f"{API}/ai/deep-scan").status_code == 202
    found = [v for v in vulns(client) if v["detected_by"] == "ai"]
    assert [(v["type"], v["file_path"], v["line_number"]) for v in found] == [("BROKEN_ACCESS_CONTROL", "notes.py", 7)]
    assert client.get(f"{API}/targets").json()["active"]["deep_scan"]["added"] == 1

    assert client.post(f"{API}/patch/{exec_finding['id']}").status_code == 202
    assert client.post(f"{API}/verify/{exec_finding['id']}").status_code == 202
    fixed = client.get(f"{API}/vulns/{exec_finding['id']}").json()
    assert fixed["status"] == "VERIFIED" and fixed["fix_source"] == "ai", fixed["verification_log"]
    assert fixed["behaviour_change"] == "Only literals are accepted."
    assert (project / "runner.py").read_text() == EXEC_APP, "your project folder is never modified"


def test_ai_fix_all_fixes_every_open_finding_and_proves_each(client, tmp_path: Path):
    from engine import ai
    from engine.tests.test_fixes import Script

    project = tmp_path / "mixed"
    project.mkdir()
    (project / "runner.py").write_text(EXEC_APP)
    (project / "db.py").write_text("import sqlite3\ndef find(c, n):\n    return c.execute(f\"SELECT * FROM t WHERE n = '{n}'\")\n")
    ai.set_responder(Script(fix=[{"replacement": "def run(code):\n    return ast.literal_eval(code)\n", "new_imports": ["import ast"],
                                  "rationale": "Literals only.", "behaviour_change": "None"}]))
    client.post(f"{API}/targets/select", json={"path": str(project)})
    assert client.post(f"{API}/ai/fix-all").status_code == 202
    done = {v["type"]: v for v in vulns(client)}
    assert {t: (v["status"], v["fix_source"]) for t, v in done.items()} == {
        "CODE_INJECTION": ("VERIFIED", "ai"), "SQL_INJECTION": ("VERIFIED", "rule")}, "rules first, the AI model for the rest"

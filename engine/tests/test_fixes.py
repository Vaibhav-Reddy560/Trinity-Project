"""Rule-based fixes, the proof checks every fix must pass, and the AI path (with a scripted model)."""

import json
from pathlib import Path

import pytest

from engine import ai, apply_patch
from engine.checks import static_checks
from engine.patcher import _style, rule_patch
from engine.scanner import scan_repository
from engine.targets import project_profile

PACKS = ["ai", "generic"]


def finding(tmp_path: Path, source: str, vtype: str) -> dict:
    (tmp_path / "app.py").write_text(source)
    found = [f for f in scan_repository(str(tmp_path), project_profile(tmp_path, "t", "local"), ai_fixes=False) if f["type"] == vtype]
    assert found, f"{vtype} was not flagged"
    return found[0]


# (type, vulnerable source, text the rule-based fix must produce)
FIXES = [
    ("SQL_INJECTION", 'import sqlite3\ndef get(cursor, params):\n    cursor.execute("SELECT id, name FROM users WHERE id=" + params["id"])\n',
     'cursor.execute("SELECT id, name FROM users WHERE id=?", (params["id"],))'),
    ("SQL_INJECTION", 'import sqlite3\ndef login(cursor, params):\n    return cursor.execute("SELECT * FROM users WHERE username=\'" + params.get("username", "")'
                      ' + "\' AND password=\'" + params.get("password", "") + "\'").fetchone()\n',
     'cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (params.get("username", ""), params.get("password", ""))).fetchone()'),
    ("SQL_INJECTION", 'import sqlite3, time\ndef comment(cursor, params):\n    cursor.execute("INSERT INTO comments VALUES(NULL, \'%s\', \'%s\')" % (params["comment"], time.ctime()))\n',
     'cursor.execute("INSERT INTO comments VALUES(NULL, ?, ?)", (params["comment"], time.ctime()))'),
    ("SQL_INJECTION", 'import psycopg2\ndef find(cur, name):\n    cur.execute("SELECT * FROM users WHERE name = \'{}\' AND note LIKE \'%{}%\'".format(name, name))\n',
     'cur.execute("SELECT * FROM users WHERE name = %s AND note LIKE %s", (name, f"%{name}%"))'),
    ("SQL_INJECTION", 'from database import execute_query\ndef register(username, password):\n    execute_query(\n'
                      '        f"INSERT INTO users (username, password) VALUES (\'{username}\', \'{password}\')",\n        fetch=False\n    )\n',
     '"INSERT INTO users (username, password) VALUES (?, ?)", (username, password),\n        fetch=False'),
    ("COMMAND_INJECTION", 'import os\ndef ping(host):\n    return os.system(f"ping -c 1 {host}")\n',
     'subprocess.call(["ping", "-c", "1", str(host)])'),
    ("COMMAND_INJECTION", 'import subprocess\ndef lookup(params):\n    return subprocess.run("nslookup " + params["domain"], shell=True, stdout=subprocess.PIPE, text=True).stdout\n',
     'subprocess.run(["nslookup", params["domain"]], stdout=subprocess.PIPE, text=True).stdout'),
    ("COMMAND_INJECTION", 'import os\ndef listing(path):\n    return os.popen("ls -la " + path).read()\n',
     'subprocess.run(["ls", "-la", path], capture_output=True, text=True).stdout'),
    ("PATH_TRAVERSAL", 'import os\ndef read(name):\n    return open(os.path.join("/srv/files", name)).read()\n',
     'open(_patchproof_safe_join("/srv/files", name))'),
    ("PATH_TRAVERSAL", 'def read(name):\n    with open(f"/srv/files/{name}") as f:\n        return f.read()\n',
     'open(_patchproof_safe_join("/srv/files/", str(name)))'),
    ("PATH_TRAVERSAL", 'BASE = "/srv/files"\ndef read(name):\n    return open(BASE + "/" + name).read()\n',
     "open(_patchproof_safe_join(BASE, name))"),
    ("CODE_INJECTION", "def calc(expr):\n    return eval(expr)\n", "return ast.literal_eval(expr)"),
    ("INSECURE_DESERIALIZATION", "import yaml\ndef load(text):\n    return yaml.load(text, Loader=yaml.Loader)\n", "return yaml.safe_load(text)"),
    ("SSRF", 'import requests\nfrom flask import request\ndef fetch():\n    return requests.get(request.args["url"], timeout=5).text\n',
     'requests.get(_patchproof_safe_url(request.args["url"]), timeout=5, allow_redirects=False)'),
    ("INSECURE_JWT", 'import jwt\nSIGNING = "k"\ndef issue(user):\n    return jwt.encode({"sub": user}, SIGNING, algorithm="HS256")\n'
                     'def read(token):\n    return jwt.decode(token, options={"verify_signature": False})\n',
     'jwt.decode(token, SIGNING, algorithms=["HS256"])'),
    ("HARDCODED_CREDENTIALS", "DB_PASSWORD = 'pr0d-s3cret-9921'\n", 'DB_PASSWORD = os.environ["DB_PASSWORD"]'),
    ("HARDCODED_CREDENTIALS", 'from flask import Flask\napp = Flask(__name__)\napp.secret_key = "s3cr3t-k3y-123"\n', 'app.secret_key = os.environ["SECRET_KEY"]'),
    ("HARDCODED_CREDENTIALS", 'import os\nPASSWORD = os.getenv("DB_PASSWORD", "postgres1")\n', 'PASSWORD = os.environ["DB_PASSWORD"]'),
    ("HARDCODED_CREDENTIALS", 'CONFIG = {"api_key": "AKIA1234567890XYZ"}\n', '{"api_key": os.environ["API_KEY"]}'),
    ("TLS_VERIFY_DISABLED", 'import requests\ndef f():\n    return requests.get("https://x.example", verify=False)\n', 'requests.get("https://x.example")'),
    ("DEBUG_MODE", "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n", 'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")'),
]


@pytest.mark.parametrize("vtype, source, expected", FIXES, ids=[f"{t}-{i}" for i, (t, _, _) in enumerate(FIXES)])
def test_rule_fix_rewrites_the_site_and_passes_every_check(tmp_path, vtype, source, expected):
    vuln = finding(tmp_path, source, vtype)
    assert vuln["fixer"] == "rule"
    result = rule_patch(source, vuln)
    assert isinstance(result, tuple), result
    after, rationale = result
    assert expected in after and rationale
    checks = static_checks(source, after, vuln, PACKS)
    assert all(c["passed"] is not False for c in checks), checks
    assert next(c for c in checks if c["id"] == "fixed")["passed"] is True


def test_fixes_add_the_imports_and_helpers_they_use(tmp_path):
    src = 'import os\ndef ping(host):\n    return os.system(f"ping -c 1 {host}")\n'
    after, _ = rule_patch(src, finding(tmp_path, src, "COMMAND_INJECTION"))
    assert after.startswith("import os\nimport subprocess\n")
    src = 'def read(name):\n    with open(f"/srv/files/{name}") as f:\n        return f.read()\n'
    after, _ = rule_patch(src, finding(tmp_path, src, "PATH_TRAVERSAL"))
    assert "import os\n" in after and "def _patchproof_safe_join(base, *parts):" in after


def test_unsafe_shapes_are_left_for_a_human_or_the_ai(tmp_path):
    shell_syntax = 'import os\ndef run(name):\n    os.system("cat " + name + " | grep x")\n'
    dynamic_columns = 'import sqlite3\ndef upd(c, cols, i):\n    c.execute(f"UPDATE t SET {cols} WHERE id = {i}", ())\n'
    no_key = 'import jwt\ndef read(token):\n    return jwt.decode(token, options={"verify_signature": False})\n'
    for src, vtype in [(shell_syntax, "COMMAND_INJECTION"), (no_key, "INSECURE_JWT")]:
        assert finding(tmp_path, src, vtype)["fixer"] is None
    (tmp_path / "app.py").write_text(dynamic_columns)
    assert not [f for f in scan_repository(str(tmp_path), project_profile(tmp_path, "t", "x"), ai_fixes=False) if f["fixer"] == "rule"]


def test_placeholder_style_comes_from_the_project_driver(tmp_path):
    (tmp_path / "database.py").write_text("import psycopg2\n")
    assert _style("from database import execute_query\n", tmp_path) == "%s"
    assert _style("import sqlite3\n", tmp_path) == "?"
    assert _style("x = 1\n") == "?"


# ---------- the checks reject bad fixes ----------

BASE = (
    "import os\nimport sqlite3\n\n\ndef helper(x):\n    return x\n\n\n"
    "def find(conn, name):\n    return conn.execute(f\"SELECT * FROM u WHERE n = '{name}'\")\n"
)
GOOD = 'def find(conn, name):\n    return conn.execute("SELECT * FROM u WHERE n = ?", (name,))\n'


def _swap(new_find: str, helper: str = "def helper(x):\n    return x\n") -> str:
    return f"import os\nimport sqlite3\n\n\n{helper}\n\n{new_find}"


@pytest.mark.parametrize("after, failing", [
    (_swap(GOOD), set()),
    (BASE.replace("return conn", "# looked at it\n    return conn"), {"fixed"}),
    (_swap(GOOD, "def helper(x):\n    return x * 2\n"), {"scoped"}),
    (_swap(GOOD.replace("(conn, name)", "(conn, name, strict=True)")), {"signature"}),
    (_swap(GOOD.replace("    return", "    os.system(name)\n    return")), {"no_new"}),
    (_swap("def find(conn, name:\n    pass\n"), {"compiles"}),
])
def test_checks_catch_each_kind_of_bad_fix(tmp_path, after, failing):
    vuln = finding(tmp_path, BASE, "SQL_INJECTION")
    checks = static_checks(BASE, after, vuln, PACKS)
    assert {c["id"] for c in checks if c["passed"] is False} == failing


# ---------- AI ----------

class Script:
    """A scripted stand-in for Claude: answers per task, in order, recording every prompt it was sent."""

    def __init__(self, **answers: list[dict]) -> None:
        self.answers = {k: list(v) for k, v in answers.items()}
        self.prompts: list[tuple[str, str]] = []

    def __call__(self, task: str, text: str, schema: dict) -> dict:
        self.prompts.append((task, text))
        answer = self.answers[task].pop(0)
        return answer(text) if callable(answer) else answer  # callables answer per prompt (parallel deep scans)


EXEC_APP = 'def run(code):\n    scope = {}\n    exec(code, scope)\n    return scope.get("result")\n'


def test_ai_fix_is_kept_only_after_it_passes_the_checks(tmp_path):
    vuln = finding(tmp_path, EXEC_APP, "CODE_INJECTION")
    assert vuln["fixer"] is None  # no rule-based fix for exec()
    script = Script(fix=[
        {"replacement": "def run(code):\n    exec(code.strip())\n", "new_imports": [], "rationale": "x", "behaviour_change": "None"},
        {"replacement": "def run(code):\n    # PatchProof: data only, never code\n    return ast.literal_eval(code)\n",
         "new_imports": ["import ast"], "rationale": "Parses literals instead of running code.", "behaviour_change": "Only literals are accepted."},
    ])
    ai.set_responder(script)
    result = apply_patch(str(tmp_path), {**vuln, "id": "vuln_x"}, project_profile(tmp_path, "t", "local"))
    assert result["success"] and result["fix_source"] == "ai"
    after = (tmp_path / "app.py").read_text()
    assert after.startswith("import ast\n") and "return ast.literal_eval(code)" in after
    assert all(c["passed"] is not False for c in result["checks"])
    log = " | ".join(line["msg"] for line in result["log"])
    assert "Attempt 1 rejected by the checks: Weakness no longer detected" in log and f"Attempt 2 by {ai.model()} passed" in log
    assert "PatchProof's checks rejected it" in script.prompts[1][1], "the second attempt must see why the first failed"


def test_ai_fix_gives_up_after_three_rejected_attempts(tmp_path):
    vuln = finding(tmp_path, EXEC_APP, "CODE_INJECTION")
    bad = {"replacement": "def run(code):\n    exec(code)\n", "new_imports": [], "rationale": "", "behaviour_change": ""}
    ai.set_responder(Script(fix=[bad, bad, bad]))
    result = apply_patch(str(tmp_path), vuln, project_profile(tmp_path, "t", "local"))
    assert not result["success"] and (tmp_path / "app.py").read_text() == EXEC_APP


def test_without_ai_there_is_no_fix_for_rule_less_shapes(tmp_path):
    vuln = finding(tmp_path, EXEC_APP, "CODE_INJECTION")
    result = apply_patch(str(tmp_path), vuln, project_profile(tmp_path, "t", "local"))
    assert not result["success"] and "AI fixes are off" in result["log"][-1]["msg"]


def test_ai_review_is_returned_as_labelled_opinion(tmp_path):
    vuln = finding(tmp_path, EXEC_APP, "CODE_INJECTION")
    ai.set_responder(Script(review=[{"verdict": "confirmed", "confidence": "high", "reasoning": "code comes from the caller",
                                     "attack_scenario": "a caller sends __import__('os')...", "fix_hint": "use ast.literal_eval"}]))
    review = ai.review(EXEC_APP, vuln)
    assert review["verdict"] == "confirmed" and review["model"] == ai.model() and review["reviewed_at"]
    ai.set_responder(Script(review=[{"verdict": "maybe"}]))
    with pytest.raises(ai.AIError):
        ai.review(EXEC_APP, vuln)


IDOR_APP = (
    "from flask import Flask, request\n"            # 1
    "app = Flask(__name__)\n"                       # 2
    "NOTES = {}\n"                                  # 3
    "\n"                                            # 4
    '@app.route("/notes/<int:note_id>")\n'          # 5
    "def get_note(note_id):\n"                      # 6
    "    note = NOTES[note_id]\n"                   # 7
    "    return note\n"                             # 8
)


def test_deep_scan_keeps_only_findings_that_quote_real_code(tmp_path):
    (tmp_path / "app.py").write_text(IDOR_APP)
    item = {"type": "BROKEN_ACCESS_CONTROL", "severity": "HIGH", "cwe": "CWE-639", "title": "Any user reads any note",
            "rationale": "No ownership check.", "line_start": 7, "line_end": 7, "evidence_line": "note = NOTES[note_id]"}
    ai.set_responder(Script(deep_scan=[{"findings": [
        item,
        {**item, "title": "off by three", "line_start": 4, "line_end": 4, "evidence_line": "return note"},
        {**item, "title": "invented", "evidence_line": "db.delete_everything()"},
        {**item, "type": "NOT_A_TYPE"},
    ]}]))
    report = ai.deep_scan(str(tmp_path), project_profile(tmp_path, "t", "local"), [])
    assert report["files"] == 1 and report["dropped"] == 2
    spans = {(f["title"], f["line_number"]) for f in report["findings"]}
    assert spans == {("Any user reads any note", 7), ("off by three", 8)}
    assert all(f["detected_by"] == "ai" and f["fixer"] == "ai" and not f["provable"] for f in report["findings"])


def test_deep_scan_skips_what_the_rules_already_reported(tmp_path):
    (tmp_path / "app.py").write_text(IDOR_APP)
    item = {"type": "BROKEN_ACCESS_CONTROL", "severity": "HIGH", "cwe": "CWE-639", "title": "t", "rationale": "r",
            "line_start": 7, "line_end": 7, "evidence_line": "note = NOTES[note_id]"}
    ai.set_responder(Script(deep_scan=[{"findings": [item]}]))
    known = [{"file_path": "app.py", "type": "BROKEN_ACCESS_CONTROL", "line_number": 6, "end_line": 8, "title": "known"}]
    assert ai.deep_scan(str(tmp_path), project_profile(tmp_path, "t", "local"), known)["findings"] == []


def test_ai_errors_become_readable_messages(tmp_path):
    def boom(task, text, schema):
        raise ai.AIError("Rate limited by the Anthropic API. Wait a minute and try again.")
    (tmp_path / "app.py").write_text(IDOR_APP)
    ai.set_responder(boom)
    report = ai.deep_scan(str(tmp_path), project_profile(tmp_path, "t", "local"), [])
    assert report["errors"] == ["app.py: Rate limited by the Anthropic API. Wait a minute and try again."]


def test_ai_is_off_without_a_key(monkeypatch):
    monkeypatch.delenv("PATCHPROOF_AI", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    status = ai.status()
    assert not status["enabled"] and "ANTHROPIC_API_KEY" in status["reason"] and status["model"] == "claude-opus-5-5"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert ai.enabled()


def test_env_file_loads_without_overriding(tmp_path, monkeypatch):
    monkeypatch.delenv("PATCHPROOF_TEST_A", raising=False)
    monkeypatch.setenv("PATCHPROOF_TEST_B", "kept")
    (tmp_path / ".env").write_text('# comment\nPATCHPROOF_TEST_A="from-file"\nexport PATCHPROOF_TEST_B=ignored\n')
    ai.load_env_file(tmp_path / ".env")
    import os
    assert os.environ["PATCHPROOF_TEST_A"] == "from-file" and os.environ["PATCHPROOF_TEST_B"] == "kept"
    monkeypatch.delenv("PATCHPROOF_TEST_A")


# ---------- precision ----------

def test_sanitised_paths_are_not_flagged(tmp_path):
    src = ("import os\nfrom werkzeug.utils import secure_filename\nUPLOADS = 'uploads'\n"
           "def save(request):\n    name = secure_filename(request.files['f'].filename)\n"
           "    name = f'1_{name}'\n    path = os.path.join(UPLOADS, name)\n    with open(path, 'wb') as f:\n        f.write(b'')\n")
    (tmp_path / "app.py").write_text(src)
    assert not [f for f in scan_repository(str(tmp_path), project_profile(tmp_path, "t", "x"), ai_fixes=False) if f["type"] == "PATH_TRAVERSAL"]


def test_credentials_in_test_files_are_not_reported(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_login.py").write_text("PASSWORD = 'hunter2-hunter2'\n")
    (tmp_path / "settings.py").write_text("PASSWORD = 'hunter2-hunter2'\n")
    found = scan_repository(str(tmp_path), project_profile(tmp_path, "t", "x"), ai_fixes=False)
    assert [f["file_path"] for f in found] == ["settings.py"]


def test_prompt_guard_counts_as_a_fix_for_the_injection_rule():
    from engine.scanner import rule_prompt_injection
    import ast as pyast
    src = ("import re\nP = re.compile('x')\nclass A:\n    def chat(self, user_message):\n"
           "        if P.search(user_message):\n            return 'no'\n"
           "        prompt = f'User: {user_message}'\n        return self._call_api(prompt)\n")
    assert rule_prompt_injection(pyast.parse(src)) is None
    assert rule_prompt_injection(pyast.parse(src.replace("        if P.search(user_message):\n            return 'no'\n", ""))) is not None


def test_ai_findings_round_trip_through_json(tmp_path):
    (tmp_path / "app.py").write_text(IDOR_APP)
    item = {"type": "BROKEN_ACCESS_CONTROL", "severity": "HIGH", "cwe": "bogus", "title": "t", "rationale": "r",
            "line_start": 7, "line_end": 7, "evidence_line": "note = NOTES[note_id]"}
    ai.set_responder(Script(deep_scan=[{"findings": [item]}]))
    [f] = ai.deep_scan(str(tmp_path), project_profile(tmp_path, "t", "local"), [])["findings"]
    assert f["cwe"] == "CWE-639" and json.loads(json.dumps(f)) == f


def test_identical_code_in_two_functions_fixes_the_right_one(tmp_path):
    """vuln-bank has three copies of one forgot-password query; each fix must land in its own function."""
    body = "    return execute_query(f\"SELECT id FROM users WHERE username='{name}'\")\n"
    src = f"from database import execute_query\n\ndef v1(name):\n{body}\n\ndef v2(name):\n{body}"
    (tmp_path / "app.py").write_text(src)
    found = sorted((f for f in scan_repository(str(tmp_path), project_profile(tmp_path, "t", "x"), ai_fixes=False)), key=lambda f: f["line_number"])
    assert len(found) == 2
    after, _ = rule_patch(src, found[1])
    v1, v2 = after.split("def v2")
    assert "{name}" in v1 and "{name}" not in v2, "the fix for v2 must not touch v1"
    assert all(c["passed"] is not False for c in static_checks(src, after, found[1], PACKS))


def test_two_queries_ending_in_the_same_call_are_two_findings(tmp_path):
    src = ("from database import execute_query\n\ndef pick(a, b):\n"
           "    if a:\n        query = f\"SELECT * FROM t WHERE k = '{a}'\"\n        rows = execute_query(query)\n"
           "    if b:\n        query = f\"SELECT * FROM t WHERE id = {b}\"\n        rows = execute_query(query)\n    return rows\n")
    (tmp_path / "app.py").write_text(src)
    found = [f for f in scan_repository(str(tmp_path), project_profile(tmp_path, "t", "x"), ai_fixes=False) if f["type"] == "SQL_INJECTION"]
    assert sorted(f["line_number"] for f in found) == [5, 8]



class FakeHTTP:
    """Stands in for urllib.request.urlopen: one scripted (status, body) per request, recording the URLs asked."""

    def __init__(self, *replies: tuple[int, dict]) -> None:
        self.replies, self.urls = list(replies), []

    def __call__(self, req, timeout=None):
        import io
        import urllib.error
        self.urls.append(req.full_url)
        status, body = self.replies.pop(0)
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, "error", {}, io.BytesIO(json.dumps(body).encode()))

        class Res(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return Res(json.dumps(body).encode())


def _gemini_answer(payload: dict, finish: str = "STOP") -> dict:
    return {"candidates": [{"finishReason": finish, "content": {"parts": [{"text": "thinking...", "thought": True},
                                                                          {"text": json.dumps(payload)}]}}]}


REVIEW = {"verdict": "confirmed", "confidence": "high", "reasoning": "r", "attack_scenario": "a", "fix_hint": "f"}


@pytest.fixture
def gemini(monkeypatch):
    monkeypatch.delenv("PATCHPROOF_AI", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("PATCHPROOF_AI_PROVIDER", "gemini")
    monkeypatch.setattr(ai.time, "sleep", lambda s: None)
    ai._spent_until.clear()
    yield
    ai._spent_until.clear()


def test_gemini_falls_back_past_busy_or_exhausted_models(tmp_path, monkeypatch, gemini):
    fake = FakeHTTP((503, {"error": {"message": "high demand"}}), (429, {"error": {"message": "quota"}}), (200, _gemini_answer(REVIEW)))
    monkeypatch.setattr(ai.urllib.request, "urlopen", fake)
    assert ai.status() == {"provider": "gemini", "model": ai.GEMINI_MODELS[0], "enabled": True, "reason": None}
    review = ai.review(EXEC_APP, finding(tmp_path, EXEC_APP, "CODE_INJECTION"))
    assert review["verdict"] == "confirmed" and review["model"] == ai.GEMINI_MODELS[2], "the answer names the model that replied"
    assert [u.split("/models/")[1].split(":")[0] for u in fake.urls] == ai.GEMINI_MODELS[:3]


def test_gemini_refusals_and_bad_keys_become_readable_errors(tmp_path, monkeypatch, gemini):
    vuln = finding(tmp_path, EXEC_APP, "CODE_INJECTION")
    monkeypatch.setattr(ai.urllib.request, "urlopen", FakeHTTP((200, _gemini_answer(REVIEW, finish="SAFETY"))))
    with pytest.raises(ai.AIError, match="Gemini declined"):
        ai.review(EXEC_APP, vuln)
    monkeypatch.setattr(ai.urllib.request, "urlopen", FakeHTTP((400, {"error": {"message": "API key not valid. Please pass a valid API key."}})))
    with pytest.raises(ai.AIError, match="GEMINI_API_KEY"):
        ai.review(EXEC_APP, vuln)
    busy = FakeHTTP(*[(503, {"error": {}})] * (2 * len(ai.GEMINI_MODELS)))
    monkeypatch.setattr(ai.urllib.request, "urlopen", busy)
    with pytest.raises(ai.AIError, match="Try again in a minute"):
        ai.review(EXEC_APP, vuln)
    assert len(busy.urls) == 2 * len(ai.GEMINI_MODELS), "every model is tried, then once more after a short wait"


def test_gemini_daily_quota_is_remembered_and_explained(tmp_path, monkeypatch, gemini):
    vuln = finding(tmp_path, EXEC_APP, "CODE_INJECTION")
    daily = {"error": {"message": "Quota exceeded.", "details": [
        {"violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}]}, {"retryDelay": "36000s"}]}}
    fake = FakeHTTP(*[(429, daily)] * len(ai.GEMINI_MODELS))
    monkeypatch.setattr(ai.urllib.request, "urlopen", fake)
    with pytest.raises(ai.AIError, match="20 requests per model per day.*reset in about 10 h"):
        ai.review(EXEC_APP, vuln)
    assert len(fake.urls) == len(ai.GEMINI_MODELS), "daily limits don't trigger a pointless retry"
    with pytest.raises(ai.AIError, match="per day"):
        ai.review(EXEC_APP, vuln)
    assert len(fake.urls) == len(ai.GEMINI_MODELS), "spent models are skipped without another request"


@pytest.mark.parametrize("failure", [TimeoutError("timed out"), ConnectionResetError(54, "reset by peer")])
def test_gemini_slow_or_dropped_answers_move_to_the_next_model(tmp_path, monkeypatch, gemini, failure):
    calls = []

    def flaky_then_ok(req, timeout=None):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise failure
        return FakeHTTP((200, _gemini_answer(REVIEW)))(req)

    monkeypatch.setattr(ai.urllib.request, "urlopen", flaky_then_ok)
    review = ai.review(EXEC_APP, finding(tmp_path, EXEC_APP, "CODE_INJECTION"))
    assert review["model"] == ai.GEMINI_MODELS[1]


def test_fixing_the_first_of_two_unreported_sites_is_not_a_new_weakness():
    """Single-site rules report one finding per file; the checks must see the second site as pre-existing."""
    import ast as pyast
    from engine.checks import static_checks
    handler = ("def {name}(self):\n    try:\n        pass\n    except Exception as e:\n"
               "        return {{'error': f'failed: {{str(e)}}', 'system_info': self.info()}}\n")
    src = handler.format(name="first") + "\n" + handler.format(name="second")
    vuln = {"file_path": "a.py", "type": "VERBOSE_ERROR_DISCLOSURE", "detected_by": "rule", "line_number": 4, "end_line": 5,
            "original_code": "    except Exception as e:\n        return {'error': f'failed: {str(e)}', 'system_info': self.info()}"}
    fixed = src.replace("f'failed: {str(e)}', 'system_info': self.info()}", "'Something went wrong'}", 1)
    pyast.parse(fixed)
    checks = {c["id"]: c["passed"] for c in static_checks(src, fixed, vuln, ["ai"])}
    assert checks["fixed"] and checks["no_new"], checks


def test_provider_follows_the_setting_then_the_keys(monkeypatch):
    monkeypatch.delenv("PATCHPROOF_AI", raising=False)
    assert ai.provider() == "anthropic" and not ai.enabled()
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    assert ai.provider() == "gemini" and ai.enabled() and ai.name() == "Gemini"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    assert ai.provider() == "anthropic", "with both keys and no setting, Claude is used"
    monkeypatch.setenv("PATCHPROOF_AI_PROVIDER", "gemini")
    assert ai.provider() == "gemini" and ai.model() == ai.GEMINI_MODELS[0]
    monkeypatch.setenv("PATCHPROOF_AI_MODEL", "gemini-3.5-flash")
    assert ai.model() == "gemini-3.5-flash"


SSRF_HELPERS = (
    "import urllib.request\nimport requests\nfrom flask import request\n"
    "PORT, FETCH = 8080, lambda url: urllib.request.urlopen(urllib.request.Request(url, headers={}))\n\n"
    "def get_json(endpoint, timeout=5):\n    return requests.get(endpoint, timeout=timeout).json()\n\n"
    "def proxy():\n    return FETCH(request.args['u']).read()\n\n"
    "def status():\n    return get_json(request.args['api'])\n\n"
    "def fixed():\n    return get_json('https://status.example.com')\n"
)


def test_ssrf_through_a_helper_is_found_at_the_call_site(tmp_path):
    (tmp_path / "app.py").write_text(SSRF_HELPERS)
    found = sorted((f for f in scan_repository(str(tmp_path), project_profile(tmp_path, "t", "x"), ai_fixes=False) if f["type"] == "SSRF"),
                   key=lambda f: f["line_number"])
    assert [(f["line_number"], f["title"]) for f in found] == [
        (10, "Server fetches a URL taken from the request through FETCH() in proxy()"),
        (13, "Server fetches a URL taken from the request through get_json() in status()"),
    ]
    after, rationale = rule_patch(SSRF_HELPERS, found[0])
    assert "return FETCH(_patchproof_safe_url(request.args['u'])).read()" in after
    assert "also refuse redirects" in rationale, "urlopen follows redirects; the rationale must not claim otherwise"
    assert all(c["passed"] is not False for c in static_checks(SSRF_HELPERS, after, found[0], PACKS))



def test_ai_replacement_keeps_the_original_def_line_and_survives_markdown(tmp_path):
    from engine.patcher import replace_region
    src = ("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef view(name, limit=5):\n"
           "    PROMPT = \"\"\"\nline at column 0\n\"\"\"\n    return eval(name)\n")
    model_said = ("```python\n    @app.route('/x')\n    @login_required\n    def view(name, limit=10, extra=None):\n"
                  "        PROMPT = \"\"\"\nline at column 0\n\"\"\"\n        return ast.literal_eval(name)\n```")
    after = replace_region(src, "view", 4, 9, model_said, ["```python\nimport ast\n```"])
    assert "def view(name, limit=5):" in after, "parameters come from the original, whatever the model wrote"
    assert "@app.route('/x')\n@login_required\ndef view" in after, "added decorators are kept"
    assert "return ast.literal_eval(name)" in after and after.startswith("from flask import Flask\nimport ast\n")
    assert "\nline at column 0\n" in after

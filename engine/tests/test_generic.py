import ast
import shutil
from pathlib import Path

import libcst as cst
import pytest

from engine import apply_patch, run_poc, scan_repository, verify_fix
from engine.generic_rules import GENERIC_RULES, Context
from engine.patcher import parameterize
from engine.targets import REPO_ROOT, load_profile, project_profile, source_root

# Each rule must fire on the vulnerable form and stay quiet on the safe form.
CASES = {
    "SQL_INJECTION": (
        "def f(conn, name):\n    conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        "def f(conn, name):\n    conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
    ),
    "COMMAND_INJECTION": (
        "import os\ndef f(host):\n    os.system(f\"ping -c 1 {host}\")",
        "import subprocess\ndef f(host):\n    subprocess.run([\"ping\", \"-c\", \"1\", host])",
    ),
    "CODE_INJECTION": (
        "def f(expr):\n    return eval(expr)",
        "import ast\ndef f(expr):\n    return ast.literal_eval(expr)",
    ),
    "PATH_TRAVERSAL": (
        "import os\ndef f(name):\n    return open(os.path.join('/srv/files', name)).read()",
        "import os\ndef f(name):\n    return open(os.path.join('/srv/files', os.path.basename(name))).read()",
    ),
    "SSRF": (
        "import requests\nfrom flask import request\ndef f():\n    return requests.get(request.args['url']).text",
        "import requests\ndef f(url):\n    return requests.get('https://api.example.com/status').text",
    ),
    "INSECURE_DESERIALIZATION": (
        "import pickle\ndef f(blob):\n    return pickle.loads(blob)",
        "import json\ndef f(blob):\n    return json.loads(blob)",
    ),
    "INSECURE_JWT": (
        "import jwt\ndef f(t):\n    return jwt.decode(t, options={'verify_signature': False})",
        "import jwt\ndef f(t, key):\n    return jwt.decode(t, key, algorithms=['HS256'])",
    ),
    "HARDCODED_CREDENTIALS": (
        "DB_PASSWORD = 'pr0d-s3cret-9921'",
        "import os\nDB_PASSWORD = os.environ['DB_PASSWORD']\nAPI_KEY = 'changeme'",
    ),
    "TLS_VERIFY_DISABLED": (
        "import requests\ndef f():\n    return requests.get('https://x.example', verify=False)",
        "import requests\ndef f():\n    return requests.get('https://x.example')",
    ),
    "WEAK_CRYPTO": (
        "import hashlib\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()",
        "import hashlib\ndef checksum(data):\n    return hashlib.md5(data).hexdigest()",
    ),
    "DEBUG_MODE": (
        "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)",
        "from flask import Flask\napp = Flask(__name__)\napp.run()",
    ),
}


def _hits(vtype: str, source: str) -> list:
    tree = ast.parse(source)
    rule = next(r for t, _, _, r in GENERIC_RULES if t == vtype)
    return rule(tree, Context(tree))


@pytest.mark.parametrize("vtype", sorted(CASES))
def test_rule_flags_vulnerable_form(vtype):
    assert _hits(vtype, CASES[vtype][0]), f"{vtype} missed the vulnerable form"


@pytest.mark.parametrize("vtype", sorted(CASES))
def test_rule_ignores_safe_form(vtype):
    assert not _hits(vtype, CASES[vtype][1]), f"{vtype} flagged the safe form"


def test_every_generic_rule_has_a_case():
    assert {t for t, *_ in GENERIC_RULES} == set(CASES)


def test_http_server_request_attributes_count_as_input():
    """Plain http.server apps read input from self.path, not a `request` object or function parameters."""
    source = (
        "import http.server, subprocess, urllib.parse\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        path, query = self.path.split('?', 1)\n"
        "        params = dict(urllib.parse.parse_qsl(query))\n"
        "        self.cursor.execute(\"SELECT * FROM t WHERE id=\" + params['id'])\n"
        "        subprocess.run('nslookup ' + params['host'], shell=True)\n"
    )
    assert _hits("SQL_INJECTION", source) and _hits("COMMAND_INJECTION", source)


def _fs(src: str) -> cst.FormattedString:
    return cst.parse_expression(src)  # type: ignore[return-value]


def test_parameterize_quotes_and_like_wildcards():
    sql, params = parameterize(_fs("f\"SELECT * FROM t WHERE a = '{a}' AND b LIKE '%{b}%' AND n = {n}\""), "?")
    assert sql == '"SELECT * FROM t WHERE a = ? AND b LIKE ? AND n = ?"'
    assert params == '(a, f"%{b}%", n)'


def test_parameterize_escapes_percent_for_pyformat_drivers():
    sql, params = parameterize(_fs("f\"SELECT * FROM t WHERE x LIKE 'a%' AND y = '{y}'\""), "%s")
    assert sql == '"SELECT * FROM t WHERE x LIKE \'a%%\' AND y = %s"'
    assert params == "(y,)"


def test_parameterize_refuses_unbalanced_quotes():
    assert parameterize(_fs("f\"SELECT * FROM t WHERE a = '{a}\""), "?") is None


@pytest.fixture
def notes_ws(tmp_path: Path) -> tuple[str, dict]:
    profile = load_profile("notes-api")
    dest = tmp_path / "notes"
    shutil.copytree(source_root(profile), dest)
    return str(dest), profile


def test_notes_api_findings(notes_ws):
    ws, profile = notes_ws
    found = {f["type"]: f for f in scan_repository(ws, profile)}
    assert set(found) == {"SQL_INJECTION", "PATH_TRAVERSAL", "HARDCODED_CREDENTIALS"}
    assert found["SQL_INJECTION"]["provable"] and found["PATH_TRAVERSAL"]["provable"]
    assert not found["HARDCODED_CREDENTIALS"]["provable"] and found["HARDCODED_CREDENTIALS"]["fixer"] == "rule"


def test_notes_api_prove_patch_verify_in_either_order(notes_ws):
    ws, profile = notes_ws
    findings = sorted((f for f in scan_repository(ws, profile) if f["provable"]), key=lambda f: f["type"] != "PATH_TRAVERSAL")
    for vuln in findings:  # path traversal first: its helper shifts the lines the SQL fix must find
        assert run_poc(ws, vuln, profile)["exploitable"]
        patch = apply_patch(ws, vuln, profile)
        assert patch["success"]
        result = verify_fix(ws, {**vuln, "base_code": patch["base_code"], "patched_code": patch["patched_code"]}, profile)
        assert result["security_blocked"] and result["regression_passed"], result["log"]
    remaining = {f["type"] for f in scan_repository(ws, profile)}
    assert remaining == {"HARDCODED_CREDENTIALS"}, "fixed weaknesses should no longer be detected"


def test_notes_api_secret_fix_keeps_every_regression_case_passing(notes_ws):
    """No exploit case exists for the hardcoded token, so the proof is the static checks plus the whole regression suite,
    run with the token supplied by the environment the way a deployment would."""
    ws, profile = notes_ws
    vuln = next(f for f in scan_repository(ws, profile) if f["type"] == "HARDCODED_CREDENTIALS")
    patch = apply_patch(ws, vuln, profile)
    assert patch["success"] and 'ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]' in patch["patched_code"]
    result = verify_fix(ws, {**vuln, "base_code": patch["base_code"], "patched_code": patch["patched_code"]}, profile)
    assert result["security_blocked"] is None and result["regression_passed"] is True, result["log"]
    assert all(c["passed"] is not False for c in result["checks"])


def test_sql_fix_uses_bound_parameters(notes_ws):
    ws, profile = notes_ws
    vuln = next(f for f in scan_repository(ws, profile) if f["type"] == "SQL_INJECTION")
    diff = apply_patch(ws, vuln)["diff"]
    assert '+    sql = "SELECT title, body FROM notes WHERE owner = ? AND title LIKE ?"' in diff
    assert '+    rows = conn.execute(sql, (owner, f"%{query}%")).fetchall()' in diff


def test_project_scan_finds_issues_across_a_whole_repo():
    root = REPO_ROOT / "target_app" / "vuln-bank"
    profile = project_profile(root, "vuln-bank", "local folder")
    stats: dict = {}
    findings = scan_repository(str(root), profile, stats)
    types = {f["type"] for f in findings}
    assert stats["files_scanned"] >= 10 and stats["parse_errors"] == 0
    assert {"SQL_INJECTION", "INSECURE_JWT", "SSRF", "DEBUG_MODE", "HARDCODED_CREDENTIALS"} <= types
    assert not any(f["provable"] for f in findings), "projects have no harness, so nothing is proven by exploit"
    assert sum(f["fixer"] == "rule" for f in findings) >= 40, "most findings get an exact rule-based fix"


def test_project_code_is_never_executed(tmp_path: Path):
    canary = tmp_path / "executed.txt"
    (tmp_path / "evil.py").write_text(
        f"open({str(canary)!r}, 'w').write('ran')\n"
        "import os\ndef f(cmd):\n    os.system(f'echo {cmd}')\n"
    )
    profile = project_profile(tmp_path, "evil", "local folder")
    findings = scan_repository(str(tmp_path), profile)
    assert [f["type"] for f in findings] == ["COMMAND_INJECTION"]
    assert not run_poc(str(tmp_path), findings[0], profile)["exploitable"]
    assert not canary.exists()


def test_project_scan_skips_dependencies_and_bad_files(tmp_path: Path):
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "dep.py").write_text("import os\ndef f(c):\n    os.system(c)\n")
    (tmp_path / "broken.py").write_text("def f(:\n")
    (tmp_path / "ok.py").write_text("x = 1\n")
    stats: dict = {}
    findings = scan_repository(str(tmp_path), project_profile(tmp_path, "p", "local"), stats)
    assert findings == []
    assert stats == {"files_scanned": 1, "files_skipped": 0, "parse_errors": 1}

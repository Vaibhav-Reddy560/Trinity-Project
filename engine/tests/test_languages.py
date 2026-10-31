"""Every language, not just Python: pattern rules, whole-project scans, AI fixes under the text checks, and the deep scan."""

import shutil
from pathlib import Path

import pytest

from engine import ai, apply_patch, verify_fix
from engine.checks import text_checks
from engine.lang_rules import scan_source, statement_span
from engine.patcher import replace_lines
from engine.scanner import scan_repository
from engine.targets import load_profile, project_profile
from engine.tests.test_fixes import Script

# (language, vulnerable line, type it must be flagged as, safe line that must not be)
RULE_CASES = [
    ("javascript", "db.query(`SELECT * FROM u WHERE id = ${req.params.id}`)", "SQL_INJECTION", "db.query('SELECT * FROM u WHERE id = ?', [id])"),
    ("javascript", "exec('ping ' + req.query.host)", "COMMAND_INJECTION", "execFile('ping', [host])"),
    ("javascript", "el.innerHTML = req.query.q", "XSS", "el.textContent = req.query.q"),
    ("javascript", "fs.readFile(path.join(DIR, req.query.f))", "PATH_TRAVERSAL", "fs.readFile(path.join(DIR, path.basename(req.query.f)))"),
    ("javascript", "eval(userInput)", "CODE_INJECTION", "JSON.parse(userInput)"),
    ("javascript", "axios.get(req.query.url)", "SSRF", "axios.get('https://api.example.com')"),
    ("javascript", "res.redirect(req.query.next)", "OPEN_REDIRECT", "res.redirect('/home')"),
    ("javascript", "const password = 'hunter2-prod-pw'", "HARDCODED_CREDENTIALS", "const password = process.env.PASSWORD"),
    ("javascript", "https.request({rejectUnauthorized: false})", "TLS_VERIFY_DISABLED", "https.request({})"),
    ("javascript", "crypto.createHash('md5').update(p)", "WEAK_CRYPTO", "crypto.createHash('sha256').update(p)"),
    ("php", '$r = mysqli_query($c, "SELECT * FROM u WHERE id = " . $_GET["id"]);', "SQL_INJECTION", '$s = $c->prepare("SELECT * FROM u WHERE id = ?");'),
    ("php", 'system("ping " . $_GET["h"]);', "COMMAND_INJECTION", 'system("ls");'),
    ("php", 'echo $_GET["name"];', "XSS", 'echo htmlspecialchars($_GET["name"]);'),
    ("php", 'include($_GET["page"]);', "PATH_TRAVERSAL", 'include("home.php");'),
    ("php", '$o = unserialize($_COOKIE["d"]);', "INSECURE_DESERIALIZATION", '$o = json_decode($_COOKIE["d"]);'),
    ("java", 'stmt.executeQuery("SELECT * FROM u WHERE id=" + id);', "SQL_INJECTION", 'ps = c.prepareStatement("SELECT * FROM u WHERE id=?");'),
    ("java", 'Runtime.getRuntime().exec("ping " + host);', "COMMAND_INJECTION", 'new ProcessBuilder("ping", host);'),
    ("java", 'MessageDigest.getInstance("MD5");', "WEAK_CRYPTO", 'MessageDigest.getInstance("SHA-256");'),
    ("go", 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id))', "SQL_INJECTION", 'db.Query("SELECT * FROM u WHERE id=$1", id)'),
    ("go", "&tls.Config{InsecureSkipVerify: true}", "TLS_VERIFY_DISABLED", "&tls.Config{}"),
    ("ruby", "User.where(\"name = '#{params[:n]}'\")", "SQL_INJECTION", 'User.where("name = ?", params[:n])'),
    ("ruby", "Marshal.load(params[:d])", "INSECURE_DESERIALIZATION", "JSON.parse(params[:d])"),
    ("csharp", 'var c = new SqlCommand("SELECT * FROM u WHERE id=" + id, conn);', "SQL_INJECTION", 'var c = new SqlCommand("SELECT * FROM u WHERE id=@id", conn);'),
]


@pytest.mark.parametrize("lang, vulnerable, vtype, safe", RULE_CASES, ids=[f"{c[0]}-{c[2]}" for c in RULE_CASES])
def test_language_rules_flag_the_vulnerable_form_only(lang, vulnerable, vtype, safe):
    if lang == "php":  # PHP rules apply inside <?php ... ?> only
        vulnerable, safe = f"<?php {vulnerable}", f"<?php {safe}"
    assert vtype in {t for t, *_ in scan_source(vulnerable, lang)}
    assert vtype not in {t for t, *_ in scan_source(safe, lang)}


def test_comments_are_not_findings():
    assert scan_source("// eval(userInput)\n/*\n eval(userInput)\n*/\n", "javascript") == []
    assert scan_source("# system($_GET['x'])\n", "php") == []


def test_false_positives_seen_in_real_repos_stay_fixed():
    """Each line here was flagged wrongly while scanning DVWA (PHP) or NodeGoat (Node.js)."""
    assert scan_source('<?php\n$query = "SELECT * FROM `users` WHERE user = \'$user\'";\n', "php")[0][0] == "SQL_INJECTION", \
        "MySQL backticks are identifiers, not a shell command"
    assert [t for t, *_ in scan_source('<?php\n$file = $_GET["page"];\n', "php")] == [], "an assignment is not a file() call"
    assert [t for t, *_ in scan_source('<?php\nmysqli_query($db, "USE " . $config["db"]) or die("<pre>" . $err);\n', "php")] == []
    assert scan_source('<p>Try phpinfo() and echo $_GET in your own code</p>\n', "php") == [], "HTML prose in a PHP file"
    assert scan_source("router.get(`/${page}`, (req, res) => res.render(page));\n", "javascript") == [], "a route, not SQL"
    assert scan_source('<?php\n$sql = "UPDATE users SET password = \'$pass_new\'";\n', "php")[0][0] == "SQL_INJECTION"
    assert all(t != "HARDCODED_CREDENTIALS" for t, *_ in scan_source("const cfg = { password: `${process.env.PW}` }\n", "javascript"))
    # Ruby on Rails (RailsGoat)
    assert scan_source("params.require(:user).permit(:email, :first_name)\n", "ruby") == [], "Rails allow-listing, not a shell command"
    assert [t for t, *_ in scan_source("params.require(:user).permit!\n", "ruby")] == ["MASS_ASSIGNMENT"]
    assert [t for t, *_ in scan_source('get "forgot_password" => "password_resets#forgot_password"\n', "ruby")] == [], "a route"
    assert [t for t, *_ in scan_source('ACCESS_TOKEN_SALT = "S4828341189aefiasd#ASDF"\n', "ruby")] == ["HARDCODED_CREDENTIALS"]
    assert scan_source('url: <%= "/users/#{current_user.id}.json".inspect.html_safe %>\n', "ruby") == []
    assert scan_source("google.loader.ApiKey = 'notsupplied';\n", "javascript") == [], "a placeholder"


def test_multi_line_template_written_to_inner_html_is_one_finding():
    src = "function show(msg) {\n  toast.innerHTML = `\n    <div class=\"toast\">\n      ${msg}\n    </div>\n  `;\n}\n"
    [(vtype, _, _, hit)] = scan_source(src, "javascript")
    assert vtype == "XSS" and hit.start == 2
    assert statement_span(src.splitlines(), 2, cap=60) == 6
    static = "el.innerHTML = `\n  <p>Loading…</p>\n`;\n"
    assert scan_source(static, "javascript") == [], "a fixed template has nothing dynamic in it"


APP = {
    "server.js": "const express = require('express');\nconst app = express();\napp.get('/u', (req, res) => {\n"
                 "  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n});\n",
    "page.php": '<?php\necho $_GET["q"];\n',
    "Main.java": 'class Main { void f(String id) { stmt.executeQuery("SELECT * FROM t WHERE id=" + id); } }\n',
    "main.go": 'package main\nfunc f() { _ = &tls.Config{InsecureSkipVerify: true} }\n',
    "app.py": "import os\ndef f(host):\n    os.system(f'ping {host}')\n",
    "tests/server.test.js": "eval(userInput)\n",
    "node_modules/lib/index.js": "eval(userInput)\n",
    "dist/app.min.js": "eval(userInput)\n",
}


def write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)


def test_a_mixed_language_project_is_scanned_end_to_end(tmp_path):
    write(tmp_path, APP)
    stats: dict = {}
    found = scan_repository(str(tmp_path), project_profile(tmp_path, "mixed", "local"), stats, ai_fixes=False)
    assert sorted((f["file_path"], f["type"]) for f in found) == [
        ("Main.java", "SQL_INJECTION"), ("app.py", "COMMAND_INJECTION"), ("main.go", "TLS_VERIFY_DISABLED"),
        ("page.php", "XSS"), ("server.js", "SQL_INJECTION"),
    ], "tests, dependencies and minified bundles are skipped"
    assert stats["by_language"] == {"java": 1, "python": 1, "go": 1, "php": 1, "javascript": 2}
    by_file = {f["file_path"]: f for f in found}
    assert by_file["app.py"]["fixer"] == "rule" and by_file["server.js"]["fixer"] is None, "outside Python, fixes come from the AI"
    assert not any(f["provable"] for f in found)


JS = ("const db = require('./db');\n\nfunction user(req) {\n"
      "  return db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n}\n\nmodule.exports = { user };\n")
JS_FIX = "return db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);"


def js_finding(tmp_path: Path) -> dict:
    (tmp_path / "users.js").write_text(JS)
    [f] = scan_repository(str(tmp_path), project_profile(tmp_path, "js", "local"), ai_fixes=True)
    return f


def test_ai_fixes_a_javascript_file_under_the_text_checks(tmp_path):
    vuln = js_finding(tmp_path)
    assert (vuln["type"], vuln["line_number"], vuln["fixer"]) == ("SQL_INJECTION", 4, "ai")
    script = Script(fix=[
        {"replacement": "return db.query(`SELECT * FROM users WHERE id = ${Number(req.query.id)}`);", "new_imports": [],
         "rationale": "", "behaviour_change": ""},
        {"replacement": JS_FIX, "new_imports": [], "rationale": "Bound parameter.", "behaviour_change": "None"},
    ])
    ai.set_responder(script)
    profile = project_profile(tmp_path, "js", "local")
    result = apply_patch(str(tmp_path), vuln, profile)
    assert result["success"] and result["fix_source"] == "ai", result["log"]
    after = (tmp_path / "users.js").read_text()
    assert "  " + JS_FIX in after and after.replace("  " + JS_FIX, "") == JS.replace(JS.splitlines()[3], ""), "only line 4 changed"
    assert {c["id"] for c in result["checks"]} == {"compiles", "fixed", "no_new", "scoped"}
    assert "Attempt 1 rejected by the checks: Weakness no longer detected" in " | ".join(x["msg"] for x in result["log"])
    verified = verify_fix(str(tmp_path), {**vuln, "base_code": result["base_code"], "patched_code": result["patched_code"]}, profile)
    assert all(c["passed"] is not False for c in verified["checks"])


@pytest.mark.parametrize("after, failing", [
    (JS.replace("${req.query.id}`);", "${req.query.id}`;"), {"compiles"}),
    (JS.replace("module.exports = { user };", "module.exports = { user, admin: true };").replace(
        "${req.query.id}`)", "?`, [req.query.id])"), {"scoped"}),
    (JS.replace("${req.query.id}`)", "?`, [req.query.id])") + "\nfunction run(c) { eval(c); }\n", {"scoped", "no_new"}),
])
def test_text_checks_reject_bad_fixes_in_other_languages(tmp_path, after, failing):
    vuln = js_finding(tmp_path)
    checks = text_checks(JS, after, vuln)
    assert {c["id"] for c in checks if c["passed"] is False} == failing, checks


def test_line_replacement_keeps_indentation_and_adds_imports():
    src = "<?php\nfunction f() {\n    echo $_GET['q'];\n}\n"
    after = replace_lines(src, 3, 3, "```php\necho htmlspecialchars($_GET['q'], ENT_QUOTES);\n```", ["use App\\Escaper;"])
    assert after == "<?php\nuse App\\Escaper;\nfunction f() {\n    echo htmlspecialchars($_GET['q'], ENT_QUOTES);\n}\n"


def test_deep_scan_reads_many_files_per_request_and_reports_what_it_could_not_read(tmp_path, monkeypatch):
    write(tmp_path, {"a.js": "app.get('/a', (req, res) => res.send(store[req.params.id]));\n", "b.py": "x = 1\n", "c.go": "package main\n"})
    item = {"file": "a.js", "type": "BROKEN_ACCESS_CONTROL", "severity": "HIGH", "cwe": "CWE-639", "title": "Any record by id",
            "line_start": 1, "line_end": 1, "evidence_line": "app.get('/a', (req, res) => res.send(store[req.params.id]));", "rationale": "r"}
    script = Script(deep_scan=[{"findings": [item, {**item, "file": "nope.js"}]}])
    ai.set_responder(script)
    report = ai.deep_scan(str(tmp_path), project_profile(tmp_path, "p", "local"), [])
    assert report["requests"] == 1 and report["files"] == 3, "three small files share one request"
    assert [(f["file_path"], f["type"]) for f in report["findings"]] == [("a.js", "BROKEN_ACCESS_CONTROL")]
    assert report["dropped"] == 1, "a finding naming a file that wasn't sent is dropped"

    monkeypatch.setattr(ai, "DEEP_SCAN_BATCH_CHARS", 10)
    monkeypatch.setattr(ai, "DEEP_SCAN_MAX_REQUESTS", 2)
    ai.set_responder(Script(deep_scan=[{"findings": []}, {"findings": []}]))
    report = ai.deep_scan(str(tmp_path), project_profile(tmp_path, "p", "local"), [])
    assert report["requests"] == 2 and len(report["unread"]) == 1, "files past the cap are listed, never silently skipped"


def test_only_files_the_test_cases_run_are_provable(tmp_path):
    profile = load_profile("notes-api")
    root = tmp_path / "notes"
    shutil.copytree(Path(__file__).resolve().parents[2] / profile["path"], root)
    (root / "extra.py").write_text("import sqlite3\ndef f(c, n):\n    return c.execute(f\"SELECT * FROM t WHERE n = '{n}'\")\n")
    profile = {**profile, "in_scope": [{"file": "**/*", "lines": None, "role": "all"}]}
    found = {f["file_path"]: f for f in scan_repository(str(root), profile, ai_fixes=False) if f["type"] == "SQL_INJECTION"}
    assert found["notes_app.py"]["provable"] and not found["extra.py"]["provable"]

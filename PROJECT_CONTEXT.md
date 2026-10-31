# PatchProof — Project Context (the "What")

> Single source of truth. If code and this file disagree, this file wins. Contracts in §5-§8 are **frozen**: changing one needs a Lead-approved edit to this file first (see `AGENT_RULES.md`).

## 1. Summary
PatchProof is an automated AppSec remediation engine. It **scans** Python code for security weaknesses, **proves** each finding by running an isolated proof-of-concept where the target allows it, **patches** the code with syntax-preserving LibCST transforms (or, when no rule covers the code, with a fix written by Claude), and **verifies** every fix. Accuracy and verifiable evidence matter more than model complexity: nothing counts as fixed until it passes the proof checks in §4.

It is not tied to one app (§4). Practice targets get the full find → prove → patch → verify loop, with exploits and a regression suite run against the patched code. Any other local folder or public Git repository is never run: findings are fixed in a copy and proven by static checks. AI assistance (§4, "AI assistance") is optional; with no API key every rule-based feature still works. The main demo target is the AI customer-support module of the deliberately vulnerable `vuln-bank` app.

Hackathon track: *Find the Flaw. Prove the Fix.* (AppSec / SAST / secure patching), 24h, 3-person team.

## 2. Tech Stack
| Layer | Choice |
|---|---|
| Engine | Python 3.13, stdlib `ast` (detection), **LibCST** (patching), `subprocess` (isolated PoC runs) |
| Backend | **FastAPI**, FastAPI `BackgroundTasks` (async jobs), **TinyDB** (JSON file DB), uvicorn |
| Frontend | **React + Vite** (TypeScript), **Tailwind CSS v4**, **shadcn/ui** |
| AI (optional) | **Claude** through the Anthropic Python SDK (`anthropic`, default `claude-opus-5-5`), or **Gemini** through its REST API with stdlib `urllib` (default chain: `gemini-2.5-flash`, then newer Flash models when it is busy). Structured JSON outputs. Keys in `.env` (see `.env.example`). |
| Tooling | **uv** (Python deps, one root `pyproject.toml`), npm (frontend), pytest |

Ports: API `:8000`, Vite dev `:5173`. Vite proxies `/api` to `:8000`, so CORS isn't needed.

## 3. Modules (MVP)
1. **Scanner** (`engine/scanner.py`, `engine/generic_rules.py`): `ast` rules in two packs over the target's in-scope files. `ai` covers LLM-agent weaknesses; `generic` covers 11 common classes (§4). Returns `Finding`s.
2. **PoC Runner** (`engine/poc_runner.py`, `engine/harness.py`): runs the target's exploit cases through its harness in a subprocess and decides `EXPLOITABLE` or `BLOCKED` from evidence.
3. **Patcher** (`engine/patcher.py`): LibCST transformers per vuln type, and LibCST region replacement for Claude's fixes. Returns the patched source, a unified diff, a rationale and the proof checks it passed.
4. **Verifier** (`engine/verifier.py`): re-runs the proof checks, then on practice targets the exploit cases (must be **blocked**) and the whole regression suite (must **pass**).
5. **Dashboard** (`frontend/`): cyber-themed console that drives the pipeline and shows the evidence.
6. **Targets** (`engine/targets.py`, `target_app/profiles/*.json`): what is under test: its files, scope, rule packs and harness.
7. **Proof checks** (`engine/checks.py`): the static checks every fix must pass (§4).
8. **AI** (`engine/ai.py`): optional Claude review, deep scan and fixes, each gated by evidence (§4).

## 4. Targets and Scope
A **target** is the code under test. The backend stores the active one (TinyDB `meta` table) and switches it with `POST /api/v1/targets/select`. There are two kinds:

| Kind | Comes from | What PatchProof does |
|---|---|---|
| `profile` (practice target) | `target_app/profiles/<id>.json` | Full loop: scan, exploit, patch, verify. Needs a harness and test cases. |
| `project` | Any absolute local folder, or a public `https://` Git URL (shallow clone into `backend/data/projects/`) | Scans every `.py` file (dependency, virtualenv and build folders skipped). The code is **never imported or run**, so `poc` returns 409. Its Python files are copied to the workspace; fixes go to that copy (your folder is never changed) and are proven by the static checks. `GET /patches` returns them as one diff. |

Practice targets:
- **`vuln-bank`** (default): the AI customer-support module of `Commando-X/vuln-bank`, pinned at `4bb7cd5`, snapshot in `target_app/vuln-bank/` (pristine, never edited). Rule packs `ai` + `generic`. Harness `vuln-bank-agent` (`target_app/harness/run_case.py`).
- **`notes-api`**: a small deliberately vulnerable notes service in `target_app/fixtures/notes-api/`. Rule pack `generic`. Harness `function-call` (`target_app/harness/run_call.py`). It shows the full loop works beyond vuln-bank.

**Read `target_app/SCOPE.md`.** It has the exact in-scope files and lines, the harness designs, the threat model, and the reference exploit/regression cases for both practice targets.

**Profile format** (`target_app/profiles/<id>.json`):
- `id`, `kind: "profile"`, `name`, `summary`, `module`, `source`, `commit`
- `path`: repo-relative source folder
- `in_scope`: `[{file, lines: [start, end] | null, role}]`
- `out_of_scope`: list of strings
- `rule_packs`: any of `"ai"`, `"generic"`
- `harness`: `{kind, cases}` or `null`
- optional `texts`: `"<file>:<TYPE>" -> [title, severity_rationale]` overrides

Per finding:
- `provable`: the profile has security cases for its type, so the fix is also proven by running exploits.
- `fixer`: `"rule"` when a rule-based patcher exists for the type and applies cleanly at that exact site (dry run); else `"ai"` when AI is on; else `null`.
- `patchable`: `fixer` is not null. `GET /vulns` recomputes `fixer` for untouched findings, so switching AI on or off shows up without a rescan.

### Generic rule pack (`engine/generic_rules.py`)
Taint is a per-function heuristic. "Input" means function parameters, names derived from them, and web input (`request`, `input()`, `self.path`/`headers`/`rfile`, `sys.argv`).

| Type | Severity | CWE | Flags | Auto-patch |
|---|---|---|---|---|
| `SQL_INJECTION` | HIGH | CWE-89 | SQL built with f-strings, `+`, `%` or `.format` from input, then executed | Values become bound parameters (`?` or `%s`, from the driver the module or project imports). Quotes are dropped and LIKE wildcards move into the value. Dynamic column lists or calls that already pass params are left for Claude. |
| `COMMAND_INJECTION` | CRITICAL | CWE-78 | `os.system`/`popen`, or `subprocess` with `shell=True`, on input | The command becomes an argument list with no shell. Only when the program is fixed text and the template has no shell syntax. |
| `CODE_INJECTION` | CRITICAL | CWE-95 | `eval`/`exec` on input | `eval(x)` becomes `ast.literal_eval(x)`. `exec` is left for Claude. |
| `PATH_TRAVERSAL` | HIGH | CWE-22 | File opened from a path built from input without a sanitiser (`basename`/`secure_filename`/`safe_join`, followed through assignments) | `os.path.join`, f-string and `+` paths go through `_patchproof_safe_join`, which refuses anything outside the base folder. |
| `SSRF` | HIGH | CWE-918 | HTTP request to a URL from web input, directly or through a module function or lambda that forwards its parameter into one (`FETCH = lambda url: urlopen(url)`) | The URL goes through `_patchproof_safe_url` (http/https only, no private, loopback or link-local addresses), at the request or where it enters the helper. `requests` stops following redirects. |
| `INSECURE_DESERIALIZATION` | HIGH | CWE-502 | `pickle`/`dill`/`marshal` loads, or `yaml.load` without a safe loader, on input | `yaml.load` becomes `yaml.safe_load`. `pickle` is left for Claude. |
| `INSECURE_JWT` | HIGH | CWE-347 | `jwt.decode` with signature verification off, or algorithm `none` allowed | Decoding uses the key and algorithm the module signs with (from its `jwt.encode`). |
| `HARDCODED_CREDENTIALS` | MEDIUM | CWE-798 | Literal secrets in password/token/key-named variables (placeholders ignored; test files skipped) | The value is read with `os.environ["NAME"]`, so the app fails fast if it isn't set. |
| `TLS_VERIFY_DISABLED` | MEDIUM | CWE-295 | HTTP call with `verify=False` | `verify=False` is removed. |
| `WEAK_CRYPTO` | MEDIUM | CWE-328 | MD5/SHA-1 used for passwords or secrets | None: stored hashes would stop matching. Left for Claude or a human. |
| `DEBUG_MODE` | MEDIUM | CWE-489 | `app.run(debug=True)` | Debug is on only when `FLASK_DEBUG=1`. |

### Proof checks (`engine/checks.py`)
Every fix, from a rule or from Claude, must pass these before it is written to the workspace. They run again on verification. A check with `passed: null` does not apply.

| id | Check | How |
|---|---|---|
| `compiles` | Patched code compiles | `compile()` the whole patched file |
| `fixed` | Weakness no longer detected | Rescan with the same rules: fewer hits of this type in the flagged function, and the original code is no longer flagged there. `null` for AI-found weaknesses, which get `ai_recheck` instead. |
| `no_new` | No new weaknesses introduced | Rescan the whole file with every rule pack: no (type, function) count may go up |
| `scoped` | Change stays inside the flagged code | Compare syntax trees: everything outside the flagged function (or flagged top-level statements) is identical, apart from new imports, `_patchproof_*` helpers and `PATCHPROOF_*` constants |
| `signature` | Function signature unchanged | Same name, parameters, defaults and decorators, so callers keep working |
| `ai_recheck` | AI re-check: weakness resolved | AI-found weaknesses only, at verification. It fails closed if Claude can't be asked. |
| `exploit` | Exploit blocked | Practice targets with exploit cases for this type: every case blocked |
| `regression` | Normal behaviour preserved | Practice targets: the **whole** regression suite runs, not only the cases for this type. No case that passes without the fix (its file put back to `base_code`) may fail with it. A case that already failed is reported as pre-existing (vuln-bank's REG-4, until prompt injection is fixed). |

The static checks judge each fix on its own change (`base_code` against `patched_code`), so later fixes to the same file don't count against it. Exploit and regression runs use the current workspace with every fix applied.

### AI assistance (`engine/ai.py`, optional)
AI is on when the chosen provider's key is set, in the environment or in `.env` at the repo root. `PATCHPROOF_AI=off` forces it off.
- **Provider:** `PATCHPROOF_AI_PROVIDER` (`anthropic` | `gemini`). If unset, Claude when `ANTHROPIC_API_KEY` is set, otherwise Gemini when `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) is set.
- **Model:** `PATCHPROOF_AI_MODEL` pins one.
- **Claude:** default `claude-opus-5-5`, with prompt caching on the file context and server-side fallback (`fallbacks: "default"`).
- **Gemini:** walks `GEMINI_MODELS` past models that are overloaded (503), out of quota (429), retired (404), slow (120s timeout) or dropping connections. A model whose daily free-tier quota (20 requests) is used up is skipped until it resets. If only temporary problems stopped every model, it waits once and retries.
- **AI fixes keep the original def line:** only the body is taken from the model. Decorators may be added (an access check), never removed. Markdown fences and odd indentation are cleaned up before parsing.

Every answer records the model that actually replied. Errors are shown as plain messages.

| Feature | What Claude does | What PatchProof checks |
|---|---|---|
| Review | Says whether a rule finding is real, a false positive or uncertain, and describes the attack | Nothing is proven by it. It is stored as `ai_review`, labelled as opinion, and never changes a status. |
| Fix | Rewrites the flagged function (or top-level statements) when no rule-based patch applies | It must pass every static proof check. Failed checks go back to Claude with the reasons, up to 3 attempts; otherwise nothing is written. Practice targets also run exploits and regressions on verify. |
| Deep scan | Reads each in-scope file for logic flaws the rules can't see (types in §6, "AI deep scan") | Each finding must quote a line that really is within 5 lines of the span it names, or it is dropped. Duplicates of known findings are skipped. These findings are never `provable`. |
| Re-check | For AI-found weaknesses, judges whether the patched code resolves them | Recorded as the `ai_recheck` check. It fails closed. |

Tests never call the API: `conftest.py` forces AI off, and AI tests install a scripted model with `ai.set_responder`.

### vuln-bank golden path (auto-patch + verify)
| Type | CWE | PoC (from SCOPE.md) | Patch intent (LibCST) | Security check | Regression check |
|---|---|---|---|---|---|
| `AI_PROMPT_INJECTION` | CWE-77, CWE-20 | PI-1, PI-2 | Add an input guard at the top of `chat()`: an instruction-override regex (`PATCHPROOF_INJECTION_PATTERN`) that returns a safe canned refusal. It deliberately does not reuse upstream's keyword list, which flags innocent words like "ignore". Remove the `or self._is_prompt_injection_request(...)` DB-access grant. Wrap user text in `<user_input>` delimiters. | PI-1 and PI-2: attacker text never reaches the LLM, and no user-table dump | REG-1 and REG-4 get normal replies (REG-4 contains the word "ignore") |
| `AI_BROKEN_AUTH` | CWE-862 | BA-1, BA-2 | In `_get_database_context()`, anonymous chats get no DB context. Every query result is filtered to rows containing `user_context["account_number"]`, and withheld rows are logged as FORBIDDEN. | BA-1 (bob's balance) and BA-2 (other customers' transfers) are absent from the prompt and the reply | REG-2 (own balance) and REG-3 (own transfers) still work |

### vuln-bank: no rule-based fix (Claude fixes them when AI is on)
`AI_INFO_DISCLOSURE`, `AI_ROLE_OVERRIDE` and `VERBOSE_ERROR_DISCLOSURE`. They are not `provable` (no exploit case), so their fixes are proven by the static checks plus vuln-bank's whole regression suite.

### notes-api (auto-patch + verify)
| Type | CWE | PoC | Patch intent (LibCST) | Regression check |
|---|---|---|---|---|
| `SQL_INJECTION` | CWE-89 | SQLI-1 (`x' OR '1'='1' --` in the search returns bob's and admin's notes), SQLI-2 (injected owner) | Parameterise the query: the f-string becomes a `?` placeholder query, and the values (with LIKE wildcards) become a parameter tuple | REG-1: alice still finds her Groceries note |
| `PATH_TRAVERSAL` | CWE-22 | PT-1 (`../secrets/api_keys.txt`), PT-2 (`../notes_app.py`) | Replace `open(os.path.join(FILES_DIR, name))` with `_patchproof_safe_join`, which resolves the path and raises `PermissionError` outside the folder | REG-2: `welcome.txt` still downloads |

`HARDCODED_CREDENTIALS` (`ADMIN_TOKEN`) has no exploit case. Its rule-based fix (`os.environ["ADMIN_TOKEN"]`) is proven by the static checks plus the whole regression suite. That suite runs with `ADMIN_TOKEN` supplied by the `env` block in `cases.json`, the way a deployment would supply it.

### Out of scope
Card generation and transaction race conditions, GraphQL depth limiting, and anything outside `SCOPE.md`.

## 5. Data Schema — TinyDB table `vulnerabilities` (file `backend/data/patchproof.json`)
Exact record shape. Python mirror: `engine/models.py` (`Vuln`). TypeScript mirror: `frontend/src/lib/types.ts`.
```json
{
  "id": "vuln_7f3a9c",
  "file_path": "ai_agent_deepseek.py",
  "line_number": 80,
  "end_line": 94,
  "severity": "CRITICAL",
  "type": "AI_PROMPT_INJECTION",
  "cwe": "CWE-77",
  "title": "User input concatenated into LLM prompt",
  "severity_rationale": "Unauthenticated attacker text reaches the model and unlocks a full user-table dump.",
  "status": "OPEN",
  "patchable": true,
  "original_code": "<exact source lines line_number..end_line>",
  "patched_code": null,
  "diff": null,
  "patch_rationale": null,
  "poc_status": "NOT_RUN",
  "regression_status": "NOT_RUN",
  "poc_log": [],
  "verification_log": [],
  "provable": true,
  "fixer": "rule",
  "detected_by": "rule",
  "fix_source": null,
  "checks": [],
  "ai_review": null,
  "behaviour_change": null,
  "base_code": null,
  "created_at": "2026-10-30T18:00:00Z",
  "updated_at": "2026-10-30T18:00:00Z"
}
```
| Field | Notes |
|---|---|
| `id` | `"vuln_" + 6 hex`. Assigned by the backend. |
| `file_path` | Relative to the active target's root (and to the workspace copy). |
| `line_number`, `end_line` | 1-based, inclusive, from the **pristine** file. |
| `original_code` | Exact pristine source of lines `line_number..end_line`. This is the "affected code" shown in the UI. |
| `patched_code` | The **whole file** after patching. |
| `diff` | Unified diff (`difflib.unified_diff`, `fromfile=a/<file_path>`, `tofile=b/<file_path>`). |
| `poc_log`, `verification_log` | Lists of `LogLine` (§6). Append-only per run. A rerun replaces the list. A failed patch writes its log, including each rejected AI attempt, to `verification_log`. For findings with no exploit case, verify stores the regression run without the fix in `poc_log` as the "before" evidence. |
| `patchable`, `provable`, `fixer` | See §4. |
| `detected_by` | `"rule"` (scanner) or `"ai"` (deep scan). |
| `fix_source` | Who wrote the applied fix: `"rule"`, `"ai"` or `null`. |
| `checks` | `[{id, label, passed: bool \| null, detail}]`: the proof checks from the latest patch or verify (§4). |
| `ai_review` | `null`, or `{verdict: "confirmed" \| "false_positive" \| "uncertain", confidence, reasoning, attack_scenario, fix_hint, model (the one that replied), reviewed_at}`; or `{error, model, reviewed_at}` if the review failed. |
| `behaviour_change` | Claude's note on what a legitimate caller would notice, for AI fixes. |
| `base_code` | The whole file just before this finding's patch, used to re-check or retry it. |

Records saved by older versions (without `fixer`) are upgraded on read: `provable` and `fixer` come from the old `patchable`.

## 6. Enums (exact strings)
| Field | Allowed values |
|---|---|
| `status` | `OPEN`, `PATCHED`, `VERIFIED`, `FAILED` |
| `poc_status` | `NOT_RUN`, `EXPLOITABLE`, `BLOCKED` |
| `regression_status` | `NOT_RUN`, `PASSED`, `FAILED` |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `type` | `ai` pack: `AI_PROMPT_INJECTION`, `AI_BROKEN_AUTH`, `AI_INFO_DISCLOSURE`, `AI_ROLE_OVERRIDE`, `VERBOSE_ERROR_DISCLOSURE`. `generic` pack: `SQL_INJECTION`, `COMMAND_INJECTION`, `CODE_INJECTION`, `PATH_TRAVERSAL`, `SSRF`, `INSECURE_DESERIALIZATION`, `INSECURE_JWT`, `HARDCODED_CREDENTIALS`, `TLS_VERIFY_DISABLED`, `WEAK_CRYPTO`, `DEBUG_MODE`. AI deep scan (it may also report generic types the rules missed): `BROKEN_ACCESS_CONTROL`, `MISSING_AUTHENTICATION`, `XSS`, `OPEN_REDIRECT`, `CSRF`, `MASS_ASSIGNMENT`, `INSECURE_FILE_UPLOAD`, `BUSINESS_LOGIC`, `RACE_CONDITION`, `SENSITIVE_DATA_EXPOSURE`, `OTHER_WEAKNESS` |
| `fixer`, `detected_by`, `fix_source` | `rule`, `ai` |
| `LogLine.level` | `INFO`, `WARN`, `ERROR`, `SUCCESS` |

`LogLine` = `{"ts": "<ISO-8601>", "level": "<level>", "msg": "<text>"}`

`msg` conventions, which the UI relies on:
- **First line** is a one-sentence headline, such as `Bob's account 4001000022 and balance 98,310.00 shown to alice`. `ERROR` headlines in `poc_log` are shown as "What the exploit proved", so state the leak plainly.
- **Optional further lines** (after `\n`) carry captured evidence, such as an excerpt of the prompt sent to the model or the assistant's reply. The UI shows them collapsed under "Captured context", with 10-digit account numbers highlighted. Keep excerpts under about 15 lines.
- **Name the case** at the start of step lines (`PI-1 as alice: "..."`, `REG-2 ...`). Case IDs come from `target_app/SCOPE.md`.

### State machine (enforced by the backend)
```
scan    -> creates OPEN / NOT_RUN / NOT_RUN
poc     -> provable only        -> poc_status = EXPLOITABLE | BLOCKED
           unpatched: replaces poc_log (security cases + a baseline of the whole regression suite)
           patched (diff set): appends the replay to verification_log; poc_log keeps the original pre-patch evidence
patch   -> requires status OPEN or FAILED; AI on unless fixer == "rule"; provable findings need poc_status == EXPLOITABLE first
           (a retry after a failed verification doesn't: the file is put back to base_code, then patched again)
           rule-based patch first, Claude when none applies; written only if every static check passes
           -> status PATCHED with fix_source, checks, base_code (or FAILED, file untouched, log says why)
verify  -> requires status == PATCHED
           every check passes (static, ai_recheck, exploit, regression) -> VERIFIED, else FAILED
           poc_status / regression_status are updated only when exploit / regression cases ran
review  -> AI on; stores ai_review (never changes status)
deep-scan -> AI on; adds detected_by = "ai" findings (OPEN, fixer "ai", not provable)
reset   -> restore the workspace from the target's pristine source and clear the table (projects: the folder is never touched)
select  -> switch the active target, reset, then scan it; on failure the previous target stays active
```
A rejected transition returns **409**.

## 7. API Contract (FastAPI, base `/api/v1`)
| Method | Path | Success response | Errors |
|---|---|---|---|
| GET | `/` (no prefix) | `200 {"status": "PatchProof API Online"}` | — |
| GET | `/api/v1/health` | `200 {"status": "ok", "busy": false, "action": null, "ai": {"enabled", "provider", "model", "reason"}}`. While a job runs: `busy: true` and `action` holds the action name (`"run-all"`, `"poc"`, `"deep-scan"`, ...). `ai.reason` says why AI is off. | — |
| GET | `/api/v1/targets` | `200 {"active": Target, "profiles": [Target, ...], "error": {"message", "at"} \| null}`. `Target` = `id`, `kind`, `name`, `summary`, `module`, `source`, `commit`, `in_scope`, `out_of_scope`, `provable`, `harness`. `active` also carries `cases`, `stats` (`files_scanned`, `files_skipped`, `parse_errors`) and `deep_scan` (`{at, files, added, dropped, errors, model}` or null). `error` is the last failed selection. | — |
| POST | `/api/v1/targets/select` | Body has exactly one of `{"id"}`, `{"path"}` (absolute local folder) or `{"git_url"}` (`https://`). Returns `202 {"accepted": true, "action": "select"}`. | 404 (unknown id), 422 (invalid selection) |
| GET | `/api/v1/vulns` | `200 {"vulns": [Vuln, ...]}` sorted by severity, then `line_number` | — |
| GET | `/api/v1/vulns/{vuln_id}` | `200 Vuln` | 404 |
| POST | `/api/v1/scan` | `202 {"accepted": true, "action": "scan"}` | — |
| POST | `/api/v1/poc/{vuln_id}` | `202 {"accepted": true, "action": "poc", "vuln_id": "..."}` | 404, 409 (not provable) |
| POST | `/api/v1/patch/{vuln_id}` | `202 {"accepted": true, "action": "patch", "vuln_id": "..."}` | 404, 409 (already patched; needs AI and it is off; exploit not run yet) |
| POST | `/api/v1/verify/{vuln_id}` | `202 {"accepted": true, "action": "verify", "vuln_id": "..."}` | 404, 409 |
| POST | `/api/v1/run-all` | `202 {"accepted": true, "action": "run-all"}`. Runs scan, then poc, patch and verify for every provable finding, then patch and verify for every other finding with `fixer == "rule"`. AI fixes are never part of run-all: they cost API calls, so they run one at a time. | — |
| POST | `/api/v1/ai/review/{vuln_id}` | `202 {"accepted": true, "action": "review", "vuln_id": "..."}` | 404, 409 (AI off) |
| POST | `/api/v1/ai/review-all` | `202 {"accepted": true, "action": "review-all"}`. Reviews every rule finding without a review, 4 at a time. | 409 (AI off) |
| POST | `/api/v1/ai/fix-all` | `202 {"accepted": true, "action": "fix-all"}`. Proves (when it can), patches and verifies every OPEN finding, one at a time: a rule-based patch where one applies, otherwise the AI model's. | 409 (AI off) |
| POST | `/api/v1/ai/deep-scan` | `202 {"accepted": true, "action": "deep-scan"}`. Up to 12 in-scope files (route-like files first), 4 at a time. | 409 (AI off) |
| GET | `/api/v1/patches` | `200 text/x-diff`: every fixed file, original source against the workspace copy, as one unified diff | — |
| POST | `/api/v1/reset` | `202 {"accepted": true, "action": "reset"}` | — |

Errors use FastAPI's default `{"detail": "<human readable>"}`. All POST work runs in `BackgroundTasks`, so the response returns immediately.
- **One job at a time.** A POST arriving while a job runs gets **409** `"Another action (...) is still running"`.
- **Frontend polling.** The frontend polls `GET /api/v1/vulns` and `GET /api/v1/health` every 0.7s after an action, and stops when `busy` is false.
- **Stable IDs.** Finding IDs are `"vuln_" + sha1("<file_path>:<type>")[:6]` for the first site of each `ai` rule in a file; further sites add `<function>#<n>` as the anchor. Generic rules can fire several times per file, so they hash `"<file_path>:<type>:<anchor>"` instead. The anchor is the enclosing function plus the statement where the value was built (for queries assigned first) plus the flagged statement, never a line number. AI findings use `ai|<evidence line>`. IDs survive reset, rescan and patches elsewhere in the file.
- **Rescans.** A rescan inserts only new findings. Existing records keep their pipeline state.

## 8. Engine Function Contracts (`engine/`, pure Python)
Typed in `engine/models.py`. The backend calls these four functions, plus the target helpers in `engine/targets.py`. `profile` is a target dict (§4) and defaults to vuln-bank.
```python
scan_repository(repo_path: str, profile=None, stats=None, ai_fixes=None) -> list[Finding]  # stats: files_scanned, files_skipped, parse_errors
run_poc(workspace: str, vuln: Vuln, profile=None) -> PocResult                 # {"exploitable": bool, "log": [LogLine]}
apply_patch(workspace: str, vuln: Vuln, profile=None, use_ai=None) -> PatchResult
    # {"success", "patched_code", "diff", "patch_rationale", "fix_source", "checks", "base_code", "behaviour_change", "log"}
    # writes the file only when every static check passed
verify_fix(workspace: str, vuln: Vuln, profile=None) -> VerifyResult           # {"security_blocked": bool|None, "regression_passed": bool|None, "checks", "log"}
```
AI (`engine/ai.py`): `status()`, `review(source, vuln)`, `review_many(items)`, `propose_fix(source, vuln, profile)`, `deep_scan(workspace, profile, known)`, `recheck(after, vuln)`. Each raises or returns `AIError` messages fit for the UI.

`Finding` = the `Vuln` fields minus `id`, `status`, `*_status`, `*_log`, `patched_code`, `diff`, `patch_rationale`, `fix_source`, `checks`, `ai_review`, `behaviour_change`, `base_code` and the timestamps. The backend fills those in.
- `workspace` is an absolute path to the writable copy (`backend/data/workspace`). For projects it holds only their Python files. The engine never decides paths.
- PoC and verify cases run the target's harness through `subprocess` with a timeout, in a fresh isolated interpreter (`sys.executable -I`): `target_app/harness/run_case.py` for vuln-bank, `target_app/harness/run_call.py` for function-call targets such as notes-api. Projects have no harness and are never run.

## 9. Design System (Frontend — mandatory)
Mood: **red-on-black cyber-noir**. Think CRT bloom, halftone dot screens, PCB traces, glitch, and "RESTRICTED" hazard stickers, like a classified forensic console. **Dark only.**

### Fonts: exactly three, strict roles, no others
| Token | Font | Use for | Never use for |
|---|---|---|---|
| `font-logo` | **Vintage Glitch** | the project name `PATCHPROOF`, the text part of the logo, **only** via `components/Logo.tsx` (`<Logo/>` in the sidebar, `<Wordmark/>` as the Overview hero title) | anything else, ever |
| `font-heading` | **Moonhouse** | headlines and section titles | body text |
| `font-body` | **Technor** (variable 200-900) | all body text, including labels, buttons, code, diffs and terminal logs | — |

**Do not add any other font**: no monospace, no Google Fonts, no `@fontsource`. Code and logs use Technor. Files live in `frontend/public/fonts/`. `@font-face` rules and tokens are in `frontend/src/index.css`.

### Colour tokens (in `index.css` `@theme`)
| Token | Value | Use |
|---|---|---|
| `--color-void` | `#050505` | page background |
| `--color-panel` | `#0c0606` | cards and panels |
| `--color-blood-950` | `#1a0000` | deep fills |
| `--color-blood-800` | `#3a0000` | borders, panel tint |
| `--color-blood-600` | `#8b0000` | muted accent |
| `--color-signal` | `#e10600` | primary accent and glow |
| `--color-ember` | `#ff3b30` | hover, hot accent |
| `--color-bone` | `#f2e9e4` | primary text |
| `--color-ash` | `#8a7f7b` | secondary text |
| `--color-amber` | `#ffb000` | `EXPLOITABLE` and warnings |
| `--color-phosphor` | `#ffe4e1` | "white-hot" `VERIFIED` glow |

Status mapping:
- `OPEN`: ash outline
- `EXPLOITABLE`: amber, pulsing
- `PATCHED`: signal red
- `VERIFIED`: phosphor white-hot glow
- `FAILED` / `BLOCKED-by-error`: ember on blood

### Effects (reusable utilities in `index.css`)
`.crt` (scanlines), `.grain`, `.halftone` (dot grid), `.glow-signal` / `.text-glow`, `.glitch` (RGB split on hover), `.sticker` (hazard label). Every animation must sit behind `@media (prefers-reduced-motion: no-preference)`.

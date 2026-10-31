# Handoff Log

Append a new entry at the **top** after every session. Keep it short and factual.

## Template
```
### <YYYY-MM-DD HH:MM> — <Engine|Backend|Frontend|Lead> — <human name> / <agent>
**Tasks:** E-02, ...
**Files changed:**
- path/to/file.py — what changed
**What was built / verified:** (commands run and their results)
**Contract impact:** none | <describe; needs Lead approval in PROJECT_CONTEXT.md>
**Dependencies added:** none | <pkg==ver, why>
**Requests to other domains:** none | <domain: request>
**Next steps:**
- ...
```

---

### 2026-10-31 (night) — Lead — Vaibhav / Claude
**Tasks:** G-10 (every language, whole app)
**What changed:**
- **Languages:** `engine/languages.py` and `engine/lang_rules.py`.
  - Python keeps the syntax-tree rules.
  - JavaScript/TypeScript, PHP, Java/Kotlin, Go, Ruby, C#, HTML and shell get about 64 pattern rules: SQL/NoSQL, command and code injection, XSS, path traversal, SSRF, open redirect, deserialization, weak crypto, TLS, JWT, CORS, CSRF, mass assignment, debug and secrets.
  - Each rule reads the whole statement.
  - Test files, minified or vendored code, and dev configs are skipped.
- **Proof checks for other languages** (`checks.text_checks`): syntax (`node --check`, `php -l`, `ruby -c`, `bash -n`, `gofmt` when installed), weakness gone on rescan, nothing new flagged, change confined to the flagged lines.
- **AI:** fixes and deep scan work on any language.
  - Fixes replace exactly the flagged lines.
  - The deep scan reads every source file in batches, and lists any it could not read.
- **vuln-bank is scanned as a whole app.** `harness.files` limits exploit/regression runs to the files the test cases actually execute. Everything else is proven by the static checks.

**Verified:**
- Tests pass.
- vuln-bank: 66 findings (51 Python, 10 JS, 5 HTML). Run-all gives 44 verified; the other 22 need an AI fix.
- Real repos:
  - DVWA (PHP): 63 findings
  - NodeGoat (Node): 9 findings, all real
  - RailsGoat (Ruby): 30 findings, all real
- Live Gemini fixed NodeGoat's `eval(req.body.preTax)`. All 4 checks passed, including `node --check`.

**Limits:**
- Rule-based fixes are Python only; other languages are fixed by the AI.
- Pattern rules see one statement at a time, with no data flow across files.

---

### 2026-10-31 (evening) — Lead — Vaibhav / Claude
**Tasks:** G-09 (fix everything the live AI runs exposed)
**What changed:**
- **Scanner:** SSRF through module helpers that forward a URL (DSVW's `FETCH` lambda: 2 new findings, both rule-fixed at the call site).
  - The AI-agent rules report every site; the first keeps its old ID. vuln-bank now has **8** findings: app.py's anonymous chat route leaks exception text too.
  - The proof checks count every site, so fixing the first site no longer makes the second look "new".
- **Verifier:**
  - Regressions are judged against the code without the fix: pre-existing failures (vuln-bank REG-4) are reported, not blamed.
  - That run is stored as the "before" column for findings with no exploit case.
- **AI fixes:**
  - Only the body is taken from the model; the original def line is kept, and decorators may only be added.
  - Markdown fences and first-line indentation are cleaned up.
  - Dropped connections, timeouts and busy models fall through to the next Gemini model, with one retry after a wait.
  - Daily free-tier quota (20 requests per model per day) is remembered and explained.
- **New:** `POST /ai/fix-all` and an **AI fix all** button.

**Verified:**
- 138 tests pass.
- Whole vuln-bank repo: 51 findings, 44/44 rule fixes verified. DSVW: 10 findings, 6/6 rule fixes verified.
- **Live Gemini fixed and verified all 9 rule-less findings** (5 vuln-bank, 4 DSVW); two needed the feedback loop.
- Browser e2e green, no page errors.

**Note:** the Gemini key is on the free tier; testing used up today's quota on several models (it resets daily). The newest unused models still answer.

---

### 2026-10-31 (later) — Lead — Vaibhav / Claude
**Tasks:** G-06..G-08 (stronger fixes, proof checks, optional AI)
**Files changed:**
- `engine/checks.py` (new): static proof checks run on every fix, at patch time and on verify
- `engine/ai.py` (new): Claude review, deep scan, fixes (up to 3 attempts, with failed checks fed back) and re-check
  - official `anthropic` SDK, structured JSON outputs, prompt caching, server-side fallback
  - off without a key
- `engine/patcher.py`:
  - rule-based fixes for 10 generic types
  - nearest-site matching for identical code in several functions
  - LibCST region replacement for AI fixes
  - `apply_patch` writes only after the checks pass
- `engine/verifier.py`: the static checks judge each fix on its own change; exploit runs plus the **whole** regression suite on practice targets
- `engine/generic_rules.py`: sanitisers followed through assignments; the SSRF guard counts as safe; the anchor includes the query's own assignment, so two queries ending in the same `execute_query(query)` are two findings (one was hidden before)
- `engine/scanner.py`: credentials in test files skipped; an early-return input guard counts as a prompt-injection fix; per finding: `provable`, `fixer`, `detected_by`
- `engine/models.py`, `engine/harness.py` (`env` for function-call cases), `engine/poc_runner.py` (whole regression suite as baseline)
- `backend/*`:
  - new record fields; old records upgraded on read
  - projects patched in a workspace copy
  - `/ai/review/{id}`, `/ai/review-all`, `/ai/deep-scan`, `/patches`; `/health` reports AI status
  - patch allowed without an exploit for non-provable findings; retry after a failed verify
- `frontend/*`:
  - AI context and sidebar status
  - review card; proof-checks list; AI actions and combined patch download on Findings
  - honest copy for projects; mocks updated
- `target_app/fixtures/notes-api/cases.json`: `env` block (synthetic `ADMIN_TOKEN`)
- `conftest.py` (new): tests never call the real API
- `.env.example` (new); `pyproject.toml`/`uv.lock`: `anthropic`
- docs: `PROJECT_CONTEXT.md` §1-§8, `README.md` (requirements-to-evidence table), `DEMO.md`, `SCOPE.md`; `AGENT_RULES.md` network rule narrowed for the optional Claude call (requested by the Lead)

**What was built / verified:**
- `uv run pytest`: 126 passed. That includes every fix shape, the checks rejecting each kind of bad fix, and the AI path with a scripted model.
- Whole vuln-bank repo as a project: 50 findings; 44 get a rule-based fix and 44/44 pass every check; the source folder is untouched.
- Live browser run, no page errors:
  - vuln-bank 2/2 verified with 7/7 checks each
  - notes-api 3/3, including the token fix
  - DSVW 4 fixed in ~3s
  - combined `.patch` download
  - mock mode
- AI screens checked in the browser against a scripted model: deep scan, review, AI fix, re-check, report.

**Live AI (later the same day):**
- The Anthropic key had no credits, so I added Gemini as a second provider (REST, stdlib, model fallback chain). `.env` is set to Gemini.
- In the live browser run on vuln-bank:
  - review: 9s
  - AI fix of information disclosure: 11s, 5/5 static checks
  - verified with 6/6 checks
  - deep scan: 28s, 5 real findings, 2 ungrounded answers dropped
- The verifier now judges regressions against the code without the fix, so pre-existing failures (REG-4) are reported and not blamed on unrelated fixes.
- 130 tests pass.
**Contract impact:** Lead-approved and documented in `PROJECT_CONTEXT.md`:
- new `Vuln` fields
- `patchable` now means "a fix can be produced"
- new endpoints and AI deep-scan types
- engine signatures

**Dependencies added:** `anthropic` (Python).
**Next steps:**
- Add `ANTHROPIC_API_KEY`, then rehearse the AI segment in `DEMO.md`.

---

### 2026-10-31 — Lead — Vaibhav / Claude
**Tasks:** G-01..G-05 (PatchProof is no longer vuln-bank only)
**Files changed:**
- `engine/targets.py` (new): target profiles, project profiles, Python file discovery that skips dependency, venv and build folders
- `engine/generic_rules.py` (new): 11-rule generic pack with per-function taint (parameters plus web input, including `self.path` for `http.server` apps)
- `engine/scanner.py`: rule packs (`ai`, `generic`), profile text overrides, scan stats, multi-site findings with an `anchor`
- `engine/patcher.py`: generic LibCST patchers for SQL injection (bound parameters) and path traversal (`_patchproof_safe_join`). They locate the site by content, and `can_patch()` dry-runs them.
- `engine/harness.py`, `poc_runner.py`, `verifier.py`, `models.py`: take a `profile`; `function-call` harness kind; new `VulnType`s
- `target_app/profiles/*.json`, `target_app/fixtures/notes-api/*`, `target_app/harness/run_call.py` (new): the vuln-bank profile, plus the notes-api practice target
- `backend/db.py`, `jobs.py`, `main.py`: active target in a `meta` table; `GET /targets` and `POST /targets/select` (profile id, local folder or https Git URL with a shallow clone into `backend/data/projects/`); a failed selection keeps the previous target
- `frontend/`: Targets page (switch practice target, scan your own project), target context, all copy driven by the active target
- `PROJECT_CONTEXT.md` §1, §3, §4, §6-§8, `README.md`, `target_app/SCOPE.md`, `DEMO.md`: documented all of the above

**What was built / verified:**
- `uv run pytest`: 76 passed. That includes a vulnerable and a safe case per rule, notes-api prove-patch-verify in either order, and a canary showing project code is never executed.
- vuln-bank still yields exactly 7 findings with the same IDs.
- Live browser run, no page errors:
  - notes-api full loop: 2/2 verified
  - `https://github.com/stamparm/DSVW`: 8 findings
  - local folder (the whole vuln-bank repo): 14 files scanned
  - switched back to vuln-bank: 7 findings

**Contract impact:** Lead-approved additive changes, documented in `PROJECT_CONTEXT.md`:
- new endpoints and `VulnType`s
- `profile` parameters on the engine functions
- anchor-based IDs for generic findings

The `Vuln` record shape is unchanged.
**Dependencies added:** none (`git` CLI is used for clones).
**Requests to other domains:** none
**Next steps:**
- Rehearse the optional "scan your own project" segment in `DEMO.md`.
- Known limits:
  - taint is within one function only
  - SSRF through a lambda (DSVW's `FETCH`) is missed
  - projects are static only

### 2026-10-30 — Audit against PS-02 — Vaibhav (Lead) / Claude
**Why:** re-checked every requirement end to end and probed for false positives.

**Gaps found and fixed:**
1. **The injection fix broke legitimate use.** The guard reused upstream's keyword list, so "Can you ignore the late fee…" and "Is my data stored in a database?" were refused.
   - Fix: replaced it with an instruction-override regex (`PATCHPROOF_INJECTION_PATTERN`; the patch adds `import re` if it's missing).
   - Added REG-4 plus 7 parametrised false-positive and true-positive tests.
2. **A second authorization leak was untested.** Alice's own history included bob → admin transfers. Added BA-2 (exploit) and REG-3 (own transfers still shown). The existing patch blocks it, and that is now proven.
3. **"Before the patch" was inferred, not evidence.**
   - `run_poc` now also records a regression baseline.
   - The UI reads per-case before/after verdicts from the logs.
   - Replaying the exploit on patched code appends to `verification_log` and keeps the original `poc_log`.
4. **The dev API restarted mid-job.** uvicorn matches `--reload-exclude` against absolute paths. Fixed in the `Makefile` with `$(CURDIR)/backend/data`. Verified: 0 reloads across reset plus full pipeline.
5. **Drift between UI, mock and engine.**
   - The UI now imports `target_app/harness/cases.json` directly.
   - Mock findings and evidence are generated from real scanner and engine output (`frontend/src/mocks/findings.json`, `evidence.json`).

**What was verified:**
- 29 Python tests pass.
- Fresh-copy install (`uv sync`, `npm ci`, build) passes.
- Live browser run: proofs, before/after cells, replay preserving evidence, REG-4 baseline "Broken" then "Passed".
- Mock-mode flow and page sweep at 1440px and 390px: no page errors, no horizontal scroll.

**Docs:** `SCOPE.md` case table, `PROJECT_CONTEXT.md` golden path and poc state machine, `README.md`.

### 2026-10-30 — Engine + Backend + Integration — Vaibhav (Lead) / Claude
**Tasks:** E-01..E-06, B-01..B-05, F-05 live switch. X-01 in progress (demo rehearsal).
**Files changed:**
- `engine/scanner.py`: 5 AST rules, pattern-based rather than line-based. Scans `ai_agent_deepseek.py` plus `app.py` 2328-2476 and finds 7 findings on the pristine snapshot.
- `engine/harness.py`: runs `run_case.py` in `python -I` subprocesses and judges cases from the recorded prompts, queries and replies
- `engine/poc_runner.py`, `engine/verifier.py`: security cases, plus regression cases for the dual test
- `engine/patcher.py`: LibCST transforms
  - **`PromptInjectionPatch`:** guard at the top of `chat()`, removes the injection DB grant, fences user text.
  - **`BrokenAuthPatch`:** anonymous chats get no DB access, and every query result is filtered to the caller's own rows.
  - Every patch must compile, is never applied twice, and carries a `# PatchProof:` comment.
- `backend/db.py`: TinyDB with locking, stable IDs, insert-only rescans, workspace reset/ensure
- `backend/jobs.py`: background jobs with one-at-a-time locking. `run_all` = scan, then poc, patch and verify per patchable finding.
- `backend/main.py`: all §7 endpoints with the 404/409 state machine. `/health` now reports `busy` and `action`.
- `target_app/harness/cases.json`: PI-1, PI-2, BA-1, REG-1, REG-2. `run_case.py` accepts `--user anonymous`.
- `frontend`:
  - Live API by default, polling driven by `/health`, offline banner, finished toasts replace in-progress ones.
  - Mocks now mirror the busy and 409 behaviour.
- `Makefile`: `make api` excludes `backend/data` from reload (the patched workspace would otherwise restart the server mid-job)
- `README.md`, `PROJECT_CONTEXT.md` §7 (health shape, one-job rule, stable IDs), `SCOPE.md` (`app.py` range 2328-2476)

**What was built / verified:**
- `uv run pytest`: 20 passed (10 engine, 10 API).
- Live browser run passes with no page errors: reset, scan (7 findings), manual exploit/patch/verify on broken auth, then the full pipeline to 2/2 verified, then the report.

**Contract impact:** `/health` gained `busy` and `action` (additive). Documented in §7.
**Dependencies added:** none
**Next steps:** rehearse the 2-minute demo (X-01).

### 2026-10-30 — Frontend (pass 2) — Vaibhav / Claude
**Tasks:** F-05 polish
**Files changed:**
- `frontend/src/components/Logo.tsx`: larger sidebar logo, plus a `<Wordmark/>` used as the Overview hero title. This is the only file that uses Vintage Glitch.
- `frontend/src/pages/OverviewPage.tsx`: hero with the wordmark (glitches in once on load), tagline, a primary action that depends on state, and a target card
- `frontend/src/lib/knowledge.ts`: per-type CWE name, OWASP Top 10 for LLM apps 2025 mapping, attacker, data at risk, remediation steps
- `frontend/src/pages/FindingPage.tsx`:
  - Summary tab gains a classification grid and step-by-step remediation (shown for report-only findings or before patching).
  - Evidence tab gains a "What the exploit proved" callout.
  - Tests tab becomes a before/after comparison.
- `frontend/src/components/EvidenceLog.tsx`: multi-line messages show "Captured context" in a collapsed block, and account numbers are highlighted
- `frontend/src/components/CommandPalette.tsx`: ⌘K or Ctrl+K to jump to any page or finding, or run actions
- `App.tsx`: per-page document titles, skip link
- `PROJECT_CONTEXT.md` §6: documented the `LogLine.msg` conventions (headline + optional captured context lines + case IDs). This is additive and the schema is unchanged.

**What was built / verified:** build passes. Playwright checks of the detail tabs, captured context, palette navigation and page titles pass with no page errors.
**Contract impact:** none to the shape. The `msg` conventions are documented in §6.
**Requests to other domains:**
- **Engine (E-02 / E-05):** follow the §6 `msg` conventions.
  - Put an excerpt of the captured prompt or reply in the extra lines of the `ERROR` log line that proves the leak.
  - Start step lines with the case ID.

### 2026-10-30 — Frontend — Vaibhav / Claude
**Tasks:** F-01..F-04 done, F-05 on mocks
**Files changed:**
- `frontend/src/App.tsx`, `frontend/src/lib/router.ts`: multi-page app with hash routing (`#/`, `#/findings`, `#/findings/:id`, `#/scope`, `#/activity`, `#/report`)
- `frontend/src/pages/*`: Overview, Findings, finding detail (Summary / Exploit evidence / Patch / Tests tabs), Target & scope, Activity, Report
- `frontend/src/components/*`: Sidebar, GlobalActions (reset asks for confirmation), PipelineRing, DiffView, EvidenceLog, CodeBlock, Pills, Panel, Toasts
- `frontend/src/lib/scope.ts`: mirrors `target_app/SCOPE.md` (target, in/out of scope, test cases PI-1, PI-2, BA-1, REG-1, REG-2)
- `frontend/src/mocks/*`: mock API simulates scan, reset, run-all, poc, patch and verify with the same state machine as §6
- `frontend/src/index.css`: headings set in uppercase (Moonhouse capitals read better), brighter secondary text, print styles

**What was built / verified:**
- `npm run build` passes.
- Playwright run: reset (with confirmation), scan, full pipeline to 2/2 verified, patch tabs, test results, filters, JSON download. No page errors.
- No horizontal scroll at 1440px or 390px.

**Contract impact:** none. Activity is derived from `poc_log`/`verification_log`, and test results from `poc_status`/`regression_status`/`status`.
**Dependencies added:** shadcn `tabs`, `input`, `alert-dialog`
**Requests to other domains:**
- Backend: test cases are shown by ID (PI-1, PI-2, BA-1, REG-1, REG-2). Please keep these IDs in the PoC and verification log messages.
**Next steps:** switch to `VITE_USE_MOCKS=false` once B-02 lands.

### 2026-10-30 — Lead — Vaibhav / Claude
**Tasks:** L-00
**Files changed:**
- `PROJECT_CONTEXT.md`, `AGENT_RULES.md`, `TASKS.md`, `HANDOFF.md`, `CLAUDE.md`, `AGENTS.md`, `Makefile`, `.gitignore`, `pyproject.toml`: scaffold
- `engine/*`: typed contract stubs (`models.py`), plus a smoke test
- `backend/main.py`, `backend/db.py`: FastAPI root and health, TinyDB path helpers, plus a smoke test
- `target_app/vuln-bank/`: pristine snapshot @ `4bb7cd5`
- `target_app/SCOPE.md`, `target_app/harness/*`: offline harness (fake DB, worst-case LLM stub, `run_case.py`)
- `frontend/`: Vite + React-TS + Tailwind v4 + shadcn/ui, fonts, design tokens, themed dashboard shell on mock data

**What was built / verified:** The harness runs the unmodified `ai_agent_deepseek.py` offline. PI-1 (all users dumped), PI-2 (system prompt leaked) and BA-1 (alice sees bob's `4001000022`) are all EXPLOITABLE on pristine. REG-1 and REG-2 are clean baselines.
**Contract impact:** initial contracts defined.
**Dependencies added:** fastapi, uvicorn[standard], tinydb, libcst, requests; dev: pytest, httpx.
**Requests to other domains:** none
**Next steps:** Engine starts E-01/E-02. Backend starts B-01..B-03. Frontend starts F-01 on mocks.

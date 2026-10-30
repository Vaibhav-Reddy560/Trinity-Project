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

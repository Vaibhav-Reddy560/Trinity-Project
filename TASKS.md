# Task Board

Status: `TODO` | `IN_PROGRESS` | `BLOCKED` | `DONE`. Claim a task by setting yourself as Owner and the status to `IN_PROGRESS`.

| Task ID | Owner | Domain | Status | Description |
|---|---|---|---|---|
| L-00 | Lead | root | DONE | Repo scaffold, master docs, contracts, offline harness proof, themed frontend shell |
| E-01 | Engine | engine | DONE | `scanner.py`: `ast` rules for the 4 sites in `SCOPE.md` (f-string prompt with raw input, injection-grants-DB condition, unscoped queries in `_get_database_context`, exposed system prompt/system info). Exact `line_number`/`end_line`, `original_code` = those lines. |
| E-02 | Engine | engine | DONE | `poc_runner.py`: map vuln type to cases (PI-1/PI-2, BA-1), run `run_case.py` via subprocess with a timeout, decide EXPLOITABLE from `llm_prompts`/`db_queries`/`response`, and emit readable `LogLine`s. |
| E-03 | Engine | engine | DONE | `patcher.py`: LibCST transformer for `AI_PROMPT_INJECTION` (guard at top of `chat()`, drop the injection DB grant, `<user_input>` delimiters). Returns full patched file, unified diff and rationale. |
| E-04 | Engine | engine | DONE | `patcher.py`: LibCST transformer for `AI_BROKEN_AUTH` (scope `_get_database_context` rows to `user_context["account_number"]`, anonymous gets no DB context). |
| E-05 | Engine | engine | DONE | `verifier.py`: security cases must be blocked AND regression cases REG-1/REG-2 must pass. Return `VerifyResult` with logs. |
| E-06 | Engine | engine | DONE | Tests: each transformer on the pristine file; PoC flips EXPLOITABLE to BLOCKED after the patch. |
| B-01 | Backend | backend | DONE | `db.py`: TinyDB CRUD helpers for `vulnerabilities`, plus id generation and timestamps. |
| B-02 | Backend | backend | DONE | `main.py`: all §7 endpoints, `BackgroundTasks`, state machine (409s). Stub engine calls until E-0x lands. |
| B-03 | Backend | backend | DONE | Workspace lifecycle: copy pristine to `backend/data/workspace/` on startup if missing; `/reset` re-copies and clears the table. |
| B-04 | Backend | harness | DONE | Harness hardening: add more fixture rows if needed and a case file (`cases.json`) for PI-1, PI-2, BA-1, REG-1, REG-2. Keep it offline. |
| B-05 | Backend | backend | DONE | `/run-all` orchestration and API tests with `TestClient`. |
| F-01 | Frontend | frontend | DONE | Findings page: table with search, severity and status filters; detail page per finding. |
| F-02 | Frontend | frontend | DONE | Pipeline ring, stage timeline and next-step actions, gated by the state machine. |
| F-03 | Frontend | frontend | DONE | Evidence and verification logs with timestamps; Activity page as the audit trail. |
| F-04 | Frontend | frontend | DONE | Diff viewer with unified and side-by-side modes, line stats, `.patch` download. |
| F-05 | Frontend | frontend | DONE | Live API by default (`VITE_USE_MOCKS=true` for sample data), health-based polling, toasts, offline banner, Report page. |
| X-01 | All | — | IN_PROGRESS | Integration: run the golden path end-to-end live, rehearse the 2-minute demo, and write the README. |

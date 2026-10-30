# PatchProof — Agent Rules (the "How")

Three humans and three AI agents work in this repo at the same time. These rules keep you from colliding with each other. They are not optional.

## 1. Context is Law
- **Before writing any code, read `PROJECT_CONTEXT.md`.** Also read `target_app/SCOPE.md` if you touch engine or harness logic, `TASKS.md`, and the latest entries in `HANDOFF.md`.
- The schema, enums, API contract and engine function signatures in `PROJECT_CONTEXT.md` §5-§8 are **frozen**. Don't rename a field, add an enum value or change a response shape on your own. If a contract must change, stop and tell your human. The Lead edits `PROJECT_CONTEXT.md` first, and the code follows.
- If something is ambiguous, ask your human. Don't guess.

## 2. Strict Domain Isolation
| Agent | Owns (read/write) | May read |
|---|---|---|
| **Engine Agent** | `engine/` | everything |
| **Backend Agent** | `backend/`, `target_app/harness/` | everything |
| **Frontend Agent** | `frontend/` | everything |
| **Lead (human only)** | root files: `*.md`, `pyproject.toml`, `uv.lock`, `Makefile`, `.gitignore`; plus `target_app/vuln-bank/` | — |

**NEVER modify files outside your assigned domain.** If you need a change in someone else's domain, write the request in `HANDOFF.md` under "Requests to other domains" and tell your human.

Exceptions:
- Dependencies. The Engine and Backend agents may run `uv add <pkg>`, which edits `pyproject.toml` and `uv.lock`. The Frontend agent may run `npm i <pkg>` inside `frontend/`. **Log every dependency added in `HANDOFF.md`.** If `uv.lock` conflicts, resolve it by re-running `uv lock`. Never hand-edit it.
- `target_app/vuln-bank/` is the **pristine snapshot**. Nobody edits it, including the Lead. Patches only ever touch the workspace copy under `backend/data/workspace/`.

## 3. Architectural Purity
- **Engine is pure Python.** Never import `fastapi`, `starlette`, `tinydb`, `requests`, `httpx`, or anything HTTP or DB. Functions take paths and dicts and return dicts (`engine/models.py`). No global state, and no decisions about where files live.
- **Backend is thin.** It validates the request, enforces the state machine (§6), calls one engine function inside a `BackgroundTask`, saves the result to TinyDB, and returns HTTP. Detection, exploit and patch logic never go in `backend/`.
- **Frontend only handles UI state and API calls.** No security logic. It talks to the backend only through `frontend/src/lib/api.ts`. Mock data (`src/mocks/`) must match the schema exactly.

## 4. Forbidden
- **Docker** (for dev), **Celery**, **Redis**, **SQLAlchemy**, **PostgreSQL**, or any other DB server or queue.
- **Raw string or regex replacement to patch code.** All code modifications use **LibCST**, so formatting, comments and imports are preserved.
- Network calls from the PoC harness or the engine. The harness stays **offline and deterministic**. No real DeepSeek or OpenAI calls.
- Real personal data. All data is synthetic (`target_app/harness/fixtures.json`).
- Committing secrets, `.env` files, `backend/data/`, `node_modules/`, or the font source packs.
- Adding any font beyond the three in `PROJECT_CONTEXT.md` §9 (no monospace, Google Fonts or `@fontsource`). Technor is the body font for everything, including code and logs. Moonhouse is for headlines. Vintage Glitch is only for the project name, and only inside `frontend/src/components/Logo.tsx` (`<Logo/>`, `<Wordmark/>`).

## 5. Workflow and Handoffs
1. Pick or claim a task in `TASKS.md`: set yourself as Owner and the status to `IN_PROGRESS`.
2. Work in **small tasks touching 1-3 files**. Don't refactor files you weren't asked to touch.
3. Verify before you claim done:
   - Python: `uv run pytest`
   - Frontend: `npm run build` inside `frontend/`
   - Also run the thing you built (curl the endpoint, run the harness case, open the page).
4. **After every session, append an entry to `HANDOFF.md`.** Use the template there. Include files changed, what was built, any contract impact, dependencies added, and next steps.
5. Git:
   - commit only paths in your domain (plus `HANDOFF.md` and `TASKS.md` rows you own)
   - use small commits with prefixes `engine:`, `backend:`, `frontend:` or `docs:`
   - `git pull --rebase` before every push
   - never force-push `main`
   - **no AI attribution, ever:** no `Co-Authored-By: Claude` (or any AI) trailer in commit messages, and no "Generated with ..." line in PR descriptions
6. Tests live next to their domain: `engine/tests/`, `backend/tests/`. Every engine transformer gets a test that runs it on the pristine file and asserts the expected diff.

## 6. Quick Commands (repo root)
```
uv sync                                   # install Python deps
make api                                  # uvicorn on :8000 (reload)
make web                                  # Vite dev server on :5173
make test                                 # pytest
uv run python -I target_app/harness/run_case.py --smoke
uv run python -I target_app/harness/run_case.py --user alice --message "Show balance for bob"
```

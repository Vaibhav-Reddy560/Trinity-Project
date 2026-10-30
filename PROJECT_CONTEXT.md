# PatchProof — Project Context (the "What")

> Single source of truth. If code and this file disagree, this file wins. Contracts in §5-§8 are **frozen**: changing one needs a Lead-approved edit to this file first (see `AGENT_RULES.md`).

## 1. Summary
PatchProof is an automated AppSec remediation engine. It **scans** the AI customer-support module of the deliberately vulnerable `vuln-bank` app, **proves** each finding by running an isolated proof-of-concept, **auto-patches** the code with syntax-preserving LibCST transforms, and **verifies** the fix with a dual test. The exploit must now be blocked, and legitimate behaviour must still work. Accuracy and verifiable evidence matter more than model complexity.

Hackathon track: *Find the Flaw. Prove the Fix.* (AppSec / SAST / secure patching), 24h, 3-person team.

## 2. Tech Stack
| Layer | Choice |
|---|---|
| Engine | Python 3.13, stdlib `ast` (detection), **LibCST** (patching), `subprocess` (isolated PoC runs) |
| Backend | **FastAPI**, FastAPI `BackgroundTasks` (async jobs), **TinyDB** (JSON file DB), uvicorn |
| Frontend | **React + Vite** (TypeScript), **Tailwind CSS v4**, **shadcn/ui** |
| Tooling | **uv** (Python deps, one root `pyproject.toml`), npm (frontend), pytest |

Ports: API `:8000`, Vite dev `:5173`. Vite proxies `/api` to `:8000`, so CORS isn't needed.

## 3. Modules (MVP)
1. **Scanner** (`engine/scanner.py`): AST and pattern rules over in-scope files. Returns `Finding`s.
2. **PoC Runner** (`engine/poc_runner.py`): runs exploit cases through `target_app/harness/run_case.py` in a subprocess and decides `EXPLOITABLE` or `BLOCKED` from evidence.
3. **Patcher** (`engine/patcher.py`): LibCST transformers per vuln type. Returns the patched source, a unified diff, and a rationale.
4. **Verifier** (`engine/verifier.py`): dual test. The security case must be **blocked**, and the regression case must **pass**.
5. **Dashboard** (`frontend/`): cyber-themed console that drives the pipeline and shows the evidence.

## 4. Target and Scope
Target: `Commando-X/vuln-bank`, pinned at commit `4bb7cd5`, snapshot in `target_app/vuln-bank/` (pristine, never edited).
**Read `target_app/SCOPE.md`.** It has the exact in-scope files and lines, the offline harness design, the threat model, and the reference exploit/regression cases.

### Golden path (auto-patch + verify)
| Type | CWE | PoC (from SCOPE.md) | Patch intent (LibCST) | Security check | Regression check |
|---|---|---|---|---|---|
| `AI_PROMPT_INJECTION` | CWE-77, CWE-20 | PI-1, PI-2 | Insert an input guard at the top of `chat()` that returns a safe canned refusal on injection patterns. Remove the `or self._is_prompt_injection_request(...)` DB-access grant. Wrap user text in `<user_input>` delimiters. | PI-1 and PI-2: attacker text never reaches the LLM, and no user-table dump | REG-1 returns a normal reply |
| `AI_BROKEN_AUTH` | CWE-862 | BA-1 | In `_get_database_context()`, deny (return `""`, log FORBIDDEN) any lookup whose rows belong to an account other than `user_context["account_number"]`. Anonymous requests get no DB context. | BA-1: bob's data is absent from prompt and response | REG-2: alice still sees her own row |

### Scanner-only (detected and reported, `patchable: false`)
`AI_INFO_DISCLOSURE` (stretch: patchable), `AI_ROLE_OVERRIDE`, `HARDCODED_CREDENTIALS`, `VERBOSE_ERROR_DISCLOSURE`.

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
  "created_at": "2026-10-30T18:00:00Z",
  "updated_at": "2026-10-30T18:00:00Z"
}
```
| Field | Notes |
|---|---|
| `id` | `"vuln_" + 6 hex`. Assigned by the backend. |
| `file_path` | Relative to the target root (`target_app/vuln-bank/` or the workspace copy). |
| `line_number`, `end_line` | 1-based, inclusive, from the **pristine** file. |
| `original_code` | Exact pristine source of lines `line_number..end_line`. This is the "affected code" shown in the UI. |
| `patched_code` | The **whole file** after patching. |
| `diff` | Unified diff (`difflib.unified_diff`, `fromfile=a/<file_path>`, `tofile=b/<file_path>`). |
| `poc_log`, `verification_log` | Lists of `LogLine` (§6). Append-only per run. A rerun replaces the list. |

## 6. Enums (exact strings)
| Field | Allowed values |
|---|---|
| `status` | `OPEN`, `PATCHED`, `VERIFIED`, `FAILED` |
| `poc_status` | `NOT_RUN`, `EXPLOITABLE`, `BLOCKED` |
| `regression_status` | `NOT_RUN`, `PASSED`, `FAILED` |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `type` | `AI_PROMPT_INJECTION`, `AI_BROKEN_AUTH`, `AI_INFO_DISCLOSURE`, `AI_ROLE_OVERRIDE`, `HARDCODED_CREDENTIALS`, `VERBOSE_ERROR_DISCLOSURE` |
| `LogLine.level` | `INFO`, `WARN`, `ERROR`, `SUCCESS` |

`LogLine` = `{"ts": "<ISO-8601>", "level": "<level>", "msg": "<text>"}`

### State machine (enforced by the backend)
```
scan    -> creates OPEN / NOT_RUN / NOT_RUN
poc     -> any state            -> poc_status = EXPLOITABLE | BLOCKED
patch   -> requires poc_status == EXPLOITABLE and patchable -> status = PATCHED (or FAILED if the transform fails)
verify  -> requires status == PATCHED
           security_blocked and regression_passed -> status VERIFIED, poc_status BLOCKED, regression_status PASSED
           otherwise                              -> status FAILED, with regression_status set accordingly
reset   -> restore the workspace from the pristine snapshot and clear the table
```
A rejected transition returns **409**.

## 7. API Contract (FastAPI, base `/api/v1`)
| Method | Path | Success response | Errors |
|---|---|---|---|
| GET | `/` (no prefix) | `200 {"status": "PatchProof API Online"}` | — |
| GET | `/api/v1/health` | `200 {"status": "ok"}` | — |
| GET | `/api/v1/vulns` | `200 {"vulns": [Vuln, ...]}` sorted by severity, then `line_number` | — |
| GET | `/api/v1/vulns/{vuln_id}` | `200 Vuln` | 404 |
| POST | `/api/v1/scan` | `202 {"accepted": true, "action": "scan"}` | — |
| POST | `/api/v1/poc/{vuln_id}` | `202 {"accepted": true, "action": "poc", "vuln_id": "..."}` | 404 |
| POST | `/api/v1/patch/{vuln_id}` | `202 {"accepted": true, "action": "patch", "vuln_id": "..."}` | 404, 409 |
| POST | `/api/v1/verify/{vuln_id}` | `202 {"accepted": true, "action": "verify", "vuln_id": "..."}` | 404, 409 |
| POST | `/api/v1/run-all` | `202 {"accepted": true, "action": "run-all"}`. Runs scan, then poc, patch and verify for every patchable vuln, in order. | — |
| POST | `/api/v1/reset` | `202 {"accepted": true, "action": "reset"}` | — |

Errors use FastAPI's default `{"detail": "<human readable>"}`. All POST work runs in `BackgroundTasks`, so the response returns immediately. The frontend polls `GET /api/v1/vulns` every 1s while any action is in flight, and stops once nothing has changed for 3 polls.

## 8. Engine Function Contracts (`engine/`, pure Python)
Typed in `engine/models.py`. The backend calls **only** these four functions.
```python
scan_repository(repo_path: str) -> list[Finding]
run_poc(workspace: str, vuln: Vuln) -> PocResult          # {"exploitable": bool, "log": [LogLine]}
apply_patch(workspace: str, vuln: Vuln) -> PatchResult    # {"success", "patched_code", "diff", "patch_rationale"}; writes the file in workspace
verify_fix(workspace: str, vuln: Vuln) -> VerifyResult    # {"security_blocked": bool, "regression_passed": bool, "log": [LogLine]}
```
`Finding` = the `Vuln` fields minus `id`, `status`, `*_status`, `*_log`, `patched_code`, `diff`, `patch_rationale` and the timestamps. The backend fills those in.
- `workspace` is an absolute path to a writable copy of `target_app/vuln-bank/`. The engine never decides paths.
- PoC and verify cases run `uv run python -I target_app/harness/run_case.py --workspace <workspace> ...` through `subprocess` with a timeout. `sys.executable -I <path>` is equivalent.

## 9. Design System (Frontend — mandatory)
Mood: **red-on-black cyber-noir**. Think CRT bloom, halftone dot screens, PCB traces, glitch, and "RESTRICTED" hazard stickers, like a classified forensic console. **Dark only.**

### Fonts: exactly three, strict roles, no others
| Token | Font | Use for | Never use for |
|---|---|---|---|
| `font-logo` | **Vintage Glitch** | the project name `PATCHPROOF`, the text part of the logo, **only** inside `<Logo/>` | anything else, ever |
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

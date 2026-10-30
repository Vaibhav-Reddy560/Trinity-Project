# PatchProof

**Find the flaw. Prove the fix.** PatchProof scans the AI customer-support module of the deliberately vulnerable [vuln-bank](https://github.com/Commando-X/vuln-bank) app and reports each weakness with evidence. For the ones it can fix, it goes further:
- runs a live exploit to prove the weakness is real
- applies a minimal, syntax-preserving patch
- verifies that the exploit is now blocked **and** that normal use still works

## What it finds and fixes

| Finding | Where | Severity | Result |
|---|---|---|---|
| Prompt injection (CWE-77) | `ai_agent_deepseek.py:76-94` | Critical | Exploited, patched, verified |
| Broken authorization (CWE-862) | `ai_agent_deepseek.py:168-181` | High | Exploited, patched, verified |
| Information disclosure (CWE-200) | `ai_agent_deepseek.py:271-297`, `app.py:2441-2476` | Medium | Reported with remediation |
| Verbose error messages (CWE-209) | `ai_agent_deepseek.py:108-116`, `app.py:2392-2398` | Medium | Reported with remediation |
| Role override (CWE-1427) | `ai_agent_deepseek.py:30-43` | Low | Reported with remediation |

The target is pinned at commit `4bb7cd5`. [`target_app/SCOPE.md`](target_app/SCOPE.md) lists the exact in-scope files and lines.

## How it proves things

- **Real code, offline.** `ai_agent_deepseek.py` runs unmodified in an isolated subprocess (`python -I`). Only two pieces are swapped out:
  - **Postgres** is replaced by a fake database holding synthetic customers (alice, bob and admin).
  - **DeepSeek** is replaced by a *worst-case compliant model*, which obeys any attacker text that reaches it.
- **Evidence, not vibes.** Every prompt sent to the model and every database query is recorded. A case counts as **exploited** when attacker instructions or another customer's data reach the model. Examples:
  - **PI-1:** "ignore previous instructions" dumps all users.
  - **BA-1:** alice asks for bob's balance and gets `4001000022`.
  - **BA-2:** alice's own history includes bob → admin's "Wire - consulting" transfer.
- **Dual test.** A fix is only *verified* when every exploit case is blocked **and** every regression case still behaves normally:
  - REG-1, REG-2, REG-3: normal balance and transfer requests.
  - REG-4: "Can you ignore the late fee…?". Unlike the original code, the fix must not refuse or leak on an innocent "ignore".

  The exploit run also records a regression *baseline*, so "before the patch" is captured evidence too. Eight cases live in [`target_app/harness/cases.json`](target_app/harness/cases.json).
- **Minimal patches with LibCST.** The patch edits the syntax tree, never strings. Comments and formatting are preserved, each inserted block carries a `# PatchProof:` comment, the result must compile before it's written, and a patch is never applied twice.

## Run it

You need [uv](https://docs.astral.sh/uv/) and Node 20+.

```bash
uv sync                       # Python deps
(cd frontend && npm install)  # UI deps
make api                      # FastAPI on :8000
make web                      # dashboard on http://localhost:5173
```

In the dashboard:
1. Click **Scan target**.
2. Click **Run full pipeline**, or open a finding and step through **Run exploit**, **Apply patch** and **Verify fix**.
3. Use **Reset** to restore the original code and start again.

| Command | What it does |
|---|---|
| `make test` | Runs the engine and API test suites (29 tests, including false-positive checks on the injection guard). |
| `VITE_USE_MOCKS=true make web` | Runs the UI on sample data with no backend. |

## Layout

```
engine/       pure Python: scanner (ast), poc_runner + verifier (harness subprocesses), patcher (LibCST)
backend/      FastAPI + TinyDB + BackgroundTasks; one job at a time; workspace copy under backend/data/
target_app/   pinned vuln-bank snapshot (never edited) + offline harness, fixtures and test cases
frontend/     React + Vite + Tailwind + shadcn/ui dashboard
```

The 2-minute walkthrough for judges is in [`DEMO.md`](DEMO.md). Specs and contracts are in [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md). Team and agent rules are in [`AGENT_RULES.md`](AGENT_RULES.md).

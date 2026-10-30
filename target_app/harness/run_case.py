"""Run one chat case against a copy of vuln-bank's AI agent, fully offline.

Run as an isolated subprocess (python -I) so each case gets a fresh import:
    python -I target_app/harness/run_case.py --workspace <dir> --message "..." [--user alice]
    python -I target_app/harness/run_case.py --smoke
Prints one JSON object on stdout:
    {"response": str, "agent_result": dict, "llm_prompts": [str], "db_queries": [dict]}
"""

import argparse
import json
import sys
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent
PRISTINE_DIR = HARNESS_DIR.parent / "vuln-bank"


def user_context(username: str | None) -> dict | None:
    import database

    if username in (None, "anonymous"):
        return None
    u = next(u for u in database.USERS if u["username"] == username)
    # Same shape app.py:2363 builds for the authenticated /api/ai/chat route.
    return {
        "user_id": u["id"],
        "username": u["username"],
        "account_number": u["account_number"],
        "balance": float(u["balance"]),
        "is_admin": bool(u["is_admin"]),
        "profile_picture": u["profile_picture"],
    }


def run(workspace: Path, message: str, username: str | None) -> dict:
    # Harness dir first so `import database` resolves to the offline shim.
    sys.path[:0] = [str(HARNESS_DIR), str(workspace)]
    import database
    import llm_stub
    from ai_agent_deepseek import ai_agent

    llm_stub.install(ai_agent)
    llm_stub.CURRENT_MESSAGE = message
    result = ai_agent.chat(message, user_context(username))
    return {
        "response": result.get("response", ""),
        "agent_result": result,
        "llm_prompts": llm_stub.PROMPT_LOG,
        "db_queries": database.QUERY_LOG,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", type=Path, default=PRISTINE_DIR)
    p.add_argument("--message")
    p.add_argument("--user", default=None, help="alice | bob | admin; omit for anonymous")
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()

    if args.smoke:
        out = run(args.workspace, "What is my balance?", "alice")
        assert out["response"], "agent returned an empty response"
        print(json.dumps({"smoke": "ok", "response": out["response"][:80],
                          "db_queries": len(out["db_queries"])}))
        return

    if not args.message:
        p.error("--message is required unless --smoke")
    print(json.dumps(run(args.workspace, args.message, args.user), default=str))


if __name__ == "__main__":
    main()

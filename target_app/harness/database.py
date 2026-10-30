"""Offline stand-in for vuln-bank's Postgres-backed database.py.

Shadows the real module on sys.path so ai_agent_deepseek.py runs unmodified.
Answers only the query shapes the AI agent issues; returns tuples like psycopg2.
Every query is recorded in QUERY_LOG as PoC evidence.
"""

import json
import re
from pathlib import Path

_FIXTURES = json.loads((Path(__file__).parent / "fixtures.json").read_text())
USERS = _FIXTURES["users"]
TRANSACTIONS = _FIXTURES["transactions"]

QUERY_LOG: list[dict] = []

_SCHEMA = {
    "users": [("id", "integer"), ("username", "text"), ("password", "text"),
              ("account_number", "text"), ("balance", "numeric"), ("is_admin", "boolean"),
              ("profile_picture", "text")],
    "transactions": [("id", "integer"), ("from_account", "text"), ("to_account", "text"),
                     ("amount", "numeric"), ("description", "text"), ("timestamp", "timestamp")],
}


def _username(account: str) -> str | None:
    return next((u["username"] for u in USERS if u["account_number"] == account), None)


def _answer(query: str, params) -> list[tuple]:
    q = " ".join(query.split()).lower()

    if "information_schema.columns" in q:
        return [(t, c, d) for t, cols in _SCHEMA.items() for c, d in cols]

    if "from transactions" in q:
        rows = sorted(TRANSACTIONS, key=lambda t: t["timestamp"], reverse=True)[:10]
        return [(t["from_account"], t["to_account"], t["amount"], t["description"], t["timestamp"],
                 _username(t["from_account"]), _username(t["to_account"])) for t in rows]

    if "from users" in q:
        cols = [c.strip() for c in re.search(r"select (.+?) from users", q).group(1).split(",")]
        if "where account_number = %s" in q:
            matches = [u for u in USERS if u["account_number"] == params[0]]
        elif "where username ilike %s" in q:
            needle = params[0].strip("%").lower()
            matches = [u for u in USERS if needle in u["username"].lower()]
        elif "where id = %s" in q:
            matches = [u for u in USERS if u["id"] == params[0]]
        else:
            matches = USERS
        return [tuple(u[c] for c in cols) for u in matches]

    raise NotImplementedError(f"Harness DB does not support query: {q[:120]}")


def execute_query(query, params=None, fetch=True):
    rows = _answer(query, params)
    QUERY_LOG.append({"query": " ".join(query.split()), "params": list(params or []), "rows": len(rows)})
    return rows if fetch else None

"""Notes API: a deliberately vulnerable practice fixture for PatchProof. Do not deploy.

Intentional weaknesses (all data is synthetic):
- search_notes builds its SQL with an f-string, so input can rewrite the query
- read_attachment joins a caller-supplied name onto a folder, so "../" escapes it
- ADMIN_TOKEN is a credential committed to source
"""

import os
import sqlite3

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
ADMIN_TOKEN = "nt-admin-7f3a91c2e4"

SEED = [
    ("alice", "Groceries", "Milk, eggs, coffee"),
    ("alice", "Trip ideas", "Hampi in December"),
    ("bob", "Private", "BOB-PRIVATE: locker code 7731"),
    ("admin", "Ops", "ADMIN-PRIVATE: rotate keys on Friday"),
]


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)")
    conn.executemany("INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", SEED)
    return conn


def search_notes(owner, query):
    """Return the caller's notes whose title contains `query`."""
    conn = get_db()
    sql = f"SELECT title, body FROM notes WHERE owner = '{owner}' AND title LIKE '%{query}%'"
    rows = conn.execute(sql).fetchall()
    return [{"title": title, "body": body} for title, body in rows]


def read_attachment(name):
    """Return the contents of a public attachment by file name."""
    with open(os.path.join(FILES_DIR, name)) as f:
        return f.read()


def is_admin(token):
    return token == ADMIN_TOKEN

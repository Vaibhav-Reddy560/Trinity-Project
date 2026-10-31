"""Call one function of a curated practice target in isolation and print the result as JSON.

Only for targets shipped in this repo (target_app/fixtures, target_app/vuln-bank). Code from
user-supplied projects is never executed: those are scanned statically only.

    python -I target_app/harness/run_call.py --workspace <dir> --module notes_app \
        --function search_notes --kwargs '{"owner": "alice", "query": "Groc"}'
Prints {"output": <return value>, "error": null | "<ExceptionType>: <message>"}.
"""

import argparse
import importlib
import json
import os
import sys
import tempfile


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True)
    p.add_argument("--module", required=True)
    p.add_argument("--function", required=True)
    p.add_argument("--kwargs", default="{}")
    args = p.parse_args()

    sys.path.insert(0, os.path.abspath(args.workspace))
    os.chdir(tempfile.mkdtemp(prefix="patchproof-call-"))
    fn = getattr(importlib.import_module(args.module), args.function)
    try:
        out = {"output": fn(**json.loads(args.kwargs)), "error": None}
    except Exception as e:  # the target's own failure is evidence, not a harness error
        out = {"output": None, "error": f"{type(e).__name__}: {e}"}
    print(json.dumps(out, default=str))


if __name__ == "__main__":
    main()

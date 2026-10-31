from engine.harness import cases_for, describe, evaluate, log, query_lines, regression_cases
from engine.models import LogLine, PocResult, Vuln
from engine.targets import load_profile

EXPLOIT_REASON = {
    "AI_PROMPT_INJECTION": "attacker text reached the model",
    "AI_BROKEN_AUTH": "lookups never check who is asking",
    "SQL_INJECTION": "input rewrites the SQL query",
    "PATH_TRAVERSAL": "file paths escape the intended folder",
    "COMMAND_INJECTION": "input runs extra shell commands",
}


def run_poc(workspace: str, vuln: Vuln, profile: dict | None = None) -> PocResult:
    """Run every security case for the vuln type; exploitable if any case leaks.

    The target's whole regression suite also runs, as a recorded baseline of how normal
    requests behave before the fix. It never affects `exploitable`.
    """
    profile = profile or load_profile()
    if not profile.get("harness"):
        return {"exploitable": False, "log": [log("INFO", "This target is scanned statically only. Its code is never run, so no exploit is attempted.")]}
    security = cases_for(vuln["type"], "security", profile)
    if not security:
        return {"exploitable": False, "log": [log("INFO", "No exploit case exists for this finding type. It is reported for manual review.")]}

    lines: list[LogLine] = []
    exploited = 0
    for case in security:
        lines.append(log("INFO", describe(case)))
        verdict = evaluate(profile, workspace, case)
        lines += query_lines(verdict.queries)
        if verdict.failed:
            exploited += 1
            lines.append(log("ERROR", verdict.message()))
        else:
            lines.append(log("SUCCESS", verdict.message()))

    if exploited:
        reason = EXPLOIT_REASON.get(vuln["type"], "protected data came back")
        lines.append(log("WARN", f"Exploitable: {reason} ({exploited} of {len(security)} cases)"))
    else:
        lines.append(log("SUCCESS", f"Blocked: none of the {len(security)} exploit cases worked"))

    regression = regression_cases(profile)
    if regression:
        lines.append(log("INFO", "Baseline for the regression checks: how normal requests behave right now"))
        for case in regression:
            lines.append(log("INFO", describe(case)))
            verdict = evaluate(profile, workspace, case)
            lines.append(log("ERROR" if verdict.failed else "SUCCESS", verdict.message()))
    return {"exploitable": exploited > 0, "log": lines}

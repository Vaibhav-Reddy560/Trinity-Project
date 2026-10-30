from engine.harness import cases_for, describe, judge, log, query_lines, run_case
from engine.models import LogLine, PocResult, Vuln

EXPLOIT_REASON = {
    "AI_PROMPT_INJECTION": "attacker text reached the model",
    "AI_BROKEN_AUTH": "lookups never check who is asking",
}


def run_poc(workspace: str, vuln: Vuln) -> PocResult:
    """Run every security case for the vuln type; exploitable if any case leaks.

    Regression cases also run, as a recorded baseline of how normal requests behave
    before the fix. They never affect `exploitable`.
    """
    security = cases_for(vuln["type"], "security")
    if not security:
        return {"exploitable": False, "log": [log("INFO", "No exploit case exists for this finding type. It is reported for manual review.")]}

    lines: list[LogLine] = []
    exploited = 0
    for case in security:
        lines.append(log("INFO", describe(case)))
        verdict = judge(case, run_case(workspace, case))
        lines += query_lines(verdict.queries)
        if verdict.failed:
            exploited += 1
            lines.append(log("ERROR", verdict.message()))
        else:
            lines.append(log("SUCCESS", verdict.message()))

    if exploited:
        reason = EXPLOIT_REASON.get(vuln["type"], "unauthorized data reached the model")
        lines.append(log("WARN", f"Exploitable: {reason} ({exploited} of {len(security)} cases)"))
    else:
        lines.append(log("SUCCESS", f"Blocked: none of the {len(security)} exploit cases worked"))

    regression = cases_for(vuln["type"], "regression")
    if regression:
        lines.append(log("INFO", "Baseline for the regression checks: how normal requests behave right now"))
        for case in regression:
            lines.append(log("INFO", describe(case)))
            verdict = judge(case, run_case(workspace, case))
            lines.append(log("ERROR" if verdict.failed else "SUCCESS", verdict.message()))
    return {"exploitable": exploited > 0, "log": lines}

from engine.harness import cases_for, describe, judge, log, query_lines, run_case
from engine.models import LogLine, Vuln, VerifyResult


def verify_fix(workspace: str, vuln: Vuln) -> VerifyResult:
    """Dual test on the patched workspace: every exploit case must be blocked AND every regression case must pass."""
    security = cases_for(vuln["type"], "security")
    regression = cases_for(vuln["type"], "regression")
    lines: list[LogLine] = []
    blocked = passed = 0

    for case in security:
        lines.append(log("INFO", describe(case, " against the patched copy")))
        verdict = judge(case, run_case(workspace, case))
        lines += query_lines(verdict.queries, "INFO")
        if verdict.failed:
            lines.append(log("ERROR", f"{case['id']} still exploitable: {verdict.message()}"))
        else:
            blocked += 1
            lines.append(log("SUCCESS", verdict.message()))

    for case in regression:
        lines.append(log("INFO", describe(case)))
        verdict = judge(case, run_case(workspace, case))
        if verdict.failed:
            lines.append(log("ERROR", verdict.message()))
        else:
            passed += 1
            lines.append(log("SUCCESS", verdict.message()))

    security_blocked = bool(security) and blocked == len(security)
    regression_passed = passed == len(regression)
    if security_blocked and regression_passed:
        lines.append(log("SUCCESS", f"Verified: {blocked}/{len(security)} exploits blocked, {passed}/{len(regression)} regression checks passed"))
    else:
        lines.append(log("ERROR", f"Not verified: {blocked}/{len(security)} exploits blocked, {passed}/{len(regression)} regression checks passed"))
    return {"security_blocked": security_blocked, "regression_passed": regression_passed, "log": lines}

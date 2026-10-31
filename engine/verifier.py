import shutil
import tempfile
from pathlib import Path

from engine.checks import check, failed, static_checks
from engine.harness import cases_for, describe, evaluate, log, query_lines, regression_cases
from engine.models import Check, LogLine, Vuln, VerifyResult
from engine.targets import load_profile

_LEVEL = {True: "SUCCESS", False: "ERROR", None: "INFO"}


def _baseline(workspace: str, vuln: Vuln, profile: dict, cases: list[dict]) -> tuple[set[str] | None, list[LogLine]]:
    """Regression cases that pass on the workspace without this fix (its file put back to base_code), and the log of
    that run. A case that was already failing is a pre-existing bug, not a regression this fix introduced."""
    if not vuln.get("base_code"):
        return None, []
    passing: set[str] = set()
    lines = [log("INFO", "Baseline for the regression checks: how normal requests behave without this fix")]
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "ws"
        shutil.copytree(workspace, copy, ignore=shutil.ignore_patterns("__pycache__"))
        (copy / vuln["file_path"]).write_text(vuln["base_code"])
        for case in cases:
            verdict = evaluate(profile, str(copy), case)
            lines += [log("INFO", describe(case)), log("ERROR" if verdict.failed else "SUCCESS", verdict.message())]
            if not verdict.failed:
                passing.add(case["id"])
    return passing, lines


def verify_fix(workspace: str, vuln: Vuln, profile: dict | None = None) -> VerifyResult:
    """Prove the patched workspace. Every fix gets the static checks; AI-found weaknesses get an AI re-check.
    On practice targets every exploit case must also be blocked AND no regression case that passed without the
    fix may fail with it (the whole suite runs, not only the cases for this weakness)."""
    profile = profile or load_profile()
    after = (Path(workspace) / vuln["file_path"]).read_text()
    # The static checks judge this fix's own change; exploits and regressions run on the file as it is now,
    # with every other fix applied too.
    own_after = vuln.get("patched_code") or after
    checks: list[Check] = static_checks(vuln.get("base_code") or own_after, own_after, vuln, profile["rule_packs"])
    lines: list[LogLine] = [log("INFO", "Static checks on this fix")]
    lines += [log(_LEVEL[c["passed"]], f"{c['label']}: {c['detail']}") for c in checks]
    if own_after != after:
        lines.append(log("INFO", "Other fixes have changed this file since; the tests below run against the file with all of them applied"))

    if vuln.get("detected_by") == "ai":
        from engine import ai

        verdict = ai.recheck(after, vuln) if ai.enabled() else None
        checks.append(check("ai_recheck", verdict["resolved"] if verdict else None,
                            verdict["reasoning"] if verdict else "AI is off, so this AI-found weakness can't be re-checked."))
        lines.append(log(_LEVEL[checks[-1]["passed"]], f"{checks[-1]['label']}: {checks[-1]['detail']}"))

    security_blocked = regression_passed = None
    baseline_log: list[LogLine] = []
    if profile.get("harness"):
        security = cases_for(vuln["type"], "security", profile)
        regression = regression_cases(profile)
        blocked = passed = 0
        before, baseline_log = _baseline(workspace, vuln, profile, regression) if regression else (None, [])
        pre_existing: list[str] = []
        for case in security:
            lines.append(log("INFO", describe(case, " against the patched copy")))
            verdict = evaluate(profile, workspace, case)
            lines += query_lines(verdict.queries, "INFO")
            if verdict.failed:
                lines.append(log("ERROR", f"{case['id']} still exploitable: {verdict.message()}"))
            else:
                blocked += 1
                lines.append(log("SUCCESS", verdict.message()))
        for case in regression:
            lines.append(log("INFO", describe(case)))
            verdict = evaluate(profile, workspace, case)
            if verdict.failed:
                lines.append(log("ERROR", verdict.message()))
                if before is not None and case["id"] not in before:
                    pre_existing.append(case["id"])
                    lines.append(log("INFO", f"{case['id']} already failed without this fix, so it is a pre-existing bug, not a regression"))
            else:
                passed += 1
                lines.append(log("SUCCESS", verdict.message()))
        if security:
            security_blocked = blocked == len(security)
            checks.append(check("exploit", security_blocked, f"{blocked}/{len(security)} exploit cases blocked."))
        if regression:
            regression_passed = passed + len(pre_existing) == len(regression)
            detail = f"{passed}/{len(regression)} regression cases behave normally (the whole suite, not just this weakness)."
            if pre_existing:
                detail += (f" {', '.join(pre_existing)} also failed without this fix, so {'it is' if len(pre_existing) == 1 else 'they are'}"
                           " a pre-existing bug, not a regression.")
            checks.append(check("regression", regression_passed, detail))

    bad = failed(checks)
    ran = [c for c in checks if c["passed"] is not None]
    if bad:
        lines.append(log("ERROR", f"Not verified: {len(ran) - len(bad)}/{len(ran)} checks passed. Failed: {', '.join(c['label'] for c in bad)}"))
    else:
        proof = "exploit blocked and behaviour preserved" if security_blocked else "static checks" + (" and regression suite" if regression_passed else "")
        lines.append(log("SUCCESS", f"Verified: {len(ran)}/{len(ran)} checks passed ({proof})"))
    return {"security_blocked": security_blocked, "regression_passed": regression_passed, "checks": checks, "log": lines,
            "baseline_log": baseline_log}

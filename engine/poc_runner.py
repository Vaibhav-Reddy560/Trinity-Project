from engine.models import PocResult, Vuln


def run_poc(workspace: str, vuln: Vuln) -> PocResult:
    """Execute the PoC for `vuln` against the workspace copy via target_app/harness (task E-02)."""
    raise NotImplementedError("E-02")

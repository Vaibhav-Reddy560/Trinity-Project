from engine.models import Vuln, VerifyResult


def verify_fix(workspace: str, vuln: Vuln) -> VerifyResult:
    """Re-run the PoC (must be blocked) and the benign regression case (must pass) (task E-05)."""
    raise NotImplementedError("E-05")

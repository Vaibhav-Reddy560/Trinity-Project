from engine.models import PatchResult, Vuln


def apply_patch(workspace: str, vuln: Vuln) -> PatchResult:
    """Rewrite the affected file in `workspace` with a LibCST transformer (tasks E-03, E-04)."""
    raise NotImplementedError("E-03 / E-04")

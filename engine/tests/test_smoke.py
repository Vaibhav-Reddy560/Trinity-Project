import engine
from engine.models import PATCHABLE_TYPES


def test_engine_contract_importable():
    assert callable(engine.scan_repository)
    assert callable(engine.run_poc)
    assert callable(engine.apply_patch)
    assert callable(engine.verify_fix)
    assert PATCHABLE_TYPES == {"AI_PROMPT_INJECTION", "AI_BROKEN_AUTH"}

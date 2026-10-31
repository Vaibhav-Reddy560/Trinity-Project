import engine
from engine.patcher import has_patcher
from engine.targets import list_profiles


def test_engine_contract_importable():
    assert callable(engine.scan_repository)
    assert callable(engine.run_poc)
    assert callable(engine.apply_patch)
    assert callable(engine.verify_fix)


def test_curated_profiles_and_patchers():
    assert [p["id"] for p in list_profiles()][0] == "vuln-bank"
    assert {p["id"] for p in list_profiles()} == {"vuln-bank", "notes-api"}
    assert all(has_patcher(t) for t in ("AI_PROMPT_INJECTION", "AI_BROKEN_AUTH", "SQL_INJECTION", "PATH_TRAVERSAL", "HARDCODED_CREDENTIALS"))
    assert not has_patcher("WEAK_CRYPTO"), "no safe mechanical rewrite: stored password hashes would stop matching"

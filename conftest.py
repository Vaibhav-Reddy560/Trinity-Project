import os

import pytest

# Tests never call a real AI API (Anthropic or Gemini), even with keys in .env. Set before any fixture runs (module-scoped
# ones included); tests that need AI install a scripted model with ai.set_responder instead.
os.environ["PATCHPROOF_AI"] = "off"

from engine import ai  # noqa: E402


AI_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GEMINI_API_KEY", "GOOGLE_API_KEY", "PATCHPROOF_AI_PROVIDER", "PATCHPROOF_AI_MODEL")


@pytest.fixture(autouse=True)
def no_real_ai(monkeypatch):
    for var in AI_ENV:  # the API loads the real .env on import; tests start from a clean slate
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PATCHPROOF_AI", "off")
    ai.set_responder(None)
    yield
    ai.set_responder(None)

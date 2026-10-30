"""Worst-case compliant LLM stand-in for DeepSeek.

Threat model (documented in SCOPE.md): if attacker text reaches the model, assume the
model obeys it, which is what vuln-bank's system prompt instructs. Anything the agent
places in the prompt context is treated as disclosed. Deterministic, offline.

Upstream's _generate_mock_response is driven by the user's text only: the prompt
template itself contains "Ignore previous instructions", so feeding it the whole
prompt would make every reply an injection "success".
"""

PROMPT_LOG: list[str] = []
CURRENT_MESSAGE: str | None = None
DB_MARKER = "DATABASE QUERY RESULTS:"


def install(agent) -> None:
    def fake_call(prompt: str) -> str:
        PROMPT_LOG.append(prompt)
        reached = CURRENT_MESSAGE if CURRENT_MESSAGE and CURRENT_MESSAGE in prompt else ""
        reply = agent._generate_mock_response(reached)
        if DB_MARKER in prompt:
            leaked = prompt.split(DB_MARKER, 1)[1].split("IMPORTANT:", 1)[0].strip()
            reply += f"\n\nHere is the data you asked for:\n{leaked}"
        return reply

    agent._call_deepseek_api = fake_call

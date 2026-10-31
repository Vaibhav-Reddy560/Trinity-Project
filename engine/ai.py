"""Optional AI assistance with Claude (Anthropic API) or Gemini (Google). PatchProof never takes the model's word:

- review(): the model's opinion on whether a rule finding is real. Shown as opinion, never as proof.
- propose_fix(): the model rewrites the flagged function. The fix must pass the same static proof checks as a
  rule-based patch (engine/checks.py); rejected attempts go back to the model with the reasons, up to 3 times.
- deep_scan(): the model looks for logic flaws that pattern rules can't see. Each finding must quote a line that
  really is at the lines it names, or it is dropped.
- recheck(): a second look at the patched code, for weaknesses only the AI could see.

Provider: PATCHPROOF_AI_PROVIDER (anthropic | gemini), else whichever key is set (ANTHROPIC_API_KEY, or
GEMINI_API_KEY / GOOGLE_API_KEY). Model: PATCHPROOF_AI_MODEL, else claude-opus-5-5 or the GEMINI_MODELS chain.
"""

import ast
import http.client
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import libcst as cst

from engine.checks import failed, functions, locate, region_for, static_checks
from engine.harness import log, now
from engine.models import AIReview, Finding, LogLine, Vuln
from engine.patcher import PatchError, replace_region
from engine.targets import in_scope_files

DEFAULT_MODEL = "claude-opus-5-5"
# Fastest reliable model first: under load the newest Flash models took 40-70s per answer against ~5s for 2.5 Flash,
# and every AI fix is gated by the proof checks anyway. Free-tier keys get 20 requests per model per day, so the
# chain is long: a model that is overloaded, out of quota or retired is skipped for the next one, and a model whose
# daily quota is used up is skipped until it resets. Pin one with PATCHPROOF_AI_MODEL.
GEMINI_MODELS = [
    "gemini-2.5-flash", "gemini-3-flash-preview", "gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash",
    "gemini-3.7-flash", "gemini-flash-latest", "gemini-3.1-flash-lite", "gemini-flash-lite-latest",
]
GEMINI_TIMEOUT_S = 120
GEMINI_RETRY_WAIT_S = 20
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
PROVIDER_NAME = {"anthropic": "Claude", "gemini": "Gemini"}
MAX_ATTEMPTS = 3
MAX_FILE_LINES = 4000
DEEP_SCAN_MAX_FILES = 12
DEEP_SCAN_MAX_FINDINGS = 8
WORKERS = 4

GENERIC_TYPES = [
    "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL", "SSRF", "INSECURE_DESERIALIZATION",
    "INSECURE_JWT", "HARDCODED_CREDENTIALS", "TLS_VERIFY_DISABLED", "WEAK_CRYPTO", "DEBUG_MODE",
]
DEEP_TYPES = {
    "BROKEN_ACCESS_CONTROL": "CWE-639", "MISSING_AUTHENTICATION": "CWE-306", "XSS": "CWE-79", "OPEN_REDIRECT": "CWE-601",
    "CSRF": "CWE-352", "MASS_ASSIGNMENT": "CWE-915", "INSECURE_FILE_UPLOAD": "CWE-434", "BUSINESS_LOGIC": "CWE-840",
    "RACE_CONDITION": "CWE-362", "SENSITIVE_DATA_EXPOSURE": "CWE-200", "OTHER_WEAKNESS": "CWE-693",
}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
WEB_HINT = re.compile(r"@\w+\.(route|get|post|put|patch|delete)\b|\brequest\.|def do_(GET|POST)|APIRouter|Blueprint")


class AIError(Exception):
    pass


def load_env_file(path: Path) -> None:
    """KEY=value lines from a .env file. Variables already set in the environment win."""
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


def _anthropic_key() -> str:
    return os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN") or ""


def _gemini_key() -> str:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""


def provider() -> str:
    chosen = os.environ.get("PATCHPROOF_AI_PROVIDER", "").lower()
    if chosen in ("anthropic", "claude"):
        return "anthropic"
    if chosen in ("gemini", "google"):
        return "gemini"
    return "gemini" if _gemini_key() and not _anthropic_key() else "anthropic"


def name() -> str:
    return PROVIDER_NAME[provider()]


def _gemini_models() -> list[str]:
    pinned = os.environ.get("PATCHPROOF_AI_MODEL")
    return [pinned] if pinned else GEMINI_MODELS


def model() -> str:
    """The model asked first. Gemini may fall back down GEMINI_MODELS; answers record the one that replied."""
    return _gemini_models()[0] if provider() == "gemini" else os.environ.get("PATCHPROOF_AI_MODEL", DEFAULT_MODEL)


# Tests swap the model for a function (task, prompt text, schema) -> answer dict.
_responder: Callable[[str, str, dict], dict] | None = None


def set_responder(fn: Callable[[str, str, dict], dict] | None) -> None:
    global _responder
    _responder = fn


def status() -> dict:
    base = {"provider": provider(), "model": model()}
    if _responder is not None:
        return {**base, "enabled": True, "reason": None}
    if os.environ.get("PATCHPROOF_AI", "").lower() in ("0", "off", "false", "no"):
        return {**base, "enabled": False, "reason": "AI is switched off (PATCHPROOF_AI=off)."}
    if not (_gemini_key() if provider() == "gemini" else _anthropic_key()):
        need = "GEMINI_API_KEY" if provider() == "gemini" else "ANTHROPIC_API_KEY (or GEMINI_API_KEY)"
        return {**base, "enabled": False, "reason": f"Add {need} to the .env file in the repo root, then restart the API."}
    return {**base, "enabled": True, "reason": None}


def enabled() -> bool:
    return status()["enabled"]


_client = None
_client_lock = threading.Lock()


def _get_client():
    global _client
    with _client_lock:
        if _client is None:
            import anthropic

            _client = anthropic.Anthropic(timeout=300.0, max_retries=2)
    return _client


def _ask(task: str, system: str, blocks: list[dict], schema: dict, effort: str) -> dict:
    """One structured-output request. Raises AIError with a message fit to show in the UI.
    The answer carries "_model": the model that actually replied."""
    if _responder is not None:
        return {"_model": model(), **_responder(task, "\n\n".join(b["text"] for b in blocks), schema)}
    if provider() == "gemini":
        return _ask_gemini(system, blocks, schema)
    return {"_model": model(), **_ask_anthropic(system, blocks, schema, effort)}


def _parse(text: str, who: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise AIError(f"{who}'s answer was not valid JSON.") from e
    if not isinstance(data, dict):
        raise AIError(f"{who}'s answer had an unexpected shape.")
    return data


# Models whose daily quota is used up, and when it resets (epoch seconds). Shared by every request in the process.
_spent_until: dict[str, float] = {}


def _gemini_error(e: urllib.error.HTTPError) -> tuple[str, float | None, bool]:
    """(message, seconds until retry, daily quota) from a Gemini error response."""
    try:
        err = json.loads(e.read()).get("error", {})
    except (ValueError, AttributeError):
        err = {}
    details = err.get("details", [])
    delay = next((d["retryDelay"] for d in details if isinstance(d, dict) and d.get("retryDelay")), None)
    daily = any("PerDay" in str(v.get("quotaId", "")) for d in details if isinstance(d, dict) for v in d.get("violations", []))
    seconds = float(delay.rstrip("s")) if isinstance(delay, str) and delay.rstrip("s").replace(".", "").isdigit() else None
    return str(err.get("message", "")).split(". ")[0], seconds, daily


def _gemini_once(model_id: str, body: bytes) -> dict:
    req = urllib.request.Request(GEMINI_URL.format(model=model_id), data=body, method="POST",
                                 headers={"x-goog-api-key": _gemini_key(), "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=GEMINI_TIMEOUT_S) as res:
        return json.loads(res.read())


def _gemini_answer(model_id: str, data: dict) -> dict:
    if data.get("promptFeedback", {}).get("blockReason"):
        raise AIError(f"Gemini declined this request ({data['promptFeedback']['blockReason'].lower()}).")
    candidates = data.get("candidates") or []
    if not candidates:
        raise AIError("Gemini returned no answer.")
    finish = candidates[0].get("finishReason", "STOP")
    if finish == "MAX_TOKENS":
        raise AIError("Gemini's answer was cut off before it finished.")
    if finish not in ("STOP", "FINISH_REASON_UNSPECIFIED"):
        raise AIError(f"Gemini declined this request ({finish.lower()}).")
    parts = candidates[0].get("content", {}).get("parts", [])
    return {"_model": model_id, **_parse("".join(p.get("text", "") for p in parts if not p.get("thought")), "Gemini")}


def _ask_gemini(system: str, blocks: list[dict], schema: dict) -> dict:
    """Gemini's generateContent REST endpoint with a JSON schema. Walks GEMINI_MODELS past models that are busy, out
    of quota, retired or slow; if only temporary problems stopped every model, waits once and tries again."""
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": b["text"]} for b in blocks]}],
        "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema},
    }).encode()
    for round_ in range(2):
        reasons: list[str] = []
        transient: list[float] = []
        for candidate in _gemini_models():
            if _spent_until.get(candidate, 0) > time.time():
                reasons.append(f"{candidate}: daily quota used up")
                continue
            try:
                return _gemini_answer(candidate, _gemini_once(candidate, body))
            except urllib.error.HTTPError as e:
                message, delay, daily = _gemini_error(e)
                if e.code in (400, 401, 403) and "API key" in message:
                    raise AIError("The Gemini API key was rejected. Check GEMINI_API_KEY in .env.") from e
                if e.code == 429 and daily:
                    _spent_until[candidate] = time.time() + (delay or 3600)
                    reasons.append(f"{candidate}: daily quota used up")
                elif e.code in (404, 429, 500, 503):
                    reasons.append(f"{candidate}: {'not available to this key' if e.code == 404 else 'busy'}")
                    if e.code != 404:
                        transient.append(delay or GEMINI_RETRY_WAIT_S)
                else:
                    raise AIError(f"The Gemini API rejected the request: {message or e.code}") from e
            except (TimeoutError, ConnectionError, http.client.HTTPException) as e:
                # Slow, reset or cut-off answers come from an overloaded model: try the next one.
                reasons.append(f"{candidate}: {'no answer within ' + str(GEMINI_TIMEOUT_S) + 's' if isinstance(e, TimeoutError) else 'connection dropped'}")
                transient.append(GEMINI_RETRY_WAIT_S)
            except urllib.error.URLError as e:
                if not isinstance(e.reason, (TimeoutError, ConnectionError)):
                    raise AIError("Could not reach the Gemini API. Check the network connection.") from e
                reasons.append(f"{candidate}: connection problem")
                transient.append(GEMINI_RETRY_WAIT_S)
        if not transient or round_ == 1:
            break
        time.sleep(min(min(transient), GEMINI_RETRY_WAIT_S))
    if reasons and all(r.endswith("daily quota used up") for r in reasons):
        hours = max(1, round((min(_spent_until.values(), default=time.time() + 3600) - time.time()) / 3600))
        raise AIError(f"Gemini's free tier allows 20 requests per model per day, and today's are used up for every model "
                      f"PatchProof can use. They reset in about {hours} h. Use a paid key, or switch provider.")
    raise AIError("Gemini couldn't answer right now (" + "; ".join(reasons[:4]) + "). Try again in a minute.")


def _ask_anthropic(system: str, blocks: list[dict], schema: dict, effort: str) -> dict:
    import anthropic

    try:
        resp = _get_client().beta.messages.create(
            model=model(),
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # a declined security request is retried on Anthropic's recommended model
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
            messages=[{"role": "user", "content": blocks}],
        )
    except anthropic.AuthenticationError as e:
        raise AIError("The API key was rejected. Check ANTHROPIC_API_KEY in .env.") from e
    except anthropic.PermissionDeniedError as e:
        raise AIError(f"This API key can't use {model()}.") from e
    except anthropic.NotFoundError as e:
        raise AIError(f"Model {model()} was not found. Check PATCHPROOF_AI_MODEL.") from e
    except anthropic.RateLimitError as e:
        raise AIError("Rate limited by the Anthropic API. Wait a minute and try again.") from e
    except anthropic.BadRequestError as e:
        detail = (e.body or {}).get("error", {}).get("message") if isinstance(e.body, dict) else None
        if detail and "credit balance" in detail:
            raise AIError("Your Anthropic account has no credits left. Add some under Plans & Billing at console.anthropic.com.") from e
        raise AIError(f"The Anthropic API rejected the request: {detail or e.message}") from e
    except anthropic.APIStatusError as e:
        raise AIError(f"Anthropic API error {e.status_code}. Try again shortly.") from e
    except anthropic.APIConnectionError as e:
        raise AIError("Could not reach the Anthropic API. Check the network connection.") from e
    if resp.stop_reason == "refusal":
        category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        raise AIError("Claude declined this request" + (f" ({category})" if category else "") + ".")
    if resp.stop_reason == "max_tokens":
        raise AIError("Claude's answer was cut off before it finished.")
    text = next((b.text for b in reversed(resp.content) if b.type == "text"), "")
    return _parse(text, "Claude")


def _text(text: str) -> dict:
    return {"type": "text", "text": text}


def _numbered(lines: list[str], lo: int, hi: int) -> str:
    return "\n".join(f"{i:>5}| {lines[i - 1]}" for i in range(lo, hi + 1))


def _file_block(rel: str, source: str, focus: int | None = None, window: tuple[int, int] | None = None) -> dict:
    """The file with line numbers. Very long files are cut to MAX_FILE_LINES around the focus line."""
    lines = source.splitlines()
    lo, hi = window or (1, len(lines))
    hi = min(hi, len(lines))
    if hi - lo + 1 > MAX_FILE_LINES:
        center = focus or lo
        lo = max(lo, center - MAX_FILE_LINES // 2)
        hi = min(hi, lo + MAX_FILE_LINES - 1)
    note = "" if (lo, hi) == (1, len(lines)) else f" (lines {lo}-{hi} of {len(lines)})"
    text = f"File: {rel}{note}\n```python\n{_numbered(lines, lo, hi)}\n```"
    return {"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}


def _finding_text(vuln: Vuln, lo: int, hi: int) -> str:
    return (
        f"Finding: {vuln['type']} ({vuln['cwe']}), severity {vuln['severity']}\n"
        f"Title: {vuln['title']}\n"
        f"Why it was flagged: {vuln['severity_rationale']}\n"
        f"Location: {vuln['file_path']}, lines {lo}-{hi}\n"
        f"Flagged code:\n```python\n{vuln['original_code']}\n```"
    )


def _pick(value, allowed):
    return value if value in allowed else None


# ---------- review ----------

REVIEW_SYSTEM = """You are the application-security reviewer inside PatchProof, a tool that helps small teams decide which static-analysis findings are real and fix them safely.

You get one Python file with line numbers and one finding from PatchProof's rule-based scanner. Decide whether it is a real, exploitable weakness in this code.

- Judge only from the code shown. Trace where the flagged values come from and where they go.
- "confirmed": data an attacker can influence (request data, arguments fed by callers, uploaded files) reaches the flagged code and can cause the stated harm.
- "false_positive": the value is constant, already validated or sanitised, only reachable by trusted code, or the code is test-only.
- "uncertain": the answer depends on code that is not shown; say what would need checking.
- attack_scenario: who sends what and what happens, in plain words. A short illustrative input is fine; no working exploit code. Empty for a false positive.
- fix_hint: the standard fix for this code in one sentence.
- Keep each text field to three sentences at most."""

REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "false_positive", "uncertain"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "fix_hint": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reasoning", "attack_scenario", "fix_hint"],
    "additionalProperties": False,
}


def review(source: str, vuln: Vuln) -> AIReview:
    lo, hi = locate(source, vuln)
    data = _ask("review", REVIEW_SYSTEM, [_file_block(vuln["file_path"], source, lo), _text(_finding_text(vuln, lo, hi))],
                REVIEW_SCHEMA, "medium")
    verdict = _pick(data.get("verdict"), ("confirmed", "false_positive", "uncertain"))
    if verdict is None:
        raise AIError(f"{name()}'s review had no valid verdict.")
    return {
        "verdict": verdict,
        "confidence": _pick(data.get("confidence"), ("high", "medium", "low")),
        "reasoning": str(data.get("reasoning", "")).strip(),
        "attack_scenario": str(data.get("attack_scenario", "")).strip(),
        "fix_hint": str(data.get("fix_hint", "")).strip(),
        "model": data["_model"],
        "reviewed_at": now(),
    }


def review_many(items: list[tuple[str, Vuln]]) -> list[AIReview | dict]:
    """Review several findings concurrently. A failed review comes back as {"error": message}."""
    def one(item: tuple[str, Vuln]) -> AIReview | dict:
        try:
            return review(*item)
        except AIError as e:
            return {"error": str(e)}

    with ThreadPoolExecutor(WORKERS) as pool:
        return list(pool.map(one, items))


# ---------- fixes ----------

FIX_SYSTEM = """You write minimal, behaviour-preserving security fixes for Python code inside PatchProof.

You get one file with line numbers, one weakness, and the exact region you may change: one whole function, or a few top-level statements.

- Fix the root cause with the standard defence for this weakness: bound query parameters, argument lists without a shell, allow-lists and path containment, output escaping, ownership and authorisation checks, safe loaders, secrets read from the environment, signature-checked tokens.
- Return the complete new source of the region as plain code (no markdown fences) and nothing else. Keep the comments and style that still apply.
- For a function: its def line and existing decorators are kept from the original no matter what you write, so fix the weakness inside the body. You may add a decorator (for example an access check the app already has). Keep what it returns compatible, so every caller still works.
- Legitimate input must behave exactly as before. Only the malicious cases may be refused or neutralised.
- Use the standard library and modules the file already imports. Put any new import statements in new_imports (they go at the top of the file), not inside the region.
- No unrelated refactors, renames or logging. One short comment starting with "PatchProof:" above the key change is welcome.
- rationale: what the fix does and why it stops the attack, in two sentences. behaviour_change: anything a legitimate caller would notice, or "None"."""

FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "replacement": {"type": "string"},
        "new_imports": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "behaviour_change": {"type": "string"},
    },
    "required": ["replacement", "new_imports", "rationale", "behaviour_change"],
    "additionalProperties": False,
}


def propose_fix(source: str, vuln: Vuln, profile: dict) -> dict:
    """Ask the model for a fix and keep it only if it passes every static check.

    Returns {"after", "rationale", "behaviour_change", "checks", "log", "reason"}; "after" is None when no attempt passed.
    """
    lo, hi = locate(source, vuln)
    region = region_for(ast.parse(source), lo, hi)
    lines = source.splitlines()
    region_src = "\n".join(lines[region.lo - 1 : region.hi])
    kind = (f"Rewrite the whole function {region.qualname} (lines {region.lo}-{region.hi})" if region.qualname
            else f"Rewrite the top-level statements on lines {region.lo}-{region.hi}")
    task = f"{_finding_text(vuln, lo, hi)}\n\n{kind}. Current source of the region:\n```python\n{region_src}\n```"
    out: list[LogLine] = [log("INFO", f"Asking {name()} to fix {region.where}")]
    feedback, last_checks = "", []

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            data = _ask("fix", FIX_SYSTEM, [_file_block(vuln["file_path"], source, lo), _text(task + feedback)], FIX_SCHEMA, "high")
        except AIError as e:
            out.append(log("ERROR", f"Attempt {attempt}: {e}"))
            return {"after": None, "rationale": None, "behaviour_change": None, "checks": last_checks, "log": out, "reason": str(e)}
        replacement = str(data.get("replacement", ""))
        try:
            after = replace_region(source, region.qualname, region.lo, region.hi, replacement,
                                   [str(i) for i in data.get("new_imports", [])])
        except (PatchError, cst.ParserSyntaxError, SyntaxError) as e:
            reason = f"it could not be applied: {e}"
            out.append(log("WARN", f"Attempt {attempt} rejected: {reason}"))
            feedback = f"\n\nYour previous replacement was rejected because {reason}. Return a corrected one."
            continue
        checks = static_checks(source, after, vuln, profile["rule_packs"])
        bad = failed(checks)
        if not bad:
            ran = sum(1 for c in checks if c["passed"] is not None)
            out.append(log("SUCCESS", f"Attempt {attempt} by {data['_model']} passed all {ran} static checks"))
            return {"after": after, "rationale": str(data.get("rationale", "")).strip(),
                    "behaviour_change": str(data.get("behaviour_change", "")).strip() or None,
                    "checks": checks, "log": out, "reason": None}
        last_checks = checks
        reasons = "\n".join(f"- {c['label']}: {c['detail']}" for c in bad)
        out.append(log("WARN", f"Attempt {attempt} rejected by the checks: " + "; ".join(c["label"] for c in bad)))
        feedback = (f"\n\nYour previous replacement:\n```python\n{replacement}\n```\n"
                    f"PatchProof's checks rejected it:\n{reasons}\nReturn a corrected replacement.")
    return {"after": None, "rationale": None, "behaviour_change": None, "checks": last_checks, "log": out,
            "reason": f"none of {name()}'s {MAX_ATTEMPTS} attempts passed the checks"}


# ---------- re-check of AI-found weaknesses ----------

RECHECK_SYSTEM = """You verify security fixes inside PatchProof. You get a weakness that was reported in a Python file, and the file after a fix was applied. Decide whether the weakness is now resolved in the patched code: the attack described can no longer succeed. Be strict: a partial fix, or a fix that only covers some inputs, is not resolved. Answer in at most three sentences."""

RECHECK_SCHEMA = {
    "type": "object",
    "properties": {"resolved": {"type": "boolean"}, "reasoning": {"type": "string"}},
    "required": ["resolved", "reasoning"],
    "additionalProperties": False,
}


def recheck(after: str, vuln: Vuln) -> dict:
    """{"resolved": bool, "reasoning": str}. Fails closed: if the model can't be asked, the weakness counts as unresolved."""
    base = vuln.get("base_code") or after
    region = region_for(ast.parse(base), *locate(base, vuln))
    fn = functions(ast.parse(after)).get(region.qualname or "")
    focus = fn.lineno if fn else region.lo
    where = f"Look at {region.where}, around line {focus} of the patched file."
    try:
        data = _ask("recheck", RECHECK_SYSTEM, [_file_block(vuln["file_path"], after, focus),
                                                _text(f"{_finding_text(vuln, vuln['line_number'], vuln['end_line'])}\n\n{where}")],
                    RECHECK_SCHEMA, "medium")
    except AIError as e:
        return {"resolved": False, "reasoning": f"Could not re-check: {e}"}
    return {"resolved": data.get("resolved") is True, "reasoning": str(data.get("reasoning", "")).strip()}


# ---------- deep scan ----------

DEEP_SYSTEM = """You are PatchProof's deep-scan reviewer. Rule-based scanning has already run on this Python file and its findings are listed. Find additional security weaknesses that pattern rules miss, especially:
- broken access control: records read or changed by an id without checking that the caller owns them
- missing authentication or authorisation on sensitive routes or functions
- business-logic flaws: unchecked or negative amounts, skipped state checks, race conditions
- cross-site scripting, open redirects, CSRF on state-changing routes, mass assignment, unsafe file uploads
- sensitive data returned in responses or written to logs
- injection paths the rules missed because data flows through helpers or lambdas

Rules:
- Report only weaknesses with concrete evidence in the code shown. No style issues, best-practice advice or duplicates of the listed findings.
- line_start and line_end are the exact lines of the weak code. evidence_line is the single most important line, copied character for character without the line-number prefix.
- rationale: who can exploit it, how, and what they gain, in at most three sentences.
- At most 8 findings, most severe first. Return an empty list if nothing is solid."""

DEEP_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": [*DEEP_TYPES, *GENERIC_TYPES]},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "cwe": {"type": "string"},
                    "title": {"type": "string"},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "evidence_line": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["type", "severity", "cwe", "title", "line_start", "line_end", "evidence_line", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}


def ground(lines: list[str], item: dict, window: tuple[int, int]) -> tuple[int, int] | None:
    """Where the evidence line really is: within 5 lines of the claimed span and inside the scanned window."""
    evidence = " ".join(str(item.get("evidence_line", "")).split())
    if len(evidence) < 4:
        return None
    lo, hi = window
    try:
        start, end = int(item["line_start"]), int(item["line_end"])
    except (KeyError, TypeError, ValueError):
        return None
    end = max(start, end)
    near = range(max(lo, start - 5), min(hi, end + 5) + 1)
    exact = [i for i in near if " ".join(lines[i - 1].split()) == evidence]
    partial = [i for i in near if evidence in " ".join(lines[i - 1].split())]
    found = (exact or partial or [None])[0]
    if found is None:
        return None
    if not start <= found <= end:
        start = end = found
    start, end = max(start, lo), min(end, hi, start + 39)
    return start, end


def _deep_files(profile: dict, root: Path) -> list[tuple[str, tuple[int, int] | None]]:
    from engine.scanner import _is_test_file

    files = [(rel, w) for rel, w in in_scope_files(profile, root) if (root / rel).is_file() and not _is_test_file(rel)]
    if len(files) <= DEEP_SCAN_MAX_FILES:
        return files

    def score(item):
        text = (root / item[0]).read_text(errors="replace")
        return bool(WEB_HINT.search(text)), len(text)

    return sorted(files, key=score, reverse=True)[:DEEP_SCAN_MAX_FILES]


def _overlaps(a: tuple[int, int], b: tuple[int, int], slack: int = 2) -> bool:
    return a[0] <= b[1] + slack and b[0] <= a[1] + slack


def deep_scan(workspace: str, profile: dict, known: list[dict]) -> dict:
    """The model reads each in-scope file for weaknesses the rules can't see.

    Returns {"findings", "files", "dropped", "errors"}: findings that quote real code and are not duplicates,
    how many files were read, how many answers were dropped for not matching the code, and per-file errors.
    """
    root = Path(workspace)
    files = _deep_files(profile, root)

    def one(item: tuple[str, tuple[int, int] | None]):
        rel, window = item
        source = (root / rel).read_text(errors="replace")
        mine = [k for k in known if k["file_path"] == rel]
        listed = "\n".join(f"- {k['type']} at lines {k['line_number']}-{k['end_line']}: {k['title']}" for k in mine) or "- none"
        try:
            data = _ask("deep_scan", DEEP_SYSTEM, [_file_block(rel, source, window=window),
                                                   _text(f"Already reported for this file (don't repeat these):\n{listed}")],
                        DEEP_SCHEMA, "high")
        except AIError as e:
            return rel, source, window, None, str(e)
        return rel, source, window, data, None

    with ThreadPoolExecutor(WORKERS) as pool:
        results = list(pool.map(one, files))

    findings: list[Finding] = []
    dropped = 0
    errors: list[str] = []
    seen: set[str] = set()
    used = [data["_model"] for _, _, _, data, _ in results if data and data.get("_model")]
    for rel, source, window, data, error in results:
        if error:
            errors.append(f"{rel}: {error}")
            continue
        lines = source.splitlines()
        span_window = window or (1, len(lines))
        for item in (data.get("findings") or [])[:DEEP_SCAN_MAX_FINDINGS]:
            vtype = item.get("type")
            span = ground(lines, item, span_window) if vtype in DEEP_TYPES or vtype in GENERIC_TYPES else None
            if span is None:
                dropped += 1
                continue
            anchor = "ai|" + " ".join(str(item["evidence_line"]).split())
            duplicate = anchor in seen or any(
                k["file_path"] == rel and k["type"] == vtype and _overlaps(span, (k["line_number"], k["end_line"])) for k in known)
            if duplicate:
                continue
            seen.add(anchor)
            cwe = str(item.get("cwe", "")).strip()
            findings.append({
                "file_path": rel,
                "line_number": span[0],
                "end_line": span[1],
                "severity": item["severity"] if item.get("severity") in SEVERITIES else "MEDIUM",
                "type": vtype,
                "cwe": cwe if re.fullmatch(r"CWE-\d+", cwe) else DEEP_TYPES.get(vtype, "CWE-693"),
                "title": str(item.get("title", "")).strip()[:120] or vtype.replace("_", " ").capitalize(),
                "severity_rationale": str(item.get("rationale", "")).strip(),
                "original_code": "\n".join(lines[span[0] - 1 : span[1]]),
                "patchable": True,
                "provable": False,  # exploit cases belong to the rule-found sites, not to these
                "fixer": "ai",
                "detected_by": "ai",
                "anchor": anchor,
            })
    return {"findings": findings, "files": len(files), "dropped": dropped, "errors": errors,
            "model": max(set(used), key=used.count) if used else model()}

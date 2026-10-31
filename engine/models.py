"""Engine data contracts. Mirrors PROJECT_CONTEXT.md §5-§7 — change there first."""

from typing import Literal, NotRequired, TypedDict

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VulnType = Literal[
    # "ai" rule pack
    "AI_PROMPT_INJECTION",
    "AI_BROKEN_AUTH",
    "AI_INFO_DISCLOSURE",
    "AI_ROLE_OVERRIDE",
    "VERBOSE_ERROR_DISCLOSURE",
    # "generic" rule pack
    "SQL_INJECTION",
    "COMMAND_INJECTION",
    "CODE_INJECTION",
    "PATH_TRAVERSAL",
    "SSRF",
    "INSECURE_DESERIALIZATION",
    "INSECURE_JWT",
    "HARDCODED_CREDENTIALS",
    "TLS_VERIFY_DISABLED",
    "WEAK_CRYPTO",
    "DEBUG_MODE",
    # AI deep scan (engine/ai.py): logic flaws that pattern rules can't see
    "BROKEN_ACCESS_CONTROL",
    "MISSING_AUTHENTICATION",
    "XSS",
    "OPEN_REDIRECT",
    "CSRF",
    "MASS_ASSIGNMENT",
    "INSECURE_FILE_UPLOAD",
    "BUSINESS_LOGIC",
    "RACE_CONDITION",
    "SENSITIVE_DATA_EXPOSURE",
    "OTHER_WEAKNESS",
]
Status = Literal["OPEN", "PATCHED", "VERIFIED", "FAILED"]
PocStatus = Literal["NOT_RUN", "EXPLOITABLE", "BLOCKED"]
RegressionStatus = Literal["NOT_RUN", "PASSED", "FAILED"]
LogLevel = Literal["INFO", "WARN", "ERROR", "SUCCESS"]
Fixer = Literal["rule", "ai"]


class LogLine(TypedDict):
    ts: str
    level: LogLevel
    msg: str


class Check(TypedDict):
    """One proof check on a fix. passed is None when the check does not apply."""

    id: str
    label: str
    passed: bool | None
    detail: str


class AIReview(TypedDict):
    verdict: Literal["confirmed", "false_positive", "uncertain"] | None
    confidence: Literal["high", "medium", "low"] | None
    reasoning: str
    attack_scenario: str
    fix_hint: str
    model: str
    reviewed_at: str
    error: NotRequired[str]


class Finding(TypedDict):
    """What scan_repository returns. Backend adds id/status/timestamps to make a Vuln."""

    file_path: str
    line_number: int
    end_line: int
    severity: Severity
    type: VulnType
    cwe: str
    title: str
    severity_rationale: str
    original_code: str
    patchable: bool  # a fix can be produced: by a rule-based patch, or by Claude when AI is on
    provable: bool  # the target has exploit cases for this type, so the fix is proven by running them
    fixer: Fixer | None
    detected_by: Fixer  # "rule" scanner or "ai" deep scan
    # Stable identity (enclosing function + flagged code). The backend derives the ID from it and does not store it.
    anchor: NotRequired[str]


class Vuln(Finding):
    """One row of the TinyDB `vulnerabilities` table."""

    id: str
    status: Status
    patched_code: str | None
    diff: str | None
    patch_rationale: str | None
    poc_status: PocStatus
    regression_status: RegressionStatus
    poc_log: list[LogLine]
    verification_log: list[LogLine]
    fix_source: Fixer | None
    checks: list[Check]
    ai_review: AIReview | None
    behaviour_change: str | None
    base_code: str | None  # the whole file before this finding's patch, to re-check or retry it
    created_at: str
    updated_at: str


class PocResult(TypedDict):
    exploitable: bool
    log: list[LogLine]


class PatchResult(TypedDict):
    success: bool
    patched_code: str | None
    diff: str | None
    patch_rationale: str | None
    fix_source: Fixer | None
    checks: list[Check]
    base_code: str | None
    behaviour_change: str | None
    log: list[LogLine]


class VerifyResult(TypedDict):
    security_blocked: bool | None  # None: no exploit cases for this finding
    regression_passed: bool | None  # None: the target has no regression suite
    checks: list[Check]
    log: list[LogLine]
    baseline_log: NotRequired[list[LogLine]]  # the regression suite run without this fix

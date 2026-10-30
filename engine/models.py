"""Engine data contracts. Mirrors PROJECT_CONTEXT.md §5-§7 — change there first."""

from typing import Literal, NotRequired, TypedDict

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VulnType = Literal[
    "AI_PROMPT_INJECTION",
    "AI_BROKEN_AUTH",
    "AI_INFO_DISCLOSURE",
    "AI_ROLE_OVERRIDE",
    "HARDCODED_CREDENTIALS",
    "VERBOSE_ERROR_DISCLOSURE",
]
Status = Literal["OPEN", "PATCHED", "VERIFIED", "FAILED"]
PocStatus = Literal["NOT_RUN", "EXPLOITABLE", "BLOCKED"]
RegressionStatus = Literal["NOT_RUN", "PASSED", "FAILED"]
LogLevel = Literal["INFO", "WARN", "ERROR", "SUCCESS"]

PATCHABLE_TYPES: frozenset[str] = frozenset({"AI_PROMPT_INJECTION", "AI_BROKEN_AUTH"})


class LogLine(TypedDict):
    ts: str
    level: LogLevel
    msg: str


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
    patchable: bool


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
    log: NotRequired[list[LogLine]]


class VerifyResult(TypedDict):
    security_blocked: bool
    regression_passed: bool
    log: list[LogLine]

// Mirrors PROJECT_CONTEXT.md §5-§7 exactly. Change the contract there first.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type VulnType =
  // "ai" rule pack
  | 'AI_PROMPT_INJECTION'
  | 'AI_BROKEN_AUTH'
  | 'AI_INFO_DISCLOSURE'
  | 'AI_ROLE_OVERRIDE'
  | 'VERBOSE_ERROR_DISCLOSURE'
  // "generic" rule pack
  | 'SQL_INJECTION'
  | 'COMMAND_INJECTION'
  | 'CODE_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'SSRF'
  | 'INSECURE_DESERIALIZATION'
  | 'INSECURE_JWT'
  | 'HARDCODED_CREDENTIALS'
  | 'TLS_VERIFY_DISABLED'
  | 'WEAK_CRYPTO'
  | 'DEBUG_MODE'
  // AI deep scan: logic flaws pattern rules can't see
  | 'BROKEN_ACCESS_CONTROL'
  | 'MISSING_AUTHENTICATION'
  | 'XSS'
  | 'OPEN_REDIRECT'
  | 'CSRF'
  | 'MASS_ASSIGNMENT'
  | 'INSECURE_FILE_UPLOAD'
  | 'BUSINESS_LOGIC'
  | 'RACE_CONDITION'
  | 'SENSITIVE_DATA_EXPOSURE'
  | 'OTHER_WEAKNESS'
export type Status = 'OPEN' | 'PATCHED' | 'VERIFIED' | 'FAILED'
export type PocStatus = 'NOT_RUN' | 'EXPLOITABLE' | 'BLOCKED'
export type RegressionStatus = 'NOT_RUN' | 'PASSED' | 'FAILED'
export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS'
export type Fixer = 'rule' | 'ai'

export interface LogLine {
  ts: string
  level: LogLevel
  msg: string
}

/** One proof check on a fix. passed is null when the check does not apply. */
export interface Check {
  id: 'compiles' | 'fixed' | 'no_new' | 'scoped' | 'signature' | 'ai_recheck' | 'exploit' | 'regression'
  label: string
  passed: boolean | null
  detail: string
}

/** The AI model's opinion on a finding. Shown as opinion, never as proof. */
export interface AIReview {
  verdict?: 'confirmed' | 'false_positive' | 'uncertain' | null
  confidence?: 'high' | 'medium' | 'low' | null
  reasoning?: string
  attack_scenario?: string
  fix_hint?: string
  model: string
  reviewed_at: string
  error?: string
}

export interface Vuln {
  id: string
  file_path: string
  line_number: number
  end_line: number
  severity: Severity
  type: VulnType
  cwe: string
  title: string
  severity_rationale: string
  status: Status
  /** A fix can be produced now: a rule-based patch, or an AI fix when AI is on. */
  patchable: boolean
  /** The target has exploit cases for this type, so the fix is proven by running them. */
  provable: boolean
  fixer: Fixer | null
  detected_by: Fixer
  fix_source: Fixer | null
  checks: Check[]
  ai_review: AIReview | null
  behaviour_change: string | null
  base_code: string | null
  original_code: string
  patched_code: string | null
  diff: string | null
  patch_rationale: string | null
  poc_status: PocStatus
  regression_status: RegressionStatus
  poc_log: LogLine[]
  verification_log: LogLine[]
  created_at: string
  updated_at: string
}

export type Action = 'scan' | 'poc' | 'patch' | 'verify' | 'run-all' | 'reset' | 'select' | 'review' | 'review-all' | 'deep-scan' | 'fix-all'

export interface AIStatus {
  enabled: boolean
  provider: 'anthropic' | 'gemini'
  model: string
  /** Why AI is off, when it is. */
  reason: string | null
}

export interface Health {
  status: string
  busy: boolean
  action: Action | null
  ai: AIStatus
}

export interface Accepted {
  accepted: true
  action: Action
  vuln_id?: string
}

export interface TargetCase {
  id: string
  kind: 'security' | 'regression'
  types: VulnType[]
  user: string
  message: string
  expected: string
}

export interface ScanStats {
  files_scanned: number
  files_skipped: number
  parse_errors: number
}

export interface TargetInfo {
  id: string
  /** "profile" = curated practice target (exploits run); "project" = your own code (never run; fixes proven by static checks). */
  kind: 'profile' | 'project'
  name: string
  summary: string
  module: string
  source: string
  commit: string | null
  in_scope: { file: string; lines: [number, number] | null; role: string }[]
  out_of_scope: string[]
  provable: boolean
  harness: 'vuln-bank-agent' | 'function-call' | null
  /** Only on the active target. */
  cases?: TargetCase[]
  stats?: ScanStats | null
  deep_scan?: DeepScanReport | null
}

export interface DeepScanReport {
  at: string
  files: number
  added: number
  /** Answers dropped because they did not quote real code at the lines they named. */
  dropped: number
  errors: string[]
  model: string
}

export interface TargetsResponse {
  active: TargetInfo
  profiles: TargetInfo[]
  error: { message: string; at: string } | null
}

export type TargetSelection = { id: string } | { path: string } | { git_url: string }

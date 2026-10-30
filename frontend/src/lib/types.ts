// Mirrors PROJECT_CONTEXT.md §5-§7 exactly. Change the contract there first.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type VulnType =
  | 'AI_PROMPT_INJECTION'
  | 'AI_BROKEN_AUTH'
  | 'AI_INFO_DISCLOSURE'
  | 'AI_ROLE_OVERRIDE'
  | 'HARDCODED_CREDENTIALS'
  | 'VERBOSE_ERROR_DISCLOSURE'
export type Status = 'OPEN' | 'PATCHED' | 'VERIFIED' | 'FAILED'
export type PocStatus = 'NOT_RUN' | 'EXPLOITABLE' | 'BLOCKED'
export type RegressionStatus = 'NOT_RUN' | 'PASSED' | 'FAILED'
export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS'

export interface LogLine {
  ts: string
  level: LogLevel
  msg: string
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
  patchable: boolean
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

export type Action = 'scan' | 'poc' | 'patch' | 'verify' | 'run-all' | 'reset'

export interface Accepted {
  accepted: true
  action: Action
  vuln_id?: string
}

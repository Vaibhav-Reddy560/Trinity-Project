import type { Severity, Vuln, VulnType } from './types'

export const typeName: Record<VulnType, string> = {
  AI_PROMPT_INJECTION: 'Prompt injection',
  AI_BROKEN_AUTH: 'Broken authorization',
  AI_INFO_DISCLOSURE: 'Information disclosure',
  AI_ROLE_OVERRIDE: 'Role override',
  VERBOSE_ERROR_DISCLOSURE: 'Verbose error messages',
  SQL_INJECTION: 'SQL injection',
  COMMAND_INJECTION: 'Command injection',
  CODE_INJECTION: 'Code injection',
  PATH_TRAVERSAL: 'Path traversal',
  SSRF: 'Server-side request forgery',
  INSECURE_DESERIALIZATION: 'Unsafe deserialization',
  INSECURE_JWT: 'Unverified JWT',
  HARDCODED_CREDENTIALS: 'Hardcoded credentials',
  TLS_VERIFY_DISABLED: 'TLS checks disabled',
  WEAK_CRYPTO: 'Weak password hashing',
  DEBUG_MODE: 'Debug mode on',
  BROKEN_ACCESS_CONTROL: 'Broken access control',
  MISSING_AUTHENTICATION: 'Missing authentication',
  XSS: 'Cross-site scripting',
  OPEN_REDIRECT: 'Open redirect',
  CSRF: 'Cross-site request forgery',
  MASS_ASSIGNMENT: 'Mass assignment',
  INSECURE_FILE_UPLOAD: 'Unsafe file upload',
  BUSINESS_LOGIC: 'Business logic flaw',
  RACE_CONDITION: 'Race condition',
  SENSITIVE_DATA_EXPOSURE: 'Sensitive data exposure',
  OTHER_WEAKNESS: 'Other weakness',
}

export const fixSourceLabel = { rule: 'Rule-based patch', ai: 'Written by AI, checked by PatchProof' } as const

/** Short model name for display: "claude-opus-5-5" -> "Claude Opus 5.5", "gemini-2.5-flash" -> "Gemini 2.5 Flash". */
export const modelName = (id: string) =>
  (id.startsWith('claude-') ? id.replace(/-(\d+)-(\d+)$/, ' $1.$2').replace(/-(\d+)$/, ' $1') : id)
    .replace(/-/g, ' ')
    .replace(/(^|\s)([a-z])/g, (_, s, c) => s + c.toUpperCase())

export const severityLabel: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

export const severityColor: Record<Severity, string> = {
  CRITICAL: 'var(--color-signal)',
  HIGH: '#d4351c',
  MEDIUM: '#b0705f',
  LOW: 'var(--color-ash)',
}

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const codeLocation = (v: Pick<Vuln, 'file_path' | 'line_number' | 'end_line'>) =>
  `${v.file_path}:${v.line_number}${v.end_line !== v.line_number ? `-${v.end_line}` : ''}`

export function clock(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

export function ago(iso: string, now = Date.now()) {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000))
  if (s < 45) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h} h ago`
  return `${Math.round(h / 24)} d ago`
}

export function downloadFile(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = Object.assign(document.createElement('a'), { href: url, download: name })
  a.click()
  URL.revokeObjectURL(url)
}

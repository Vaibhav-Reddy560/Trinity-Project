import type { Severity, Vuln, VulnType } from './types'

export const typeName: Record<VulnType, string> = {
  AI_PROMPT_INJECTION: 'Prompt injection',
  AI_BROKEN_AUTH: 'Broken authorization',
  AI_INFO_DISCLOSURE: 'Information disclosure',
  AI_ROLE_OVERRIDE: 'Role override',
  HARDCODED_CREDENTIALS: 'Hardcoded credentials',
  VERBOSE_ERROR_DISCLOSURE: 'Verbose error messages',
}

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

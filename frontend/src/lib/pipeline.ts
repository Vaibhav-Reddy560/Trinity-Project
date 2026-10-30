import type { Severity, Vuln } from './types'

export type StageState = 'done' | 'alert' | 'pending' | 'fail' | 'skipped'
export interface Stage {
  key: 'scan' | 'prove' | 'patch' | 'verify'
  label: string
  state: StageState
}

export function stagesFor(v: Vuln): Stage[] {
  const prove: StageState =
    v.poc_status === 'EXPLOITABLE' ? 'alert' : v.poc_status === 'BLOCKED' ? 'done' : 'pending'
  const patch: StageState = !v.patchable
    ? 'skipped'
    : v.status === 'PATCHED' || v.status === 'VERIFIED'
      ? 'done'
      : v.status === 'FAILED' && !v.diff
        ? 'fail'
        : 'pending'
  const verify: StageState = !v.patchable
    ? 'skipped'
    : v.status === 'VERIFIED'
      ? 'done'
      : v.status === 'FAILED' && v.diff
        ? 'fail'
        : 'pending'
  return [
    { key: 'scan', label: 'Scan', state: 'done' },
    { key: 'prove', label: 'Prove', state: prove },
    { key: 'patch', label: 'Patch', state: patch },
    { key: 'verify', label: 'Verify', state: verify },
  ]
}

export type Verdict = 'Verified' | 'Failed' | 'Patched' | 'Exploitable' | 'Blocked' | 'Open'

export function verdictFor(v: Vuln): Verdict {
  if (v.status === 'VERIFIED') return 'Verified'
  if (v.status === 'FAILED') return 'Failed'
  if (v.status === 'PATCHED') return 'Patched'
  if (v.poc_status === 'EXPLOITABLE') return 'Exploitable'
  if (v.poc_status === 'BLOCKED') return 'Blocked'
  return 'Open'
}

export const canRunPoc = (v: Vuln) => v.patchable
export const canPatch = (v: Vuln) =>
  v.patchable && v.poc_status === 'EXPLOITABLE' && (v.status === 'OPEN' || v.status === 'FAILED')
export const canVerify = (v: Vuln) => v.status === 'PATCHED'

export const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export const severityLabel: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

export const severityColor: Record<Severity, string> = {
  CRITICAL: 'var(--color-signal)',
  HIGH: '#b81d14',
  MEDIUM: 'var(--color-blood-600)',
  LOW: 'var(--color-ash)',
}

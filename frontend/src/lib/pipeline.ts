import type { TestCase } from './scope'
import type { LogLine, Severity, Vuln } from './types'

export type StageState = 'done' | 'alert' | 'pending' | 'fail' | 'skipped'
export type StageKey = 'scan' | 'prove' | 'patch' | 'verify'
export interface Stage {
  key: StageKey
  label: string
  state: StageState
}

const fixable = (v: Vuln) => v.patchable || v.diff !== null

export function stagesFor(v: Vuln): Stage[] {
  const prove: StageState =
    v.poc_status === 'EXPLOITABLE' ? 'alert' : v.poc_status === 'BLOCKED' ? 'done' : 'pending'
  const patch: StageState = !fixable(v)
    ? 'skipped'
    : v.status === 'PATCHED' || v.status === 'VERIFIED' || (v.status === 'FAILED' && v.diff)
      ? 'done'
      : v.status === 'FAILED'
        ? 'fail'
        : 'pending'
  const verify: StageState = !fixable(v)
    ? 'skipped'
    : v.status === 'VERIFIED'
      ? 'done'
      : v.status === 'FAILED' && v.diff
        ? 'fail'
        : 'pending'
  return [
    { key: 'scan', label: 'Scan', state: 'done' },
    { key: 'prove', label: 'Prove', state: v.provable ? prove : 'skipped' },
    { key: 'patch', label: 'Patch', state: patch },
    { key: 'verify', label: 'Verify', state: verify },
  ]
}

export type Verdict = 'Verified' | 'Failed' | 'Patched' | 'Exploitable' | 'Blocked' | 'Open' | 'Report only'

export function verdictFor(v: Vuln): Verdict {
  if (!fixable(v)) return 'Report only'
  if (v.status === 'VERIFIED') return 'Verified'
  if (v.status === 'FAILED') return 'Failed'
  if (v.status === 'PATCHED') return 'Patched'
  if (v.poc_status === 'EXPLOITABLE') return 'Exploitable'
  if (v.poc_status === 'BLOCKED') return 'Blocked'
  return 'Open'
}

/** What a verified fix was proven by, strongest first. */
export type Proof = 'exploit' | 'regression' | 'static'
export const proofOf = (v: Vuln): Proof =>
  v.provable ? 'exploit' : v.checks.some((c) => c.id === 'regression' && c.passed !== null) ? 'regression' : 'static'
export const proofLabel: Record<Proof, string> = {
  exploit: 'Exploit blocked, behaviour intact',
  regression: 'Static checks and regression suite passed',
  static: 'Every static proof check passed',
}

export type StepAction = 'poc' | 'patch' | 'verify'

export function nextAction(v: Vuln): StepAction | null {
  if (v.status === 'VERIFIED' || !fixable(v)) return null
  if (v.status === 'PATCHED') return 'verify'
  if (v.status === 'FAILED') return v.patchable ? 'patch' : null
  if (v.provable && v.poc_status !== 'EXPLOITABLE') return 'poc'
  return v.patchable ? 'patch' : null
}

export function nextActionHint(v: Vuln, step: StepAction): string {
  if (step === 'poc') return 'Run the exploit to prove this weakness is real.'
  if (step === 'verify')
    return v.provable
      ? 'Patch applied. Verify that the exploit is blocked and normal use still works.'
      : 'Fix applied. Run the proof checks to verify it.'
  if (v.status === 'FAILED') return 'The last fix did not pass its checks. Try again, or fix it by hand.'
  if (v.provable) return 'The exploit works. Apply the patch to fix it.'
  return v.fixer === 'ai'
    ? 'No rule covers this code. Ask the AI for a fix: PatchProof applies it only if it passes every check.'
    : 'A rule-based fix is ready for this code.'
}

export const canRunPoc = (v: Vuln) => v.provable
export const canPatch = (v: Vuln) =>
  v.patchable && (v.status === 'OPEN' || v.status === 'FAILED') && (!v.provable || v.poc_status === 'EXPLOITABLE' || v.diff !== null)
export const canVerify = (v: Vuln) => v.status === 'PATCHED'

export const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export function diffStats(diff: string | null) {
  if (!diff) return { added: 0, removed: 0, hunks: 0 }
  let added = 0
  let removed = 0
  let hunks = 0
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++') || line.startsWith('---')) continue
    if (line.startsWith('@@')) hunks++
    else if (line.startsWith('+')) added++
    else if (line.startsWith('-')) removed++
  }
  return { added, removed, hunks }
}

export type CaseResult = 'Passed' | 'Failed' | 'Exploit reproduced' | 'Not run'

export interface CaseVerdict {
  id: string
  ok: boolean
  line: LogLine
}

// Engine logs name each case on an INFO step line ("BA-1 as alice: ..."); the next
// SUCCESS/ERROR line is that case's verdict (PROJECT_CONTEXT.md §6). Later runs win.
export function caseVerdicts(lines: LogLine[]): Record<string, CaseVerdict> {
  const out: Record<string, CaseVerdict> = {}
  let current: string | null = null
  for (const line of lines) {
    const step = line.level === 'INFO' ? line.msg.match(/^([A-Z]+-\d+) as /) : null
    if (step) current = step[1]
    else if (current && (line.level === 'SUCCESS' || line.level === 'ERROR')) {
      out[current] = { id: current, ok: line.level === 'SUCCESS', line }
      current = null
    }
  }
  return out
}

/** Result after the patch, from verification evidence. */
export function caseResult(c: TestCase, v: Vuln): CaseResult {
  const after = caseVerdicts(v.verification_log)[c.id]
  if (after) return after.ok ? 'Passed' : 'Failed'
  if (c.kind === 'Security' && caseVerdicts(v.poc_log)[c.id]?.ok === false) return 'Exploit reproduced'
  return 'Not run'
}

export type Baseline = 'Exploit worked' | 'Exploit blocked' | 'Works' | 'Broken' | 'Not run'

/** Result before the patch, from the original exploit run (which also records a regression baseline). */
export function baselineResult(c: TestCase, v: Vuln): Baseline {
  const before = caseVerdicts(v.poc_log)[c.id]
  if (!before) return 'Not run'
  if (c.kind === 'Security') return before.ok ? 'Exploit blocked' : 'Exploit worked'
  return before.ok ? 'Works' : 'Broken'
}

/** ERROR verdicts of security cases: the leaks the exploit actually proved. */
export function provenLeaks(v: Vuln, securityIds: Set<string>): string[] {
  return Object.values(caseVerdicts(v.poc_log))
    .filter((r) => !r.ok && securityIds.has(r.id))
    .map((r) => r.line.msg.split('\n', 1)[0])
}

export function summarize(vulns: Vuln[]) {
  const patchable = vulns.filter(fixable)
  return {
    total: vulns.length,
    patchable: patchable.length,
    provable: patchable.filter((v) => v.provable).length,
    byAI: vulns.filter((v) => v.detected_by === 'ai').length,
    aiFixes: vulns.filter((v) => v.fix_source === 'ai').length,
    proven: patchable.filter((v) => v.provable && v.poc_status !== 'NOT_RUN').length,
    exploitable: vulns.filter((v) => v.poc_status === 'EXPLOITABLE').length,
    patched: patchable.filter((v) => v.status === 'PATCHED' || v.status === 'VERIFIED').length,
    verified: patchable.filter((v) => v.status === 'VERIFIED').length,
    failed: vulns.filter((v) => v.status === 'FAILED').length,
    reportOnly: vulns.length - patchable.length,
  }
}

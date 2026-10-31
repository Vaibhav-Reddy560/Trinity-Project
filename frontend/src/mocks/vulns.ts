import type { Check, LogLine, Vuln, VulnType } from '@/lib/types'
import evidence from './evidence.json'
import findings from './findings.json'

// Shapes match PROJECT_CONTEXT.md §5 exactly; content mirrors target_app/SCOPE.md @ 4bb7cd5.

type Msg = [LogLine['level'], string]

export const stamp = (msgs: Msg[], start: number): LogLine[] =>
  msgs.map(([level, msg], i) => ({ ts: new Date(start + i * 1400).toISOString(), level, msg }))

export interface Evidence {
  poc: Msg[]
  verify: Msg[]
  diff: string
  rationale: string
}

// Generated from a real engine run (see evidence.json), so mock mode shows exactly what the engine produces.
export const EVIDENCE = evidence as unknown as Partial<Record<VulnType, Evidence>>

type Finding = Pick<Vuln, 'id' | 'file_path' | 'line_number' | 'end_line' | 'severity' | 'type' | 'cwe' | 'title' | 'severity_rationale' | 'original_code' | 'patchable'>

/** The checks the engine runs on the two golden-path fixes (all pass, as in the recorded engine run). */
export function mockChecks(v: Pick<Vuln, 'type'>, verified: boolean): Check[] {
  const fn = v.type === 'AI_BROKEN_AUTH' ? 'DeepSeekAgent._get_database_context' : 'DeepSeekAgent.chat'
  const checks: Check[] = [
    { id: 'compiles', label: 'Patched code compiles', passed: true, detail: 'The patched file parses and compiles.' },
    { id: 'fixed', label: 'Weakness no longer detected', passed: true, detail: `Rescanned: the rule no longer flags this code in ${fn}().` },
    { id: 'no_new', label: 'No new weaknesses introduced', passed: true, detail: 'Rescanned the whole file: nothing new is flagged.' },
    { id: 'scoped', label: 'Change stays inside the flagged code', passed: true, detail: `Only ${fn}() changed, plus imports or PatchProof helpers.` },
    { id: 'signature', label: 'Function signature unchanged', passed: true, detail: `${fn}() keeps its name, parameters and decorators, so callers keep working.` },
  ]
  if (!verified) return checks
  return [
    ...checks,
    { id: 'exploit', label: 'Exploit blocked', passed: true, detail: 'Every exploit case for this weakness was blocked.' },
    { id: 'regression', label: 'Normal behaviour preserved', passed: true, detail: '4/4 regression cases behave normally (the whole suite, not just this weakness).' },
  ]
}

// Generated from the real scanner on the pristine snapshot (see findings.json), IDs included.
export function scannedFindings(at = Date.now()): Vuln[] {
  const t = new Date(at).toISOString()
  return (findings as Finding[]).map((f) => ({
    ...f,
    provable: f.patchable,
    fixer: f.patchable ? 'rule' : null,
    detected_by: 'rule',
    fix_source: null,
    checks: [],
    ai_review: null,
    behaviour_change: null,
    base_code: null,
    status: 'OPEN',
    patched_code: null,
    diff: null,
    patch_rationale: null,
    poc_status: 'NOT_RUN',
    regression_status: 'NOT_RUN',
    poc_log: [],
    verification_log: [],
    created_at: t,
    updated_at: t,
  }))
}

// Initial demo state: one finding fully verified, one proven exploitable, the rest reported.
export function demoFindings(): Vuln[] {
  const t0 = Date.now() - 42 * 60_000
  const found = scannedFindings(t0)
  const pi = EVIDENCE.AI_PROMPT_INJECTION!
  const ba = EVIDENCE.AI_BROKEN_AUTH!
  return found.map((v) => {
    if (v.type === 'AI_PROMPT_INJECTION')
      return {
        ...v,
        status: 'VERIFIED',
        poc_status: 'BLOCKED',
        regression_status: 'PASSED',
        diff: pi.diff,
        patch_rationale: pi.rationale,
        fix_source: 'rule',
        checks: mockChecks(v, true),
        poc_log: stamp(pi.poc, t0 + 3 * 60_000),
        verification_log: stamp(pi.verify, t0 + 14 * 60_000),
        updated_at: new Date(t0 + 14 * 60_000).toISOString(),
      }
    if (v.type === 'AI_BROKEN_AUTH')
      return {
        ...v,
        poc_status: 'EXPLOITABLE',
        poc_log: stamp(ba.poc, t0 + 27 * 60_000),
        updated_at: new Date(t0 + 27 * 60_000).toISOString(),
      }
    return v
  })
}

import vulnBankCases from '../../../target_app/harness/cases.json'
import notesProfile from '../../../target_app/profiles/notes-api.json'
import vulnBankProfile from '../../../target_app/profiles/vuln-bank.json'
import type { TargetCase, TargetInfo, TargetsResponse, VulnType } from './types'

export type CaseKind = 'Security' | 'Regression'
export interface TestCase {
  id: string
  kind: CaseKind
  types: VulnType[]
  user: string
  input: string
  expected: string
}

export const targetCases = (t: TargetInfo): TestCase[] =>
  (t.cases ?? []).map((c) => ({
    id: c.id,
    kind: c.kind === 'security' ? 'Security' : 'Regression',
    types: c.types,
    user: c.user,
    input: c.message,
    expected: c.expected,
  }))

export const casesFor = (t: TargetInfo, type: VulnType) => targetCases(t).filter((c) => c.types.includes(type))

/** Every case a fix for `type` must pass: its exploit cases, plus the target's whole regression suite. */
export const proofCases = (t: TargetInfo, type: VulnType) =>
  targetCases(t).filter((c) => (c.kind === 'Security' ? c.types.includes(type) : true))

export const securityIds = (t: TargetInfo) => new Set(targetCases(t).filter((c) => c.kind === 'Security').map((c) => c.id))

/** "vuln-bank at 4bb7cd5", or just the name for targets without a pinned commit. */
export const targetLabel = (t: TargetInfo) => (t.commit ? `${t.name} at ${t.commit}` : t.name)

export const scopeLines = (lines: [number, number] | null) => (lines ? `${lines[0]}-${lines[1]}` : 'Whole file')

/** How findings on this target are proven, in plain words. */
export function harnessPoints(t: TargetInfo): { title: string; body: string }[] {
  if (t.harness === 'vuln-bank-agent') {
    return [
      { title: 'Runs the real code', body: 'ai_agent_deepseek.py runs unmodified in an isolated process. Only the database and the model are replaced.' },
      { title: 'Synthetic data only', body: 'A fake database serves three made-up customers (alice, bob, admin) and three transactions. No real data is ever touched.' },
      { title: 'Worst-case model', body: 'If attacker text reaches the model, we assume it obeys. A finding is exploitable when unauthorized data or instructions reach the model, which is provable from the recorded prompts and queries.' },
    ]
  }
  if (t.harness === 'function-call') {
    return [
      { title: 'Runs the real code', body: 'Each case calls one function of the practice app in a fresh, isolated process, against a throwaway copy of its code.' },
      { title: 'Synthetic data only', body: 'The app seeds its own made-up notes and files. Exploits try to reach planted markers such as BOB-PRIVATE and SECRET-KEY.' },
      { title: 'Evidence, not guesses', body: 'A case is exploited only if a protected marker actually comes back. A fix counts only if every exploit is blocked and normal requests still return what they should.' },
    ]
  }
  return [
    { title: 'Read, never run', body: 'Your code is parsed into a syntax tree and analysed. Nothing in the project is imported or executed, and your folder is never modified: fixes go to a copy.' },
    { title: 'Evidence from the code', body: 'A rule finding needs a concrete path: input pasted into SQL, a shell, eval or a file path, or request data reaching an outbound URL. AI findings must quote the real lines they point at.' },
    { title: 'Fixes proven by checks', body: 'Every fix must compile, make the rule stop flagging the code, flag nothing new, stay inside the flagged function and keep its signature. Download them all as one patch.' },
  ]
}

// Mock mode has no backend, so it serves the two curated targets from the repo files.
const asInfo = (p: typeof vulnBankProfile | typeof notesProfile): TargetInfo => ({
  id: p.id,
  kind: 'profile',
  name: p.name,
  summary: p.summary,
  module: p.module,
  source: p.source,
  commit: p.commit,
  in_scope: p.in_scope as TargetInfo['in_scope'],
  out_of_scope: p.out_of_scope,
  provable: true,
  harness: p.harness.kind as TargetInfo['harness'],
})

export const MOCK_TARGETS: TargetsResponse = {
  active: { ...asInfo(vulnBankProfile), cases: vulnBankCases.cases as TargetCase[], stats: null },
  profiles: [asInfo(vulnBankProfile), asInfo(notesProfile)],
  error: null,
}

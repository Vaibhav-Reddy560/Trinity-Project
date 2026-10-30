import casesFile from '../../../target_app/harness/cases.json'
import type { VulnType } from './types'

// Mirrors target_app/SCOPE.md. Static facts about the pinned target.
export const TARGET = {
  name: 'vuln-bank',
  repo: 'Commando-X/vuln-bank',
  commit: '4bb7cd5',
  commitFull: '4bb7cd5f46921959f034455e5615782481966177',
  commitDate: '22 Sep 2026',
  license: 'MIT',
  module: 'AI customer support',
  snapshot: 'target_app/vuln-bank/',
}

export const IN_SCOPE = [
  { file: 'ai_agent_deepseek.py', lines: '1-300', role: 'Scan, exploit, patch and verify' },
  { file: 'app.py', lines: '2328-2476', role: 'Scan only: the AI chat and system-info routes' },
]

export const OUT_OF_SCOPE = [
  'Every other file in the vuln-bank snapshot',
  'Card generation and transaction race conditions',
  'GraphQL depth limiting',
  'Behavioural fixes to the system prompt (role override is reported, not patched)',
]

export const HARNESS_POINTS = [
  {
    title: 'Runs the real code',
    body: 'ai_agent_deepseek.py runs unmodified in an isolated process. Only the database and the model are replaced.',
  },
  {
    title: 'Synthetic data only',
    body: 'A fake database serves three made-up customers (alice, bob, admin) and three transactions. No real data is ever touched.',
  },
  {
    title: 'Worst-case model',
    body: 'If attacker text reaches the model, we assume it obeys. A finding is exploitable when unauthorized data or instructions reach the model, which is provable from the recorded prompts and queries.',
  },
]

type RawCase = { id: string; kind: string; types: string[]; user: string; message: string; expected: string }

export type CaseKind = 'Security' | 'Regression'
export interface TestCase {
  id: string
  kind: CaseKind
  types: VulnType[]
  user: string
  input: string
  expected: string
}

// Same file the engine runs, so the UI can never drift from the real cases.
export const CASES: TestCase[] = (casesFile.cases as RawCase[]).map((c) => ({
  id: c.id,
  kind: c.kind === 'security' ? 'Security' : 'Regression',
  types: c.types as VulnType[],
  user: c.user,
  input: c.message,
  expected: c.expected,
}))

export const SECURITY_IDS = new Set(CASES.filter((c) => c.kind === 'Security').map((c) => c.id))

export const casesFor = (type: VulnType) => CASES.filter((c) => c.types.includes(type))

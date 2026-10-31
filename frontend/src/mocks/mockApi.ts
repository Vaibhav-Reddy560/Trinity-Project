import { MOCK_TARGETS } from '@/lib/scope'
import type { Accepted, Action, Vuln } from '@/lib/types'
import { EVIDENCE, demoFindings, mockChecks, scannedFindings, stamp } from './vulns'

// In-memory stand-in for the backend: same endpoints, same state machine, simulated delays.
let state: Vuln[] = demoFindings()
let timers: number[] = []
let current: Action | null = null

const at = (ms: number, fn: () => void) => {
  const id = window.setTimeout(() => {
    timers = timers.filter((t) => t !== id)
    fn()
    if (timers.length === 0) current = null
  }, ms)
  timers.push(id)
}
const begin = (action: Action) => {
  if (current) throw new Error(`Another action (${current}) is still running. Wait for it to finish.`)
  current = action
}
const accepted = (action: Action, vuln_id?: string): Accepted => ({ accepted: true, action, vuln_id })

function update(id: string, patch: Partial<Vuln>) {
  state = state.map((v) => (v.id === id ? { ...v, ...patch, updated_at: new Date().toISOString() } : v))
}

function find(id: string): Vuln {
  const v = state.find((x) => x.id === id)
  if (!v) throw new Error(`Finding ${id} no longer exists. Run a scan to refresh the list.`)
  return v
}

function doPoc(id: string) {
  const v = find(id)
  const ev = EVIDENCE[v.type]
  if (!ev) return update(id, { poc_status: 'NOT_RUN' })
  if (v.diff) {
    // Same as the backend: replaying against patched code keeps the original pre-patch evidence in poc_log.
    const replay = ev.verify.filter(([, msg]) => !msg.startsWith('Verified'))
    update(id, {
      poc_status: 'BLOCKED',
      verification_log: [...v.verification_log, ...stamp([['INFO', 'Exploit replayed against the patched copy'], ...replay], Date.now())],
    })
    return
  }
  update(id, { poc_status: 'EXPLOITABLE', poc_log: stamp(ev.poc, Date.now()) })
}

function doPatch(id: string) {
  const v = find(id)
  const ev = EVIDENCE[v.type]!
  update(id, { status: 'PATCHED', diff: ev.diff, patch_rationale: ev.rationale, fix_source: 'rule', checks: mockChecks(v, false) })
}

function doVerify(id: string) {
  const ev = EVIDENCE[find(id).type]!
  update(id, {
    status: 'VERIFIED',
    poc_status: 'BLOCKED',
    regression_status: 'PASSED',
    checks: mockChecks(find(id), true),
    verification_log: stamp(ev.verify, Date.now()),
  })
}

export const mockApi = {
  mode: 'mock' as const,
  health: async () => ({
    status: 'ok', busy: current !== null, action: current,
    ai: { enabled: false, provider: 'anthropic' as const, model: 'claude-opus-5-5', reason: 'Mock mode has no backend, so AI assist needs the live API.' },
  }),
  listVulns: async () => ({ vulns: structuredClone(state) }),
  getVuln: async (id: string) => structuredClone(find(id)),
  targets: async () => structuredClone(MOCK_TARGETS),
  selectTarget: async (): Promise<Accepted> => {
    throw new Error('Switching targets needs the live API. Start it with make api, then reload with VITE_USE_MOCKS unset.')
  },
  review: async (): Promise<Accepted> => {
    throw new Error('AI assist needs the live API and an ANTHROPIC_API_KEY.')
  },
  reviewAll: async (): Promise<Accepted> => {
    throw new Error('AI assist needs the live API and an ANTHROPIC_API_KEY.')
  },
  deepScan: async (): Promise<Accepted> => {
    throw new Error('AI assist needs the live API and an ANTHROPIC_API_KEY.')
  },
  fixAll: async (): Promise<Accepted> => {
    throw new Error('AI assist needs the live API and an AI key.')
  },
  patches: async () => state.filter((v) => v.diff).map((v) => v.diff).join(''),

  scan: async () => {
    begin('scan')
    const known = new Set(state.map((v) => v.id))
    at(1200, () => (state = [...state, ...scannedFindings().filter((v) => !known.has(v.id))]))
    return accepted('scan')
  },

  reset: async () => {
    begin('reset')
    timers.forEach(clearTimeout)
    timers = []
    at(400, () => (state = []))
    return accepted('reset')
  },

  runAll: async () => {
    begin('run-all')
    const needsScan = state.length === 0
    if (needsScan) state = scannedFindings()
    const targets = state.filter((v) => v.patchable && v.status !== 'VERIFIED').map((v) => v.id)
    targets.forEach((id, i) => {
      const t = i * 3300 + 600
      if (find(id).status !== 'PATCHED') {
        at(t, () => doPoc(id))
        at(t + 1100, () => doPatch(id))
      }
      at(t + 2200, () => doVerify(id))
    })
    if (targets.length === 0) at(300, () => {})
    return accepted('run-all')
  },

  poc: async (id: string) => {
    if (!find(id).provable) throw new Error('This target has no exploit case for this finding type.')
    begin('poc')
    at(900, () => doPoc(id))
    return accepted('poc', id)
  },

  patch: async (id: string) => {
    const v = find(id)
    if (!v.patchable) throw new Error('No rule covers this code, and AI fixes need the live API.')
    if (v.diff) throw new Error('This finding is already patched. Reset the workspace to patch it again.')
    if (v.poc_status !== 'EXPLOITABLE') throw new Error('Run the exploit first. Only proven weaknesses can be patched.')
    begin('patch')
    at(1000, () => doPatch(id))
    return accepted('patch', id)
  },

  verify: async (id: string) => {
    if (find(id).status !== 'PATCHED') throw new Error('Apply the patch before verifying.')
    begin('verify')
    at(1200, () => doVerify(id))
    return accepted('verify', id)
  },
}

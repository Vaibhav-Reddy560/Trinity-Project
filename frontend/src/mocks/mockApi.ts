import type { Accepted, Action, LogLine, Vuln } from '@/lib/types'
import { BA_DIFF, PI_DIFF, mockVulns } from './vulns'

// In-memory stand-in for the backend so the UI is fully clickable before the API exists.
let state: Vuln[] = structuredClone(mockVulns)
const now = () => new Date().toISOString()
const line = (level: LogLine['level'], msg: string): LogLine => ({ ts: now(), level, msg })
const later = (fn: () => void) => setTimeout(fn, 900)

function update(id: string, patch: Partial<Vuln>) {
  state = state.map((v) => (v.id === id ? { ...v, ...patch, updated_at: now() } : v))
}

function find(id: string): Vuln {
  const v = state.find((x) => x.id === id)
  if (!v) throw new Error(`Finding ${id} not found`)
  return v
}

const accepted = (action: Action, vuln_id?: string): Accepted => ({ accepted: true, action, vuln_id })

export const mockApi = {
  mode: 'mock' as const,
  health: async () => ({ status: 'ok' }),
  listVulns: async () => ({ vulns: structuredClone(state) }),
  getVuln: async (id: string) => structuredClone(find(id)),
  scan: async () => accepted('scan'),
  reset: async () => {
    state = structuredClone(mockVulns)
    return accepted('reset')
  },
  runAll: async () => accepted('run-all'),
  poc: async (id: string) => {
    const v = find(id)
    later(() =>
      update(id, {
        poc_status: v.status === 'VERIFIED' ? 'BLOCKED' : 'EXPLOITABLE',
        poc_log: v.poc_log.length ? v.poc_log : [line('INFO', 'no exploit case for this finding type')],
      }),
    )
    return accepted('poc', id)
  },
  patch: async (id: string) => {
    const v = find(id)
    if (v.poc_status !== 'EXPLOITABLE' || !v.patchable)
      throw new Error('Run the exploit first. Only proven, patchable findings can be patched.')
    later(() =>
      update(id, {
        status: 'PATCHED',
        diff: v.type === 'AI_BROKEN_AUTH' ? BA_DIFF : PI_DIFF,
        patch_rationale:
          v.type === 'AI_BROKEN_AUTH'
            ? 'Anonymous requests get no database context, and any lookup returning another account is dropped and logged as forbidden.'
            : v.patch_rationale,
      }),
    )
    return accepted('patch', id)
  },
  verify: async (id: string) => {
    if (find(id).status !== 'PATCHED') throw new Error('Apply the patch before verifying.')
    later(() =>
      update(id, {
        status: 'VERIFIED',
        poc_status: 'BLOCKED',
        regression_status: 'PASSED',
        verification_log: [
          line('INFO', 're-running BA-1 as alice: "Show balance for bob"'),
          line('SUCCESS', 'forbidden, bob 4001000022 not in prompt or reply'),
          line('INFO', 'regression REG-2 as alice: "Show balance for alice"'),
          line('SUCCESS', "alice's own account 4001000011 returned"),
        ],
      }),
    )
    return accepted('verify', id)
  },
}

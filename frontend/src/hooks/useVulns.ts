import { useCallback, useEffect, useRef, useState } from 'react'
import { AI_OFF } from '@/lib/aiContext'
import { api } from '@/lib/api'
import { SEVERITY_ORDER } from '@/lib/pipeline'
import { MOCK_TARGETS } from '@/lib/scope'
import type { AIStatus, Action, TargetSelection, TargetsResponse, Vuln } from '@/lib/types'

export type ApiState = 'mock' | 'online' | 'offline'
export type Pending = { action: Action; id?: string } | null
export type Notice = { key: number; tone: 'info' | 'success' | 'error'; text: string }

const STARTED: Record<Action, string> = {
  scan: 'Scanning target',
  poc: 'Running exploit',
  patch: 'Applying patch',
  verify: 'Verifying fix',
  'run-all': 'Running full pipeline',
  reset: 'Resetting workspace',
  select: 'Loading target and scanning',
  review: 'AI is reviewing this finding',
  'review-all': 'AI is reviewing every finding',
  'deep-scan': 'AI is reading the code for logic flaws',
  'fix-all': 'Fixing and proving every open finding, one at a time',
}
const FINISHED: Record<Action, string> = {
  scan: 'Scan finished',
  poc: 'Exploit run finished',
  patch: 'Patch applied',
  verify: 'Verification finished',
  'run-all': 'Full pipeline finished',
  reset: 'Workspace reset',
  select: 'Target loaded and scanned',
  review: 'AI review ready',
  'review-all': 'AI reviews ready',
  'deep-scan': 'AI deep scan finished',
  'fix-all': 'Fix all finished',
}

/** What the finished action actually achieved, read back from the data it changed. */
function outcome(action: Action, all: Vuln[] | null, id: string | undefined, t: TargetsResponse | null, startedAt: number): [Notice['tone'], string] {
  const v = all?.find((x) => x.id === id)
  if (action === 'fix-all' && all) {
    const verified = all.filter((x) => x.status === 'VERIFIED').length
    const failed = all.filter((x) => x.status === 'FAILED').length
    return [failed ? 'error' : 'success', `${verified} of ${all.length} findings fixed and verified${failed ? `; ${failed} failed their checks and were left as they were` : ''}`]
  }
  if (action === 'select' && t?.error && Date.parse(t.error.at) >= startedAt - 1000) return ['error', t.error.message]
  if (action === 'patch' && v) {
    if (v.status !== 'PATCHED') return ['error', 'No fix applied. The Patch tab log says why.']
    return ['success', v.fix_source === 'ai' ? 'AI fix passed every static check and was applied' : 'Patch applied']
  }
  if (action === 'verify' && v)
    return v.status === 'VERIFIED' ? ['success', 'Verified: every check passed'] : ['error', 'Not verified: a check failed. See the Tests tab.']
  if (action === 'review' && v?.ai_review?.error) return ['error', `AI review failed: ${v.ai_review.error}`]
  const deep = t?.active.deep_scan
  if (action === 'deep-scan' && deep) {
    if (deep.errors.length && !deep.added) return ['error', `AI deep scan failed: ${deep.errors[0]}`]
    return ['success', `AI deep scan: ${deep.added} new finding${deep.added === 1 ? '' : 's'} in ${deep.files} file${deep.files === 1 ? '' : 's'}`]
  }
  return ['success', FINISHED[action]]
}

const sortVulns = (vs: Vuln[]) =>
  [...vs].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.line_number - b.line_number)

// After an action, polls GET /vulns until GET /health reports the backend idle (PROJECT_CONTEXT.md §7).
export function useVulns() {
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [loaded, setLoaded] = useState(false)
  const [apiState, setApiState] = useState<ApiState>(api.mode === 'mock' ? 'mock' : 'offline')
  const [pending, setPending] = useState<Pending>(null)
  const [notices, setNotices] = useState<Notice[]>([])
  const [targets, setTargets] = useState<TargetsResponse>(MOCK_TARGETS)
  const [targetsLoaded, setTargetsLoaded] = useState(false)
  const [ai, setAi] = useState<AIStatus>(AI_OFF)
  const pollRef = useRef<number | null>(null)
  const keyRef = useRef(0)

  const notify = useCallback((tone: Notice['tone'], text: string, replaces?: number) => {
    const key = ++keyRef.current
    setNotices((n) => [...n.filter((x) => x.key !== replaces).slice(-1), { key, tone, text }])
    if (tone !== 'info') window.setTimeout(() => setNotices((n) => n.filter((x) => x.key !== key)), 4200)
    return key
  }, [])

  const load = useCallback(async () => {
    try {
      const { vulns } = await api.listVulns()
      const sorted = sortVulns(vulns)
      setVulns(sorted)
      setLoaded(true)
      if (api.mode === 'live') setApiState('online')
      return sorted
    } catch {
      if (api.mode === 'live') setApiState('offline')
      setLoaded(true)
      return null
    }
  }, [])

  const loadTargets = useCallback(async () => {
    try {
      const t = await api.targets()
      setTargets(t)
      return t
    } catch {
      return null
    } finally {
      setTargetsLoaded(true)
    }
  }, [])

  const run = useCallback(
    async (action: Action, id?: string, selection?: TargetSelection) => {
      const call = {
        select: () => api.selectTarget(selection!),
        scan: () => api.scan(),
        reset: () => api.reset(),
        'run-all': () => api.runAll(),
        poc: () => api.poc(id!),
        patch: () => api.patch(id!),
        verify: () => api.verify(id!),
        review: () => api.review(id!),
        'review-all': () => api.reviewAll(),
        'deep-scan': () => api.deepScan(),
        'fix-all': () => api.fixAll(),
      }[action]
      try {
        await call()
      } catch (e) {
        notify('error', e instanceof Error ? e.message : 'The request failed. Check that the API is running on port 8000.')
        return
      }
      const started = notify('info', STARTED[action])
      const startedAt = Date.now()
      setPending({ action, id })
      if (pollRef.current) window.clearInterval(pollRef.current)
      let ticks = 0
      pollRef.current = window.setInterval(async () => {
        ticks++
        await load()
        const health = await api.health().catch(() => null)
        if (health) setAi(health.ai)
        // AI calls take a while: allow up to 15 minutes of polling instead of ~3.
        if ((health && !health.busy) || ticks > 1300) {
          window.clearInterval(pollRef.current!)
          pollRef.current = null
          const latest = await load()
          const t = await loadTargets()
          setPending(null)
          if (!health) notify('error', 'Lost contact with the API before the action finished.', started)
          else notify(...outcome(action, latest ?? null, id, t, startedAt), started)
        }
      }, 700)
    },
    [load, loadTargets, notify],
  )

  useEffect(() => {
    void load()
    void loadTargets()
    void api.health().then((h) => setAi(h.ai)).catch(() => {})
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
  }, [load, loadTargets])

  const reload = useCallback(async () => {
    await Promise.all([load(), loadTargets(), api.health().then((h) => setAi(h.ai)).catch(() => {})])
  }, [load, loadTargets])

  return { vulns, loaded: loaded && targetsLoaded, apiState, pending, notices, run, reload, targets, ai }
}

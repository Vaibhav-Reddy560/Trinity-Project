import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '@/lib/api'
import { SEVERITY_ORDER } from '@/lib/pipeline'
import type { Action, Vuln } from '@/lib/types'

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
}
const FINISHED: Record<Action, string> = {
  scan: 'Scan finished',
  poc: 'Exploit run finished',
  patch: 'Patch applied',
  verify: 'Verification finished',
  'run-all': 'Full pipeline finished',
  reset: 'Workspace reset',
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
      return JSON.stringify(sorted)
    } catch {
      if (api.mode === 'live') setApiState('offline')
      setLoaded(true)
      return null
    }
  }, [])

  const run = useCallback(
    async (action: Action, id?: string) => {
      const call = {
        scan: () => api.scan(),
        reset: () => api.reset(),
        'run-all': () => api.runAll(),
        poc: () => api.poc(id!),
        patch: () => api.patch(id!),
        verify: () => api.verify(id!),
      }[action]
      try {
        await call()
      } catch (e) {
        notify('error', e instanceof Error ? e.message : 'The request failed. Check that the API is running on port 8000.')
        return
      }
      const started = notify('info', STARTED[action])
      setPending({ action, id })
      if (pollRef.current) window.clearInterval(pollRef.current)
      let ticks = 0
      pollRef.current = window.setInterval(async () => {
        ticks++
        await load()
        const health = await api.health().catch(() => null)
        if ((health && !health.busy) || ticks > 240) {
          window.clearInterval(pollRef.current!)
          pollRef.current = null
          await load()
          setPending(null)
          notify(health ? 'success' : 'error', health ? FINISHED[action] : 'Lost contact with the API before the action finished.', started)
        }
      }, 700)
    },
    [load, notify],
  )

  useEffect(() => {
    void load()
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
  }, [load])

  return { vulns, loaded, apiState, pending, notices, run, reload: load }
}

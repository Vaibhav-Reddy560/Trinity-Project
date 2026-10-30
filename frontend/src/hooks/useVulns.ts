import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '@/lib/api'
import { SEVERITY_ORDER } from '@/lib/pipeline'
import type { Vuln } from '@/lib/types'

export type ApiState = 'mock' | 'online' | 'offline'

const sortVulns = (vs: Vuln[]) =>
  [...vs].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.line_number - b.line_number)

// Polls GET /vulns every second after an action until nothing changes for 3 polls (PROJECT_CONTEXT.md §7).
export function useVulns() {
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [apiState, setApiState] = useState<ApiState>(api.mode === 'mock' ? 'mock' : 'offline')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const pollRef = useRef<number | null>(null)

  const load = useCallback(async () => {
    try {
      const { vulns } = await api.listVulns()
      const sorted = sortVulns(vulns)
      setVulns(sorted)
      if (api.mode === 'live') setApiState('online')
      return JSON.stringify(sorted)
    } catch {
      if (api.mode === 'live') setApiState('offline')
      return null
    }
  }, [])

  const poll = useCallback(() => {
    if (pollRef.current) window.clearInterval(pollRef.current)
    let last: string | null = null
    let stable = 0
    setBusy(true)
    pollRef.current = window.setInterval(async () => {
      const snap = await load()
      stable = snap === last ? stable + 1 : 0
      last = snap
      if (stable >= 3) {
        window.clearInterval(pollRef.current!)
        pollRef.current = null
        setBusy(false)
      }
    }, 1000)
  }, [load])

  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      setError(null)
      try {
        await fn()
        poll()
      } catch (e) {
        setError(e instanceof Error ? e.message : 'The request failed. Check that the API is running on port 8000.')
      }
    },
    [poll],
  )

  useEffect(() => {
    void load()
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
  }, [load])

  return { vulns, apiState, busy, error, run }
}

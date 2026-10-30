import { mockApi } from '@/mocks/mockApi'
import type { Accepted, Health, Vuln } from './types'

// The only way the UI talks to the backend. Endpoints: PROJECT_CONTEXT.md §7.
// Live API by default; set VITE_USE_MOCKS=true to run on in-memory sample data.
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === 'true'

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

const OFFLINE = 'Cannot reach the PatchProof API on port 8000. Start it with `make api`.'

async function request<T>(path: string, method: 'GET' | 'POST' = 'GET'): Promise<T> {
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, { method })
  } catch {
    throw new ApiError(0, OFFLINE)
  }
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    if (!body?.detail && res.status >= 500) throw new ApiError(res.status, OFFLINE)
    throw new ApiError(res.status, body?.detail ?? res.statusText)
  }
  return res.json()
}

const liveApi = {
  mode: 'live' as const,
  health: () => request<Health>('/health'),
  listVulns: () => request<{ vulns: Vuln[] }>('/vulns'),
  getVuln: (id: string) => request<Vuln>(`/vulns/${id}`),
  scan: () => request<Accepted>('/scan', 'POST'),
  poc: (id: string) => request<Accepted>(`/poc/${id}`, 'POST'),
  patch: (id: string) => request<Accepted>(`/patch/${id}`, 'POST'),
  verify: (id: string) => request<Accepted>(`/verify/${id}`, 'POST'),
  runAll: () => request<Accepted>('/run-all', 'POST'),
  reset: () => request<Accepted>('/reset', 'POST'),
}

export const api: Omit<typeof liveApi, 'mode'> & { mode: 'live' | 'mock' } = USE_MOCKS ? mockApi : liveApi

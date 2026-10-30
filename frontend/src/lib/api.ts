import { mockApi } from '@/mocks/mockApi'
import type { Accepted, Vuln } from './types'

// The only way the UI talks to the backend. Endpoints: PROJECT_CONTEXT.md §7.
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false'

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, method: 'GET' | 'POST' = 'GET'): Promise<T> {
  const res = await fetch(`/api/v1${path}`, { method })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new ApiError(res.status, body.detail ?? res.statusText)
  }
  return res.json()
}

const liveApi = {
  mode: 'live' as const,
  health: () => request<{ status: string }>('/health'),
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

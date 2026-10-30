import { Bug, Crosshair, FileText, LayoutDashboard, ScrollText, type LucideIcon } from 'lucide-react'
import type { ApiState } from '@/hooks/useVulns'
import { href, type Route } from '@/lib/router'
import { TARGET } from '@/lib/scope'
import { cn } from '@/lib/utils'
import { Logo } from './Logo'

type NavKey = 'overview' | 'findings' | 'scope' | 'activity' | 'report'
const NAV: { key: NavKey; label: string; icon: LucideIcon; href: string }[] = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard, href: href.overview },
  { key: 'findings', label: 'Findings', icon: Bug, href: href.findings },
  { key: 'scope', label: 'Target & scope', icon: Crosshair, href: href.scope },
  { key: 'activity', label: 'Activity', icon: ScrollText, href: href.activity },
  { key: 'report', label: 'Report', icon: FileText, href: href.report },
]

const activeKey = (r: Route): NavKey => (r.name === 'finding' ? 'findings' : r.name)

const modeInfo: Record<ApiState, { label: string; detail: string; dot: string }> = {
  mock: { label: 'Mock data', detail: 'Sample findings, no backend needed', dot: 'bg-amber shadow-[0_0_8px_var(--color-amber)]' },
  online: { label: 'Live API', detail: 'Connected on port 8000', dot: 'bg-signal shadow-[0_0_8px_var(--color-signal)]' },
  offline: { label: 'API offline', detail: 'Start it with make api', dot: 'bg-ash' },
}

export function Sidebar({ route, counts, apiState }: {
  route: Route
  counts: Partial<Record<NavKey, number>>
  apiState: ApiState
}) {
  const active = activeKey(route)
  return (
    <aside className="no-print flex flex-col border-border bg-void/85 backdrop-blur lg:fixed lg:inset-y-0 lg:left-0 lg:w-64 lg:border-r">
      <div className="flex items-center justify-between px-5 pt-5 pb-4 lg:pb-6">
        <Logo />
      </div>

      <nav aria-label="Main" className="overflow-x-auto border-y border-border lg:overflow-visible lg:border-0 lg:px-3">
        <ul className="flex gap-1 px-3 py-2 lg:flex-col lg:px-0 lg:py-0">
          {NAV.map(({ key, label, icon: Icon, href: to }) => {
            const on = key === active
            return (
              <li key={key}>
                <a href={to} aria-current={on ? 'page' : undefined}
                  className={cn(
                    'group relative flex h-10 items-center gap-3 px-3 text-sm whitespace-nowrap transition-colors',
                    on ? 'bg-blood-950 text-bone' : 'text-ash hover:bg-blood-950/50 hover:text-bone',
                  )}>
                  <span aria-hidden className={cn('absolute inset-y-1.5 left-0 w-0.5', on ? 'bg-signal shadow-[0_0_8px_var(--color-signal)]' : 'bg-transparent')} />
                  <Icon className={cn('size-4', on ? 'text-signal' : 'text-ash group-hover:text-bone')} aria-hidden />
                  <span className="font-medium">{label}</span>
                  {counts[key] !== undefined && (
                    <span className="ml-auto text-xs text-ash tabular-nums">{counts[key]}</span>
                  )}
                </a>
              </li>
            )
          })}
        </ul>
      </nav>

      <div className="mt-auto hidden space-y-3 p-4 lg:block">
        <div className="border border-border bg-panel/80 p-4">
          <p className="label">Target</p>
          <p className="mt-1 text-sm font-semibold text-bone">{TARGET.name}</p>
          <p className="text-xs text-ash tabular-nums">commit {TARGET.commit}</p>
          <p className="label mt-3">Module</p>
          <p className="mt-1 text-sm text-bone">{TARGET.module}</p>
        </div>
        <div className="flex items-start gap-3 border border-border bg-panel/80 p-4" role="status">
          <span aria-hidden className={cn('mt-1.5 size-2 shrink-0 rounded-full', modeInfo[apiState].dot)} />
          <div>
            <p className="text-sm text-bone">{modeInfo[apiState].label}</p>
            <p className="text-xs text-ash">{modeInfo[apiState].detail}</p>
          </div>
        </div>
      </div>
    </aside>
  )
}

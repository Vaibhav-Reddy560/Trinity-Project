import { Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Highlight, headline, levelIcon, levelTone } from '@/components/EvidenceLog'
import { PageHeader } from '@/components/Panel'
import { Input } from '@/components/ui/input'
import { activityOf } from '@/lib/activity'
import { ago, clock, typeName } from '@/lib/format'
import { href } from '@/lib/router'
import type { LogLevel, Vuln } from '@/lib/types'
import { cn } from '@/lib/utils'

const LEVELS: { key: 'all' | LogLevel; label: string }[] = [
  { key: 'all', label: 'Everything' },
  { key: 'ERROR', label: 'Leaks' },
  { key: 'WARN', label: 'Warnings' },
  { key: 'SUCCESS', label: 'Passed checks' },
  { key: 'INFO', label: 'Steps' },
]

export function ActivityPage({ vulns }: { vulns: Vuln[] }) {
  const [level, setLevel] = useState<'all' | LogLevel>('all')
  const [query, setQuery] = useState('')
  const all = useMemo(() => activityOf(vulns), [vulns])
  const q = query.trim().toLowerCase()
  const shown = all.filter((a) => (level === 'all' || a.level === level) && (!q || a.msg.toLowerCase().includes(q)))
  const counts = Object.fromEntries(LEVELS.map((l) => [l.key, l.key === 'all' ? all.length : all.filter((a) => a.level === l.key).length]))

  return (
    <>
      <PageHeader
        title="Activity"
        description={<p>Every exploit and verification step across all findings, newest first. This is the audit trail behind each verdict.</p>}
      />

      <section className="panel" aria-label="Activity log">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3 border-b border-border px-5 py-4">
          <label className="relative w-full sm:w-72">
            <span className="sr-only">Search activity</span>
            <Search aria-hidden className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ash" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search messages" className="h-9 pl-9" />
          </label>
          <div role="group" aria-label="Filter by type" className="flex flex-wrap gap-1">
            {LEVELS.map((l) => (
              <button key={l.key} type="button" aria-pressed={level === l.key} onClick={() => setLevel(l.key)}
                className={cn('flex h-8 items-center gap-2 border px-3 text-sm', level === l.key ? 'border-signal bg-blood-800 text-bone' : 'border-border text-ash hover:text-bone')}>
                {l.label}
                <span className="text-xs text-ash tabular-nums">{counts[l.key]}</span>
              </button>
            ))}
          </div>
        </div>

        {shown.length === 0 ? (
          <p className="px-5 py-10 text-center text-ash">
            {all.length === 0 ? 'No activity yet. Run an exploit or the full pipeline to start the audit trail.' : 'Nothing matches this filter.'}
          </p>
        ) : (
          <ol className="divide-y divide-border/60">
            {shown.map((a, i) => {
              const Icon = levelIcon[a.level]
              return (
                <li key={i} className="grid grid-cols-[1.25rem_1fr] gap-x-4 gap-y-1 px-5 py-3.5 md:grid-cols-[6rem_1.25rem_1fr_14rem] md:items-start">
                  <time dateTime={a.ts} className="hidden text-sm text-ash tabular-nums md:block">{clock(a.ts)}</time>
                  <Icon className={cn('mt-0.5 size-4', levelTone[a.level])} aria-hidden />
                  <p className={cn('text-sm leading-relaxed', levelTone[a.level])}><Highlight text={headline(a.msg)} /></p>
                  <p className="col-start-2 text-xs text-ash md:col-start-auto md:text-right">
                    <a href={href.finding(a.vuln.id)} className="text-bone/85 hover:text-ember">{typeName[a.vuln.type]}</a>
                    <span className="block">{a.phase} / {ago(a.ts)}</span>
                  </p>
                </li>
              )
            })}
          </ol>
        )}
      </section>
    </>
  )
}

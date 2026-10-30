import { ChevronRight, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { PageHeader } from '@/components/Panel'
import { Pill, SeverityTag, VerdictPill } from '@/components/Pills'
import { Input } from '@/components/ui/input'
import type { Pending } from '@/hooks/useVulns'
import { SEVERITIES, codeLocation, severityLabel, typeName } from '@/lib/format'
import { verdictFor, type Verdict } from '@/lib/pipeline'
import { href } from '@/lib/router'
import type { Severity, Vuln } from '@/lib/types'
import { cn } from '@/lib/utils'
import { EmptyFindings } from './EmptyFindings'

const STATUS_FILTERS: { key: 'all' | Verdict; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'Open', label: 'Not tested' },
  { key: 'Exploitable', label: 'Exploitable' },
  { key: 'Patched', label: 'Patched' },
  { key: 'Verified', label: 'Verified' },
  { key: 'Report only', label: 'Report only' },
]

function ExploitCell({ v }: { v: Vuln }) {
  if (!v.patchable) return <span className="text-ash">No exploit</span>
  if (v.poc_status === 'EXPLOITABLE') return <Pill tone="amber" pulse>Reproduced</Pill>
  if (v.poc_status === 'BLOCKED') return <Pill tone="neutral">Blocked</Pill>
  return <span className="text-ash">Not run</span>
}

function PatchCell({ v }: { v: Vuln }) {
  if (!v.patchable) return <span className="text-ash">Report only</span>
  if (v.diff) return <Pill tone="signal">Applied</Pill>
  return <span className="text-ash">Not patched</span>
}

function TestsCell({ v }: { v: Vuln }) {
  if (!v.patchable) return <span className="text-ash">—</span>
  if (v.status === 'VERIFIED') return <Pill tone="hot">Passed</Pill>
  if (v.status === 'FAILED') return <Pill tone="fail">Failed</Pill>
  return <span className="text-ash">Not run</span>
}

export function FindingsPage({ vulns, pending, onScan }: { vulns: Vuln[]; pending: Pending; onScan: () => void }) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<'all' | Severity>('all')
  const [status, setStatus] = useState<'all' | Verdict>('all')

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return vulns.filter(
      (v) =>
        (severity === 'all' || v.severity === severity) &&
        (status === 'all' || verdictFor(v) === status) &&
        (!q || [v.title, typeName[v.type], v.cwe, v.file_path].some((t) => t.toLowerCase().includes(q))),
    )
  }, [vulns, query, severity, status])

  return (
    <>
      <PageHeader
        title="Findings"
        description={<p>Weaknesses found in the AI customer support module. Open one to see its exploit evidence, the patch and the test results.</p>}
      />

      {vulns.length === 0 ? (
        <EmptyFindings pending={pending} onScan={onScan} />
      ) : (
        <section className="panel" aria-label="Findings table">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3 border-b border-border px-5 py-4">
            <label className="relative w-full sm:w-72">
              <span className="sr-only">Search findings</span>
              <Search aria-hidden className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ash" />
              <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by name, CWE or file" className="h-9 pl-9" />
            </label>

            <div role="group" aria-label="Filter by severity" className="flex flex-wrap gap-1">
              {(['all', ...SEVERITIES] as const).map((s) => (
                <button key={s} type="button" aria-pressed={severity === s} onClick={() => setSeverity(s)}
                  className={cn('h-8 border px-3 text-sm', severity === s ? 'border-signal bg-blood-800 text-bone' : 'border-border text-ash hover:text-bone')}>
                  {s === 'all' ? 'All severities' : severityLabel[s]}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 text-sm text-ash">
              Status
              <select value={status} onChange={(e) => setStatus(e.target.value as 'all' | Verdict)}
                className="h-8 border border-border bg-void px-2 text-sm text-bone">
                {STATUS_FILTERS.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
              </select>
            </label>

            <p className="ml-auto text-sm text-ash tabular-nums" aria-live="polite">
              {shown.length} of {vulns.length} shown
            </p>
          </div>

          {shown.length === 0 ? (
            <p className="px-5 py-10 text-center text-ash">No findings match these filters. Clear the search or choose another status.</p>
          ) : (
            <>
              <table className="hidden w-full border-collapse text-sm md:table">
                <thead>
                  <tr className="border-b border-border text-left text-xs text-ash">
                    <th scope="col" className="py-3 pr-4 pl-5 font-medium">Severity</th>
                    <th scope="col" className="py-3 pr-4 font-medium">Finding</th>
                    <th scope="col" className="py-3 pr-4 font-medium">Location</th>
                    <th scope="col" className="py-3 pr-4 font-medium">Exploit</th>
                    <th scope="col" className="py-3 pr-4 font-medium">Patch</th>
                    <th scope="col" className="py-3 pr-4 font-medium">Tests</th>
                    <th scope="col" className="py-3 pr-5"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {shown.map((v) => (
                    <tr key={v.id} className="group cursor-pointer transition-colors hover:bg-blood-950/70"
                      onClick={() => (window.location.hash = href.finding(v.id))}>
                      <td className="py-4 pr-4 pl-5 align-top"><SeverityTag severity={v.severity} /></td>
                      <td className="py-4 pr-4 align-top">
                        <a href={href.finding(v.id)} className="font-semibold text-bone group-hover:text-ember" onClick={(e) => e.stopPropagation()}>
                          {typeName[v.type]}
                        </a>
                        <p className="mt-1 text-ash">{v.title}</p>
                      </td>
                      <td className="py-4 pr-4 align-top text-bone/80 tabular-nums">
                        {codeLocation(v)}
                        <p className="mt-1 text-xs text-ash">{v.cwe}</p>
                      </td>
                      <td className="py-4 pr-4 align-top"><ExploitCell v={v} /></td>
                      <td className="py-4 pr-4 align-top"><PatchCell v={v} /></td>
                      <td className="py-4 pr-4 align-top"><TestsCell v={v} /></td>
                      <td className="py-4 pr-5 align-top"><ChevronRight aria-hidden className="size-4 text-ash group-hover:text-ember" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <ul className="divide-y divide-border/60 md:hidden">
                {shown.map((v) => (
                  <li key={v.id}>
                    <a href={href.finding(v.id)} className="block px-5 py-4 hover:bg-blood-950/70">
                      <div className="flex items-center justify-between gap-3">
                        <SeverityTag severity={v.severity} />
                        <VerdictPill verdict={verdictFor(v)} />
                      </div>
                      <p className="mt-2 font-semibold text-bone">{typeName[v.type]}</p>
                      <p className="mt-1 text-sm text-ash">{v.title}</p>
                      <p className="mt-2 text-xs text-ash tabular-nums">{codeLocation(v)} / {v.cwe}</p>
                    </a>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}
    </>
  )
}

import { severityColor, severityLabel, verdictFor } from '@/lib/pipeline'
import type { Vuln } from '@/lib/types'
import { cn } from '@/lib/utils'

const verdictText = {
  Verified: 'text-phosphor',
  Failed: 'text-ember',
  Patched: 'text-signal',
  Exploitable: 'text-amber',
  Blocked: 'text-bone',
  Open: 'text-ash',
} as const

export function VulnList({ vulns, selectedId, onSelect }: {
  vulns: Vuln[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  if (vulns.length === 0) {
    return <p className="px-4 py-6 text-sm text-ash">No findings yet. Run a scan to inspect the target.</p>
  }

  return (
    <ul className="flex flex-col gap-1.5" aria-label="Findings">
      {vulns.map((v) => {
        const selected = v.id === selectedId
        const verdict = verdictFor(v)
        return (
          <li key={v.id}>
            <button
              type="button"
              onClick={() => onSelect(v.id)}
              aria-current={selected ? 'true' : undefined}
              className={cn(
                'group relative grid w-full grid-cols-[3px_1fr] gap-x-3 py-3 pr-3 text-left transition-colors',
                selected ? 'bg-blood-950' : 'hover:bg-blood-950/60',
              )}
            >
              <span
                aria-hidden
                className="row-span-3 h-full"
                style={{
                  background: severityColor[v.severity],
                  boxShadow: selected ? '0 0 10px var(--color-signal)' : undefined,
                }}
              />
              <span className="flex items-baseline justify-between gap-3 text-xs">
                <span style={{ color: severityColor[v.severity] }} className="font-semibold">
                  {severityLabel[v.severity]}
                </span>
                <span className={cn('font-medium', verdictText[verdict], verdict === 'Exploitable' && 'pulse-amber')}>
                  {verdict}
                </span>
              </span>
              <span className={cn('mt-1 text-[0.9375rem] leading-snug font-medium', selected ? 'text-bone' : 'text-bone/85')}>
                {v.title}
              </span>
              <span className="mt-1 text-xs text-ash tabular-nums">
                {v.file_path}:{v.line_number}
                <span className="text-blood-600"> / </span>
                {v.cwe}
                {!v.patchable && <span className="text-blood-600"> / report only</span>}
              </span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

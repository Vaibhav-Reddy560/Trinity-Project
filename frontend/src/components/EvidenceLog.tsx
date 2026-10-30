import { Check, ChevronRight, CircleAlert, Info, TriangleAlert } from 'lucide-react'
import { Fragment } from 'react'
import { clock } from '@/lib/format'
import type { LogLine } from '@/lib/types'
import { cn } from '@/lib/utils'

export const levelTone: Record<LogLine['level'], string> = {
  INFO: 'text-bone/75',
  WARN: 'text-amber',
  ERROR: 'text-ember',
  SUCCESS: 'text-phosphor',
}
export const levelIcon = { INFO: Info, WARN: TriangleAlert, ERROR: CircleAlert, SUCCESS: Check }
export const levelName: Record<LogLine['level'], string> = {
  INFO: 'Step',
  WARN: 'Warning',
  ERROR: 'Leak',
  SUCCESS: 'Passed',
}

// Account numbers in the synthetic data are 10 digits; highlight them wherever they appear.
const SENSITIVE = /(\b\d{10}\b)/g

export function Highlight({ text }: { text: string }) {
  return (
    <>
      {text.split(SENSITIVE).map((part, i) =>
        i % 2 ? (
          <mark key={i} className="bg-amber/15 px-0.5 text-amber" title="Customer account number">{part}</mark>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </>
  )
}

export const headline = (msg: string) => msg.split('\n', 1)[0]

export function EvidenceLog({ lines, empty }: { lines: LogLine[]; empty: string }) {
  if (lines.length === 0) return <p className="text-sm text-ash">{empty}</p>
  return (
    <ol className="divide-y divide-border/50 border border-border bg-void/70" role="log" aria-live="polite">
      {lines.map((l, i) => {
        const Icon = levelIcon[l.level]
        const [first, ...rest] = l.msg.split('\n')
        return (
          <li key={i} className={cn('grid grid-cols-[4.75rem_1.25rem_minmax(0,1fr)] items-start gap-3 px-4 py-2.5 text-sm', levelTone[l.level])}>
            <time dateTime={l.ts} className="text-xs leading-5 text-ash tabular-nums">{clock(l.ts)}</time>
            <Icon className="mt-0.5 size-4" aria-label={levelName[l.level]} />
            <div className="min-w-0">
              <p className="leading-relaxed break-words"><Highlight text={first} /></p>
              {rest.length > 0 && (
                <details className="group mt-2">
                  <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-ash hover:text-bone [&::-webkit-details-marker]:hidden">
                    <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" aria-hidden />
                    Captured context ({rest.length} lines)
                  </summary>
                  <pre className="code mt-2 overflow-x-auto border-l-2 border-signal/60 bg-blood-950/50 px-3 py-2 text-bone/85">
                    <Highlight text={rest.join('\n')} />
                  </pre>
                </details>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

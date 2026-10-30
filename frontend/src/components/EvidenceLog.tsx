import type { LogLine } from '@/lib/types'
import { cn } from '@/lib/utils'

const levelTone: Record<LogLine['level'], string> = {
  INFO: 'text-ash',
  WARN: 'text-amber',
  ERROR: 'text-ember',
  SUCCESS: 'text-phosphor',
}
const levelMark: Record<LogLine['level'], string> = {
  INFO: '·',
  WARN: '!',
  ERROR: '×',
  SUCCESS: '✓',
}

function Section({ title, lines }: { title: string; lines: LogLine[] }) {
  if (lines.length === 0) return null
  return (
    <section className="mb-4 last:mb-0">
      <h3 className="mb-2 text-xs text-signal">{title}</h3>
      <ol className="space-y-1">
        {lines.map((l, i) => (
          <li key={i} className={cn('grid grid-cols-[1rem_1fr] gap-2 text-[0.8125rem] leading-relaxed', levelTone[l.level])}>
            <span aria-hidden className="text-center">{levelMark[l.level]}</span>
            <span className="break-words">
              <span className="sr-only">{l.level.toLowerCase()}: </span>
              {l.msg}
            </span>
          </li>
        ))}
      </ol>
    </section>
  )
}

export function EvidenceLog({ poc, verification }: { poc: LogLine[]; verification: LogLine[] }) {
  return (
    <div className="panel flex min-h-0 flex-col">
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-sm text-bone">Evidence</h2>
        <span className="flex items-center gap-1.5 text-xs text-ash">
          <span aria-hidden className="size-1.5 rounded-full bg-signal shadow-[0_0_6px_var(--color-signal)]" />
          offline harness
        </span>
      </header>
      <div className="min-h-0 flex-1 overflow-auto px-4 py-4" role="log" aria-live="polite">
        {poc.length === 0 && verification.length === 0 ? (
          <p className="text-sm text-ash">Run the exploit to capture evidence. Every query and every prompt sent to the model is recorded here.</p>
        ) : (
          <>
            <Section title="Exploit run" lines={poc} />
            <Section title="Verification" lines={verification} />
          </>
        )}
      </div>
    </div>
  )
}

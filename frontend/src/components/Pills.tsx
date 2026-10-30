import { severityColor, severityLabel } from '@/lib/format'
import type { CaseResult, Verdict } from '@/lib/pipeline'
import type { Severity } from '@/lib/types'
import { cn } from '@/lib/utils'

export type Tone = 'neutral' | 'amber' | 'signal' | 'hot' | 'fail' | 'muted'

const toneClass: Record<Tone, string> = {
  neutral: 'border-ash/40 text-bone/90',
  muted: 'border-ash/25 text-ash',
  amber: 'border-amber/60 bg-amber/10 text-amber',
  signal: 'border-signal/70 bg-signal/15 text-ember',
  hot: 'border-phosphor/70 bg-phosphor/10 text-phosphor shadow-[0_0_10px_rgb(255_228_225/0.25)]',
  fail: 'border-ember bg-ember/15 text-ember',
}

export function Pill({ tone, children, pulse, className }: { tone: Tone; children: React.ReactNode; pulse?: boolean; className?: string }) {
  return (
    <span className={cn('inline-flex h-6 items-center gap-1.5 border px-2 text-xs font-medium whitespace-nowrap', toneClass[tone], className)}>
      <span aria-hidden className={cn('size-1.5 rounded-full bg-current', pulse && 'pulse-amber')} />
      {children}
    </span>
  )
}

export const verdictTone: Record<Verdict, Tone> = {
  Verified: 'hot',
  Failed: 'fail',
  Patched: 'signal',
  Exploitable: 'amber',
  Blocked: 'neutral',
  Open: 'neutral',
  'Report only': 'muted',
}

export function VerdictPill({ verdict }: { verdict: Verdict }) {
  return <Pill tone={verdictTone[verdict]} pulse={verdict === 'Exploitable'}>{verdict}</Pill>
}

export const caseTone: Record<CaseResult, Tone> = {
  Passed: 'hot',
  Failed: 'fail',
  'Exploit reproduced': 'amber',
  'Not run': 'muted',
}

export function SeverityTag({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2 text-sm font-semibold', className)} style={{ color: severityColor[severity] }}>
      <span aria-hidden className="inline-block h-3 w-1" style={{ background: severityColor[severity] }} />
      {severityLabel[severity]}
    </span>
  )
}

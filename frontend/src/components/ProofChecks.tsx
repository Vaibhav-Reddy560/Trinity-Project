import { Check as CheckIcon, Minus, X } from 'lucide-react'
import type { Check } from '@/lib/types'
import { cn } from '@/lib/utils'

/** The proof checks a fix went through, in the order they run. */
export function ProofChecks({ checks, compact }: { checks: Check[]; compact?: boolean }) {
  return (
    <ul className="divide-y divide-border/60 border border-border">
      {checks.map((c) => {
        const Icon = c.passed === null ? Minus : c.passed ? CheckIcon : X
        return (
          <li key={c.id} className={cn('grid grid-cols-[1.25rem_1fr] gap-3 px-4', compact ? 'py-2' : 'py-3')}>
            <Icon aria-hidden className={cn('mt-0.5 size-4', c.passed === null ? 'text-ash' : c.passed ? 'text-phosphor' : 'text-ember')} />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-bone">
                {c.label}
                <span className="sr-only">: {c.passed === null ? 'not applicable' : c.passed ? 'passed' : 'failed'}</span>
              </p>
              {!compact && <p className="mt-0.5 text-sm leading-relaxed text-ash">{c.detail}</p>}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

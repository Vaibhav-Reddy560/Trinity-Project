import { CircleAlert, CircleCheck, Loader } from 'lucide-react'
import type { Notice } from '@/hooks/useVulns'
import { cn } from '@/lib/utils'

const icon = { info: Loader, success: CircleCheck, error: CircleAlert }
const tone = {
  info: 'border-signal/50 text-bone',
  success: 'border-phosphor/60 text-phosphor',
  error: 'border-ember text-ember',
}

export function Toasts({ notices }: { notices: Notice[] }) {
  return (
    <div className="no-print pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2" role="status" aria-live="polite">
      {notices.map((n) => {
        const Icon = icon[n.tone]
        return (
          <div key={n.key} className={cn('flex items-start gap-3 border bg-panel/95 px-4 py-3 text-sm shadow-[0_10px_30px_rgb(0_0_0/0.6)] backdrop-blur', tone[n.tone])}>
            <Icon className={cn('mt-0.5 size-4 shrink-0', n.tone === 'info' && 'spin-scan')} aria-hidden />
            <span>{n.text}</span>
          </div>
        )
      })}
    </div>
  )
}

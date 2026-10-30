import { href } from '@/lib/router'
import { cn } from '@/lib/utils'

// The ONLY file where the Vintage Glitch font may be used (PROJECT_CONTEXT.md §9).

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 40" className={cn('shrink-0 drop-shadow-[0_0_8px_rgb(225_6_0/0.7)]', className)} aria-hidden>
      <circle cx="20" cy="20" r="18" fill="none" stroke="var(--color-signal)" strokeWidth="2" strokeDasharray="88 6 14 6" />
      <circle cx="20" cy="20" r="12" fill="none" stroke="var(--color-blood-600)" strokeWidth="1" />
      <circle cx="20" cy="20" r="7" fill="none" stroke="var(--color-signal)" strokeWidth="3" />
      <circle cx="20" cy="20" r="1.6" fill="var(--color-phosphor)" />
      <path d="M20 0v6M20 34v6M0 20h6M34 20h6" stroke="var(--color-signal)" strokeWidth="1.5" />
    </svg>
  )
}

export function Wordmark({ className, intro }: { className?: string; intro?: boolean }) {
  return (
    <span data-text="PATCHPROOF" className={cn('glitch font-logo leading-none tracking-wide text-ember text-glow', intro && 'glitch-intro', className)}>
      PATCHPROOF
    </span>
  )
}

export function Logo({ className }: { className?: string }) {
  return (
    <a href={href.overview} className={cn('group inline-flex items-center gap-3 outline-offset-4', className)} aria-label="PatchProof overview">
      <LogoMark className="size-11" />
      <Wordmark className="text-[2.6rem]" />
    </a>
  )
}

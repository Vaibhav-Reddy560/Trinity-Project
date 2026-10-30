import { cn } from '@/lib/utils'

// The ONLY place the Vintage Glitch font may be used (PROJECT_CONTEXT.md §9).
export function Logo({ className }: { className?: string }) {
  return (
    <a href="/" className={cn('group inline-flex items-center gap-3 outline-offset-4', className)} aria-label="PatchProof home">
      <svg viewBox="0 0 40 40" className="size-10 shrink-0 drop-shadow-[0_0_8px_rgb(225_6_0/0.7)] md:size-12" aria-hidden>
        <circle cx="20" cy="20" r="18" fill="none" stroke="var(--color-signal)" strokeWidth="2" strokeDasharray="88 6 14 6" />
        <circle cx="20" cy="20" r="12" fill="none" stroke="var(--color-blood-600)" strokeWidth="1" />
        <circle cx="20" cy="20" r="7" fill="none" stroke="var(--color-signal)" strokeWidth="3" />
        <circle cx="20" cy="20" r="1.6" fill="var(--color-phosphor)" />
        <path d="M20 0v6M20 34v6M0 20h6M34 20h6" stroke="var(--color-signal)" strokeWidth="1.5" />
      </svg>
      <span
        data-text="PATCHPROOF"
        className="glitch font-logo text-[2.1rem] leading-none tracking-wide text-ember text-glow md:text-[2.75rem]"
      >
        PATCHPROOF
      </span>
    </a>
  )
}

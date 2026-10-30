const PHRASE = ['Find the flaw', 'Prove the fix']

export function Ticker() {
  const run = Array.from({ length: 6 }, () => PHRASE).flat()
  return (
    <div aria-hidden className="overflow-hidden border-y border-border bg-void/80 py-1.5 opacity-70">
      <div className="ticker-track flex w-max gap-14 whitespace-nowrap">
        {[...run, ...run].map((p, i) => (
          <span key={i} className={i % 2 ? 'font-heading text-xs text-signal/60' : 'font-heading text-xs outline-text'}>
            {p}
          </span>
        ))}
      </div>
    </div>
  )
}

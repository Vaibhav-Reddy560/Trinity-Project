import { cn } from '@/lib/utils'

export type RingTone = 'signal' | 'amber' | 'ember' | 'hot' | 'none'
export interface RingSegment {
  label: string
  fill: number
  tone: RingTone
  pulse?: boolean
  dim?: boolean
}

const C = 180
const R = 128
const GAP = 7

const stroke: Record<RingTone, string> = {
  signal: 'var(--color-signal)',
  amber: 'var(--color-amber)',
  ember: 'var(--color-ember)',
  hot: 'var(--color-phosphor)',
  none: 'transparent',
}

function polar(r: number, deg: number) {
  const a = ((deg - 90) * Math.PI) / 180
  return { x: C + r * Math.cos(a), y: C + r * Math.sin(a) }
}

function arc(r: number, start: number, end: number) {
  const a = polar(r, start)
  const b = polar(r, end)
  return `M ${a.x} ${a.y} A ${r} ${r} 0 ${end - start > 180 ? 1 : 0} 1 ${b.x} ${b.y}`
}

const RIM = 'find the flaw  /  prove the fix  /  vuln-bank 4bb7cd5  /  synthetic data only  /  '

// The signature element: four pipeline stages as arcs around a disc, verdict in the centre.
export function PipelineRing({ segments, title, subline, titleClass, busy, hot, className, label, hideCenter }: {
  segments: RingSegment[]
  title: string
  subline: string
  titleClass?: string
  busy?: boolean
  hot?: boolean
  className?: string
  label: string
  hideCenter?: boolean
}) {
  return (
    <figure className={cn('relative mx-auto w-full max-w-[21rem]', className)} aria-label={label}>
      <svg viewBox="0 0 360 360" className={cn('w-full', hot && 'drop-shadow-[0_0_26px_rgb(225_6_0/0.5)]')} aria-hidden>
        <defs>
          <radialGradient id="ring-face" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#1f0202" />
            <stop offset="70%" stopColor="#0b0303" />
            <stop offset="100%" stopColor="#050505" />
          </radialGradient>
          <path id="ring-rim" d={`M ${C} ${C} m -152 0 a 152 152 0 1 1 304 0 a 152 152 0 1 1 -304 0`} />
          <linearGradient id="ring-sweep" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--color-signal)" stopOpacity="0" />
            <stop offset="100%" stopColor="var(--color-ember)" stopOpacity="0.32" />
          </linearGradient>
        </defs>

        <circle cx={C} cy={C} r="172" fill="url(#ring-face)" stroke="var(--color-blood-800)" />
        {Array.from({ length: 120 }, (_, i) => {
          const major = i % 10 === 0
          const a = polar(172, i * 3)
          const b = polar(major ? 161 : 166, i * 3)
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={major ? 'var(--color-signal)' : 'var(--color-blood-600)'} strokeWidth={major ? 1.5 : 0.75} />
        })}
        <g className="spin-slow">
          <text fill="var(--color-ash)" fontSize="8.5" letterSpacing="2.2" style={{ fontFamily: 'var(--font-body)' }}>
            <textPath href="#ring-rim">{RIM.repeat(2)}</textPath>
          </text>
        </g>
        {[142, 104, 96, 88].map((r) => (
          <circle key={r} cx={C} cy={C} r={r} fill="none" stroke="rgb(225 6 0 / 0.08)" />
        ))}

        {segments.map((s, i) => {
          const start = i * 90 + GAP / 2
          const end = (i + 1) * 90 - GAP / 2
          const fillEnd = start + (end - start) * Math.min(1, Math.max(0, s.fill))
          const mid = polar(R - 27, i * 90 + 45)
          return (
            <g key={s.label}>
              <path d={arc(R, start, end)} fill="none" stroke="var(--color-blood-950)" strokeWidth="14" />
              <path d={arc(R, start, end)} fill="none" stroke="var(--color-blood-800)" strokeWidth="14" strokeOpacity="0.6" />
              {s.fill > 0 && (
                <g className={cn(s.pulse && 'pulse-amber')}>
                  {/* Keyed on fill/tone so the arc re-draws itself whenever the stage advances. */}
                  <path key={`${s.fill}-${s.tone}`} d={arc(R, start, fillEnd)} pathLength={1} fill="none" stroke={stroke[s.tone]} strokeWidth="12"
                    className="arc-draw"
                    style={{
                      animationDelay: `${i * 120}ms`,
                      ...(s.tone === 'signal' || s.tone === 'hot' ? { filter: 'drop-shadow(0 0 5px rgb(225 6 0 / 0.8))' } : {}),
                    }} />
                </g>
              )}
              <text x={mid.x} y={mid.y} textAnchor="middle" dominantBaseline="middle" fontSize="12" fontWeight="600"
                fill={s.dim ? 'var(--color-ash)' : 'var(--color-bone)'} opacity={s.dim ? 0.6 : 1} style={{ fontFamily: 'var(--font-body)' }}>
                {s.label}
              </text>
            </g>
          )
        })}

        {busy && (
          <g className="spin-scan">
            {/* Radar sweep: a fading wedge trailing a bright leading edge at 12 o'clock. */}
            <path d={`M ${C} ${C} L ${polar(R + 16, -55).x} ${polar(R + 16, -55).y} A ${R + 16} ${R + 16} 0 0 1 ${C} ${C - R - 16} Z`} fill="url(#ring-sweep)" />
            <line x1={C} y1={C - 20} x2={C} y2={C - R - 16} stroke="var(--color-ember)" strokeWidth="1.5" strokeLinecap="round" opacity="0.9" />
          </g>
        )}
        <circle cx={C} cy={C} r="9" fill="var(--color-void)" stroke="var(--color-signal)" strokeWidth="2" />
      </svg>

      <figcaption className={cn('pointer-events-none absolute inset-0 text-center transition-opacity duration-200', hideCenter && 'opacity-0')}>
        <span className={cn(
          'absolute top-[41%] left-1/2 -translate-x-1/2 -translate-y-1/2 font-heading leading-none tracking-[0.04em] whitespace-nowrap uppercase',
          title.length > 9 ? 'text-[0.95rem]' : title.length > 6 ? 'text-[1.1rem]' : 'text-[1.3rem]',
          titleClass,
        )}>
          {title}
        </span>
        <span className="absolute top-[56%] left-1/2 w-[9.5rem] -translate-x-1/2 text-xs leading-snug text-ash">{subline}</span>
      </figcaption>
    </figure>
  )
}

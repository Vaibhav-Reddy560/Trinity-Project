import { stagesFor, verdictFor, type StageState } from '@/lib/pipeline'
import type { Vuln } from '@/lib/types'
import { cn } from '@/lib/utils'

const C = 180
const STAGE_R = 128
const GAP_DEG = 7

const stageStroke: Record<StageState, string> = {
  done: 'var(--color-signal)',
  alert: 'var(--color-amber)',
  fail: 'var(--color-ember)',
  pending: 'var(--color-blood-950)',
  skipped: 'transparent',
}

function arc(r: number, startDeg: number, endDeg: number) {
  const p = (deg: number) => {
    const a = ((deg - 90) * Math.PI) / 180
    return `${C + r * Math.cos(a)} ${C + r * Math.sin(a)}`
  }
  return `M ${p(startDeg)} A ${r} ${r} 0 ${endDeg - startDeg > 180 ? 1 : 0} 1 ${p(endDeg)}`
}

function polar(r: number, deg: number) {
  const a = ((deg - 90) * Math.PI) / 180
  return { x: C + r * Math.cos(a), y: C + r * Math.sin(a) }
}

const verdictTone = {
  Verified: 'text-phosphor text-glow-hot',
  Failed: 'text-ember text-glow',
  Patched: 'text-signal text-glow',
  Exploitable: 'text-amber pulse-amber',
  Blocked: 'text-bone',
  Open: 'text-ash',
} as const

const RIM_TEXT = 'find the flaw  /  prove the fix  /  vuln-bank 4bb7cd5  /  synthetic data only  /  '

export function EvidenceDisc({ vuln, busy }: { vuln: Vuln; busy: boolean }) {
  const stages = stagesFor(vuln)
  const verdict = verdictFor(vuln)
  const hot = verdict === 'Verified'
  const subline =
    verdict === 'Verified'
      ? 'Exploit blocked, behaviour intact'
      : verdict === 'Exploitable'
        ? 'Exploit reproduced'
        : verdict === 'Patched'
          ? 'Fix applied, not yet verified'
          : verdict === 'Failed'
            ? 'Verification failed'
            : vuln.patchable
              ? 'Exploit not run yet'
              : 'Reported for review'

  return (
    <figure className="relative mx-auto w-full max-w-[22rem]" aria-label={`Pipeline status: ${verdict}. ${subline}.`}>
      <svg viewBox="0 0 360 360" className={cn('w-full', hot && 'drop-shadow-[0_0_28px_rgb(225_6_0/0.55)]')} role="img" aria-hidden>
        <defs>
          <radialGradient id="disc-face" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#1f0202" />
            <stop offset="70%" stopColor="#0b0303" />
            <stop offset="100%" stopColor="#050505" />
          </radialGradient>
          <path id="rim-path" d={`M ${C} ${C} m -152 0 a 152 152 0 1 1 304 0 a 152 152 0 1 1 -304 0`} />
        </defs>

        <circle cx={C} cy={C} r="172" fill="url(#disc-face)" stroke="var(--color-blood-800)" />

        {Array.from({ length: 120 }, (_, i) => {
          const major = i % 10 === 0
          const a = polar(172, i * 3)
          const b = polar(major ? 160 : 166, i * 3)
          return (
            <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={major ? 'var(--color-signal)' : 'var(--color-blood-600)'} strokeWidth={major ? 1.5 : 0.75} />
          )
        })}

        <g className="spin-slow">
          <text fill="var(--color-ash)" fontSize="8.5" letterSpacing="2.2" style={{ fontFamily: 'var(--font-body)' }}>
            <textPath href="#rim-path">{RIM_TEXT.repeat(2)}</textPath>
          </text>
        </g>

        {[142, 104, 96, 88, 80].map((r) => (
          <circle key={r} cx={C} cy={C} r={r} fill="none" stroke="rgb(225 6 0 / 0.09)" />
        ))}

        {stages.map((s, i) => {
          const start = i * 90 + GAP_DEG / 2
          const end = (i + 1) * 90 - GAP_DEG / 2
          const mid = polar(STAGE_R - 26, i * 90 + 45)
          return (
            <g key={s.key}>
              <path d={arc(STAGE_R, start, end)} fill="none" stroke="var(--color-blood-800)" strokeWidth="16" />
              <path d={arc(STAGE_R, start, end)} fill="none" stroke={stageStroke[s.state]} strokeWidth="12"
                className={cn(s.state === 'alert' && 'pulse-amber')}
                style={s.state === 'done' ? { filter: 'drop-shadow(0 0 5px rgb(225 6 0 / 0.8))' } : undefined} />
              <text x={mid.x} y={mid.y} textAnchor="middle" dominantBaseline="middle" fontSize="11" fontWeight="600"
                fill={s.state === 'pending' || s.state === 'skipped' ? 'var(--color-ash)' : 'var(--color-bone)'}
                style={{ fontFamily: 'var(--font-body)' }}>
                {s.label}
              </text>
            </g>
          )
        })}

        {busy && (
          <g className="spin-scan">
            <path d={arc(STAGE_R + 14, 0, 38)} fill="none" stroke="var(--color-ember)" strokeWidth="2" strokeLinecap="round" />
          </g>
        )}

        <circle cx={C} cy={C} r="9" fill="var(--color-void)" stroke="var(--color-signal)" strokeWidth="2" />
      </svg>

      <figcaption className="pointer-events-none absolute inset-0 text-center">
        <span className={cn('absolute top-[41.5%] left-1/2 -translate-x-1/2 -translate-y-1/2 font-heading text-[1.3rem] leading-none whitespace-nowrap', verdictTone[verdict])}>
          {verdict}
        </span>
        <span className="absolute top-[56%] left-1/2 w-[9rem] -translate-x-1/2 text-[0.6875rem] leading-snug text-ash">
          {subline}
        </span>
      </figcaption>
    </figure>
  )
}

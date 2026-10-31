import { useEffect, useMemo, useState, type CSSProperties } from 'react'
import { targetLabel } from '@/lib/scope'
import { useActiveTarget } from '@/lib/targetContext'
import { cn } from '@/lib/utils'
import { Lockup } from './Logo'

const C = 150
const layer = (i: number) => ({ '--i': i }) as CSSProperties

// Scanner rings, inspired by a Uiverse loader and rebuilt for PatchProof. Each layer is a
// separate SVG so the boot sequence can split them into an exploded 3D stack and back.
function ScannerRings() {
  return (
    <div className="boot-stack" aria-hidden>
      <svg viewBox="0 0 300 300" className="boot-layer" style={layer(0)}>
        <circle cx={C} cy={C} r="146" fill="none" stroke="var(--color-blood-600)" strokeWidth="6" pathLength={360} strokeDasharray="1 9" />
        <circle cx={C} cy={C} r="138" fill="none" stroke="var(--color-signal)" strokeWidth="1.5" />
      </svg>
      <svg viewBox="0 0 300 300" className="boot-layer" style={layer(1)}>
        <g className="boot-swing">
          <circle cx={C} cy={C} r="122" fill="none" stroke="var(--color-bone)" strokeWidth="7" pathLength={100} strokeDasharray="16 4 7 4 24 6 10 5 14 10" />
        </g>
      </svg>
      <svg viewBox="0 0 300 300" className="boot-layer" style={layer(2)}>
        <g className="boot-spin">
          <circle cx={C} cy={C} r="103" fill="none" stroke="var(--color-amber)" strokeWidth="2.5" pathLength={100} strokeDasharray="62 38" strokeLinecap="round" />
        </g>
      </svg>
      <svg viewBox="0 0 300 300" className="boot-layer" style={layer(3)}>
        <g className="boot-swing-fast">
          <circle cx={C} cy={C} r="82" fill="none" stroke="var(--color-signal)" strokeWidth="5" pathLength={100} strokeDasharray="22 28" />
        </g>
      </svg>
      <svg viewBox="0 0 300 300" className="boot-layer" style={layer(4)}>
        <g className="boot-spin-rev">
          <circle cx={C} cy={C} r="62" fill="none" stroke="var(--color-bone)" strokeWidth="1.2" pathLength={100} strokeDasharray="30 20" opacity="0.75" />
          <circle cx={C} cy={C} r="55" fill="none" stroke="var(--color-bone)" strokeWidth="1" pathLength={100} strokeDasharray="18 32" opacity="0.5" />
        </g>
      </svg>
      <svg viewBox="0 0 300 300" className="boot-layer" style={layer(5)}>
        <circle cx={C} cy={C} r="36" fill="none" stroke="var(--color-signal)" strokeWidth="2.5" />
        <g className="boot-whirl">
          <circle cx={C} cy={C} r="25" fill="none" stroke="var(--color-ember)" strokeWidth="3" pathLength={100} strokeDasharray="65 35" strokeLinecap="round" />
        </g>
        <path d={`M${C} ${C - 48}v14M${C} ${C + 34}v14M${C - 48} ${C}h14M${C + 34} ${C}h14`} stroke="var(--color-signal)" strokeWidth="2" />
        <circle cx={C} cy={C} r="5" fill="var(--color-phosphor)" />
      </svg>
    </div>
  )
}

const LINE_GAP_MS = 260

export function BootScreen({ ready, onDone }: { ready: boolean; onDone: () => void }) {
  const target = useActiveTarget()
  const reduced = useMemo(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches, [])
  const minMs = reduced ? 500 : 2100
  const [minElapsed, setMinElapsed] = useState(false)
  const [fontsReady, setFontsReady] = useState(false)
  const [showMark, setShowMark] = useState(reduced)
  const [exiting, setExiting] = useState(false)

  useEffect(() => {
    const timers = [
      window.setTimeout(() => setMinElapsed(true), minMs),
      window.setTimeout(() => setShowMark(true), 1050),
    ]
    void document.fonts.ready.then(() => setFontsReady(true))
    const skip = () => setExiting(true)
    window.addEventListener('keydown', skip)
    document.documentElement.style.overflow = 'hidden'
    return () => {
      timers.forEach(clearTimeout)
      window.removeEventListener('keydown', skip)
      document.documentElement.style.overflow = ''
    }
  }, [minMs])

  const done = ready && fontsReady && minElapsed
  useEffect(() => {
    if (done) setExiting(true)
  }, [done])
  useEffect(() => {
    if (!exiting) return
    const t = window.setTimeout(onDone, reduced ? 220 : 620)
    return () => clearTimeout(t)
  }, [exiting, onDone, reduced])

  const lines = [
    'Initialising PatchProof console',
    'Loading detection rules: AI and generic packs',
    target.provable
      ? `Mounting offline exploit harness (${target.cases?.length ?? 0} cases)`
      : 'Project mode: code is read, never run; fixes go to a copy',
    `Target ${targetLabel(target)}`,
  ]

  return (
    <div className={cn('boot', exiting && 'boot-exit')} onClick={() => setExiting(true)} role="status" aria-live="polite" aria-label="Loading PatchProof">
      {/* One vertical rhythm, scaled to the viewport height so it fills large screens
          and still fits short ones. The logo is sized to match the tagline's width. */}
      <div className="relative z-10 flex w-full max-w-xl flex-col items-center">
        <ScannerRings />

        {/* Reserves the logo's height so nothing jumps when it glitches in. */}
        <div className="mt-[clamp(1.5rem,4.5vh,3rem)] flex h-[clamp(3rem,min(10vh,19vw),6rem)] items-center justify-center">
          {showMark && (
            <Lockup intro className="gap-[clamp(0.6rem,1.4vh,1rem)]"
              markClass="h-[clamp(2.35rem,min(7.8vh,14.8vw),4.7rem)]" textClass="text-[clamp(3rem,min(10vh,19vw),6rem)]" />
          )}
        </div>
        <p className="boot-rise mt-[clamp(0.6rem,1.6vh,1rem)] font-heading text-[clamp(0.66rem,1.25vh,0.82rem)] tracking-[0.18em] text-bone/85 uppercase"
          style={{ animationDelay: '1.2s' }}>
          Find the flaw. Prove the fix.
        </p>

        <div className="mt-[clamp(1.5rem,4vh,2.5rem)] w-full max-w-[24rem]">
          <ol className="space-y-2 text-sm text-ash">
            {lines.map((l, i) => (
              <li key={l} className="line-in flex gap-2.5" style={{ animationDelay: `${250 + i * LINE_GAP_MS}ms` }}>
                <span aria-hidden className="text-signal">&gt;</span>
                {l}
              </li>
            ))}
            <li className={cn('flex gap-2.5 text-phosphor', done ? 'line-in' : 'invisible')}>
              <span aria-hidden className="text-signal">&gt;</span>
              Ready
              <span aria-hidden className="type-cursor" />
            </li>
          </ol>
          <div className="boot-bar mt-5 w-full"><span /></div>
        </div>
      </div>

      <p className="absolute bottom-[clamp(1rem,3vh,2rem)] left-1/2 z-10 -translate-x-1/2 text-xs text-ash/60">Press any key to skip</p>
    </div>
  )
}

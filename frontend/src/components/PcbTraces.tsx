// Faint circuit-board traces behind the console (decorative).
const traces = [
  'M0 520 H120 L160 480 H300 L340 440 V300',
  'M0 560 H180 L220 600 H420',
  'M60 640 V560 L100 520',
  'M0 420 H70 L110 380 V220 L150 180 H260',
  'M240 640 V600 L280 560 H520 L560 520',
  'M380 640 V620 L420 580 H600',
]
const pads: [number, number][] = [
  [340, 300], [420, 600], [100, 520], [260, 180], [560, 520], [600, 580], [300, 480], [110, 380],
]

export function PcbTraces() {
  return (
    <svg
      aria-hidden
      viewBox="0 0 640 640"
      className="pointer-events-none fixed right-0 bottom-0 -z-10 h-[60vh] w-auto -scale-x-100 opacity-40"
      preserveAspectRatio="xMinYMax meet"
    >
      <g fill="none" stroke="var(--color-blood-800)" strokeWidth="2">
        {traces.map((d) => <path key={d} d={d} />)}
      </g>
      {pads.map(([x, y]) => (
        <circle key={`${x}-${y}`} cx={x} cy={y} r="5" fill="var(--color-void)" stroke="var(--color-blood-600)" strokeWidth="2" />
      ))}
    </svg>
  )
}

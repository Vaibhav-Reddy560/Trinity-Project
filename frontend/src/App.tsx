import { useState } from 'react'
import { FindingDetail, type StepAction } from '@/components/FindingDetail'
import { Logo } from '@/components/Logo'
import { PcbTraces } from '@/components/PcbTraces'
import { Ticker } from '@/components/Ticker'
import { VulnList } from '@/components/VulnList'
import { Button } from '@/components/ui/button'
import { useVulns, type ApiState } from '@/hooks/useVulns'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

const apiBadge: Record<ApiState, { label: string; dot: string }> = {
  mock: { label: 'Mock data', dot: 'bg-amber shadow-[0_0_8px_var(--color-amber)]' },
  online: { label: 'API online', dot: 'bg-signal shadow-[0_0_8px_var(--color-signal)]' },
  offline: { label: 'API offline', dot: 'bg-ash' },
}

export default function App() {
  const { vulns, apiState, busy, error, run } = useVulns()
  const [picked, setPicked] = useState<string | null>(null)
  const selected = vulns.find((v) => v.id === picked) ?? vulns[0] ?? null

  const act = (a: StepAction) => {
    if (!selected) return
    const id = selected.id
    void run(() => (a === 'poc' ? api.poc(id) : a === 'patch' ? api.patch(id) : api.verify(id)))
  }

  return (
    <div className="crt halftone relative isolate flex min-h-dvh flex-col">
      <PcbTraces />

      <header className="flex flex-wrap items-center gap-x-8 gap-y-4 px-4 pt-5 pb-4 md:px-8">
        <Logo />
        <dl className="flex flex-wrap gap-x-6 gap-y-1 text-xs">
          <div>
            <dt className="text-ash">Target</dt>
            <dd className="text-bone">vuln-bank at 4bb7cd5</dd>
          </div>
          <div>
            <dt className="text-ash">Module</dt>
            <dd className="text-bone">AI customer support</dd>
          </div>
        </dl>
        <div className="ml-auto flex items-center gap-4">
          <span className="flex items-center gap-2 text-xs text-ash" role="status">
            <span aria-hidden className={cn('size-2 rounded-full', apiBadge[apiState].dot)} />
            {apiBadge[apiState].label}
          </span>
          <Button variant="ghost" size="sm" disabled={busy} onClick={() => void run(api.reset)}>
            Reset
          </Button>
          <Button size="sm" disabled={busy} onClick={() => void run(api.runAll)} className="shadow-[var(--glow-signal)]">
            Run all
          </Button>
        </div>
      </header>

      <Ticker />

      <main className="grid flex-1 grid-cols-[minmax(0,1fr)] gap-4 px-4 py-5 md:px-8 lg:grid-cols-[20rem_minmax(0,1fr)]">
        <aside className="panel self-start p-4" aria-labelledby="findings-heading">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 id="findings-heading" className="text-base text-bone">Findings</h2>
            <span className="text-xs text-ash tabular-nums">{vulns.length}</span>
          </div>
          <VulnList vulns={vulns} selectedId={selected?.id ?? null} onSelect={setPicked} />
        </aside>

        {selected ? (
          <FindingDetail vuln={selected} busy={busy} error={error} onAction={act} />
        ) : (
          <section className="panel grid place-items-center p-10 text-center">
            <div>
              <h1 className="text-xl text-bone">Nothing scanned yet</h1>
              <p className="mt-3 text-ash">Scan the target to find weaknesses in the AI customer support module.</p>
              <Button className="mt-6" onClick={() => void run(api.scan)}>Scan target</Button>
            </div>
          </section>
        )}
      </main>
    </div>
  )
}

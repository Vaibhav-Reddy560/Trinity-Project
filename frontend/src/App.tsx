import { Loader, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { BootScreen } from '@/components/BootScreen'
import { CommandPalette } from '@/components/CommandPalette'
import { GlobalActions } from '@/components/GlobalActions'
import { PcbTraces } from '@/components/PcbTraces'
import { Sidebar } from '@/components/Sidebar'
import { Toasts } from '@/components/Toasts'
import { Button } from '@/components/ui/button'
import { useVulns } from '@/hooks/useVulns'
import { activityOf } from '@/lib/activity'
import { AIContext } from '@/lib/aiContext'
import { typeName } from '@/lib/format'
import { href, useRoute, type Route } from '@/lib/router'
import { targetLabel } from '@/lib/scope'
import { TargetContext } from '@/lib/targetContext'
import type { Action, TargetSelection } from '@/lib/types'
import { ActivityPage } from '@/pages/ActivityPage'
import { FindingPage } from '@/pages/FindingPage'
import { FindingsPage } from '@/pages/FindingsPage'
import { OverviewPage } from '@/pages/OverviewPage'
import { ReportPage } from '@/pages/ReportPage'
import { ScopePage } from '@/pages/ScopePage'

const RUNNING: Record<Action, string> = {
  scan: 'Scanning target',
  poc: 'Running exploit',
  patch: 'Applying patch',
  verify: 'Verifying fix',
  'run-all': 'Running full pipeline',
  reset: 'Resetting workspace',
  select: 'Loading target and scanning',
  review: 'AI is reviewing a finding',
  'review-all': 'AI is reviewing every finding',
  'deep-scan': 'AI is reading the code for logic flaws',
  'fix-all': 'Fixing and proving every open finding',
}

const TITLES: Record<Route['name'], string> = {
  overview: 'Overview',
  findings: 'Findings',
  finding: 'Finding',
  scope: 'Targets',
  activity: 'Activity',
  report: 'Report',
}

export default function App() {
  const route = useRoute()
  const { vulns, loaded, apiState, pending, notices, run, reload, targets, ai } = useVulns()
  const activityCount = useMemo(() => activityOf(vulns).length, [vulns])
  const onRun = (a: Action, id?: string) => void run(a, id)
  const onSelect = (selection: TargetSelection) => void run('select', undefined, selection)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [booting, setBooting] = useState(true)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    const v = route.name === 'finding' ? vulns.find((x) => x.id === route.id) : undefined
    document.title = `${v ? typeName[v.type] : TITLES[route.name]} | PatchProof`
  }, [route, vulns])

  let page: React.ReactNode
  if (!loaded) page = <p className="text-ash">Loading findings…</p>
  else if (route.name === 'findings') page = <FindingsPage vulns={vulns} pending={pending} onRun={onRun} />
  else if (route.name === 'finding') {
    const vuln = vulns.find((v) => v.id === route.id)
    page = vuln ? (
      <FindingPage key={vuln.id} vuln={vuln} vulns={vulns} pending={pending} onAction={onRun} />
    ) : (
      <section className="panel px-6 py-12 text-center">
        <h1 className="text-xl text-bone">Finding not found</h1>
        <p className="mt-3 text-ash">It may have been cleared by a reset or a new scan.</p>
        <a href={href.findings} className="mt-5 inline-block text-ember hover:underline">Back to findings</a>
      </section>
    )
  } else if (route.name === 'scope') page = <ScopePage pending={pending} apiState={apiState} onSelect={onSelect} />
  else if (route.name === 'activity') page = <ActivityPage vulns={vulns} />
  else if (route.name === 'report') page = <ReportPage vulns={vulns} />
  else page = <OverviewPage vulns={vulns} pending={pending} onRun={onRun} />

  return (
    <TargetContext.Provider value={targets}>
    <AIContext.Provider value={ai}>
    {booting && <BootScreen ready={loaded} onDone={() => setBooting(false)} />}
    <div className="crt halftone relative isolate min-h-dvh" inert={booting}>
      <a href="#main" className="sr-only z-[70] bg-signal px-4 py-2 text-white focus:not-sr-only focus:fixed focus:top-2 focus:left-2">
        Skip to content
      </a>
      <PcbTraces />
      <Sidebar route={route} counts={{ findings: vulns.length, activity: activityCount }} apiState={apiState} />

      <div className="lg:pl-64">
        <div className="no-print sticky top-0 z-40 flex flex-wrap items-center justify-end gap-3 sm:justify-between border-b border-border bg-void/85 px-4 py-3 backdrop-blur md:px-8">
          <div className="flex min-w-0 items-center gap-4">
            <button type="button" onClick={() => setPaletteOpen(true)}
              className="flex h-9 items-center gap-2 border border-border bg-void/60 px-3 text-sm text-ash transition-colors hover:border-signal/60 hover:text-bone md:w-72">
              <Search className="size-4" aria-hidden />
              <span className="hidden md:inline">Search or jump to</span>
              <kbd className="ml-auto hidden border border-border px-1.5 text-xs text-ash md:inline">⌘K</kbd>
            </button>
            <p className="hidden items-center gap-2 text-sm text-ash xl:flex" role="status">
              {pending ? (
                <><Loader className="spin-scan size-4 text-signal" aria-hidden /><span className="text-bone">{RUNNING[pending.action]}</span></>
              ) : (
                <>Target <a href={href.scope} className="text-bone hover:text-ember">{targetLabel(targets.active)}</a></>
              )}
            </p>
          </div>
          <GlobalActions pending={pending} onRun={onRun} />
        </div>

        <main id="main" className="mx-auto max-w-[90rem] px-4 py-8 md:px-8">
          {loaded && apiState === 'offline' && (
            <section role="alert" className="mb-6 flex flex-wrap items-center justify-between gap-4 border border-ember bg-ember/10 px-5 py-4">
              <div>
                <p className="font-semibold text-ember">Can't reach the PatchProof API</p>
                <p className="mt-1 text-sm text-bone/85">Start it from the repo root with <kbd className="border border-border px-1.5">make api</kbd>, then retry.</p>
              </div>
              <Button variant="outline" size="lg" onClick={() => void reload()}>Retry</Button>
            </section>
          )}
          {page}
        </main>
      </div>

      <Toasts notices={notices} />
      <CommandPalette open={paletteOpen && !booting} onOpenChange={setPaletteOpen} vulns={vulns} pending={pending} onRun={onRun} />
    </div>
    </AIContext.Provider>
    </TargetContext.Provider>
  )
}

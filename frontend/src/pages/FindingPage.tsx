import { Bug, ChevronLeft, ChevronRight, CircleAlert, FlaskConical, ShieldCheck, Wrench } from 'lucide-react'
import { CodeBlock } from '@/components/CodeBlock'
import { DiffView } from '@/components/DiffView'
import { useEffect, useRef, useState } from 'react'
import { EvidenceLog, Highlight, LINE_STAGGER_MS } from '@/components/EvidenceLog'
import { TYPE_INFO } from '@/lib/knowledge'
import { PageHeader, Panel } from '@/components/Panel'
import { Pill, SeverityTag, VerdictPill, caseTone } from '@/components/Pills'
import { PipelineRing, type RingSegment } from '@/components/PipelineRing'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { Pending } from '@/hooks/useVulns'
import { clock, codeLocation, typeName } from '@/lib/format'
import {
  baselineResult, canPatch, canRunPoc, canVerify, caseResult, diffStats, nextAction, nextActionHint, provenLeaks, stagesFor, verdictFor,
  type Baseline, type Stage, type StepAction,
} from '@/lib/pipeline'
import { href } from '@/lib/router'
import { SECURITY_IDS, casesFor } from '@/lib/scope'
import type { Tone } from '@/components/Pills'

const baselineTone: Record<Baseline, Tone> = {
  'Exploit worked': 'amber',
  'Exploit blocked': 'neutral',
  Works: 'neutral',
  Broken: 'fail',
  'Not run': 'muted',
}
import type { Vuln } from '@/lib/types'
import { cn } from '@/lib/utils'

const verdictTitleClass = {
  Verified: 'text-phosphor text-glow-hot',
  Failed: 'text-ember text-glow',
  Patched: 'text-signal text-glow',
  Exploitable: 'text-amber pulse-amber',
  Blocked: 'text-bone',
  Open: 'text-ash',
  'Report only': 'text-ash',
} as const

const sublineFor = {
  Verified: 'Exploit blocked, behaviour intact',
  Failed: 'The fix did not pass its tests',
  Patched: 'Fix applied, not yet verified',
  Exploitable: 'Exploit reproduced',
  Blocked: 'Exploit did not work',
  Open: 'Exploit not run yet',
  'Report only': 'Reported for review',
} as const

function ringSegments(stages: Stage[]): RingSegment[] {
  return stages.map((s) => ({
    label: s.label,
    fill: s.state === 'pending' || s.state === 'skipped' ? 0 : 1,
    tone: s.state === 'alert' ? 'amber' : s.state === 'fail' ? 'ember' : 'signal',
    pulse: s.state === 'alert',
    dim: s.state === 'pending' || s.state === 'skipped',
  }))
}

function stageDetail(s: Stage, v: Vuln): string {
  const d = diffStats(v.diff)
  switch (s.key) {
    case 'scan':
      return `Found at ${clock(v.created_at)}`
    case 'prove':
      if (!v.patchable) return 'No exploit for this finding type'
      return v.poc_status === 'EXPLOITABLE' ? `Exploit reproduced at ${clock(v.poc_log[0]?.ts ?? v.updated_at)}`
        : v.poc_status === 'BLOCKED' ? 'Exploit blocked' : 'Not run yet'
    case 'patch':
      if (!v.patchable) return 'Report only'
      return v.diff ? `${d.hunks} change${d.hunks === 1 ? '' : 's'}, +${d.added} / −${d.removed} lines` : 'Not patched yet'
    case 'verify':
      if (!v.patchable) return 'Report only'
      return v.status === 'VERIFIED' ? 'Security and regression tests passed' : v.status === 'FAILED' ? 'Tests failed' : 'Not verified yet'
  }
}

const stageDot: Record<Stage['state'], string> = {
  done: 'bg-signal shadow-[0_0_8px_var(--color-signal)]',
  alert: 'bg-amber pulse-amber',
  fail: 'bg-ember',
  pending: 'border border-ash/50',
  skipped: 'border border-ash/25',
}

const stepIcon = { poc: Bug, patch: Wrench, verify: ShieldCheck }
const STEP_TAB: Record<StepAction, string> = { poc: 'evidence', patch: 'patch', verify: 'tests' }
const stepLabel: Record<StepAction, string> = { poc: 'Run exploit', patch: 'Apply patch', verify: 'Verify fix' }
const stepRunning: Record<StepAction, string> = { poc: 'Running exploit', patch: 'Applying patch', verify: 'Verifying fix' }

export function FindingPage({ vuln, vulns, pending, onAction }: {
  vuln: Vuln
  vulns: Vuln[]
  pending: Pending
  onAction: (a: StepAction, id: string) => void
}) {
  const verdict = verdictFor(vuln)
  const stages = stagesFor(vuln)
  const next = nextAction(vuln)
  const cases = casesFor(vuln.type)
  const busyHere = pending !== null && (pending.id === vuln.id || pending.action === 'run-all')
  const idx = vulns.findIndex((v) => v.id === vuln.id)
  const prev = vulns[idx - 1]
  const after = vulns[idx + 1]
  const enabled: Record<StepAction, boolean> = { poc: canRunPoc(vuln), patch: canPatch(vuln), verify: canVerify(vuln) }
  const d = diffStats(vuln.diff)
  const passed = cases.filter((c) => caseResult(c, vuln) === 'Passed').length
  const info = TYPE_INFO[vuln.type]
  const proofs = provenLeaks(vuln, SECURITY_IDS)

  // Each action opens the tab where its result lands, so the evidence types in on screen.
  const [tab, setTab] = useState('summary')
  const act = (a: StepAction) => {
    setTab(STEP_TAB[a])
    onAction(a, vuln.id)
  }

  // Proof box glitches in only when it appears (or changes) while the page is open,
  // and only after the evidence lines above it have finished typing in.
  const proofKey = proofs.join('|')
  const initialProofKey = useRef(proofKey)
  const proofsAreNew = proofKey !== initialProofKey.current
  const [revealedKey, setRevealedKey] = useState(proofKey)
  useEffect(() => {
    if (!proofsAreNew) return
    const t = window.setTimeout(() => setRevealedKey(proofKey), vuln.poc_log.length * LINE_STAGGER_MS + 300)
    return () => window.clearTimeout(t)
  }, [proofKey, proofsAreNew, vuln.poc_log.length])
  const proofsShown = !proofsAreNew || revealedKey === proofKey

  // One stamp when this finding turns Verified while you are watching.
  const prevVerdict = useRef(verdict)
  const [stamped, setStamped] = useState(false)
  useEffect(() => {
    const justVerified = prevVerdict.current !== 'Verified' && verdict === 'Verified'
    prevVerdict.current = verdict
    if (!justVerified) return
    setStamped(true)
    const t = window.setTimeout(() => setStamped(false), 2800)
    return () => window.clearTimeout(t)
  }, [verdict])

  return (
    <>
      <PageHeader
        crumbs={<><a href={href.findings} className="hover:text-bone">Findings</a><span className="mx-2 text-blood-600">/</span><span className="text-bone/80">{typeName[vuln.type]}</span></>}
        title={typeName[vuln.type]}
        description={<p className="text-lg text-bone">{vuln.title}</p>}
        actions={
          <>
            <Button variant="ghost" size="lg" disabled={!prev} onClick={() => prev && (window.location.hash = href.finding(prev.id))}>
              <ChevronLeft /> Previous
            </Button>
            <Button variant="ghost" size="lg" disabled={!after} onClick={() => after && (window.location.hash = href.finding(after.id))}>
              Next <ChevronRight />
            </Button>
          </>
        }
      />

      <dl className="panel mb-5 grid grid-cols-2 gap-x-6 gap-y-4 px-5 py-4 md:grid-cols-[1fr_1fr_minmax(15rem,1.8fr)_1.3fr_1fr]">
        <div><dt className="label">Severity</dt><dd className="mt-1"><SeverityTag severity={vuln.severity} /></dd></div>
        <div><dt className="label">Weakness</dt><dd className="mt-1 text-sm text-bone">{vuln.cwe}</dd></div>
        <div className="col-span-2 md:col-span-1"><dt className="label">Location</dt><dd className="mt-1 text-sm text-bone tabular-nums">{codeLocation(vuln)}</dd></div>
        <div><dt className="label">Fix</dt><dd className="mt-1 text-sm text-bone">{vuln.patchable ? 'Auto-patch available' : 'Report only'}</dd></div>
        <div><dt className="label">Status</dt><dd className="mt-1"><VerdictPill verdict={verdict} /></dd></div>
      </dl>

      {vuln.patchable && (
        <section aria-label="Next step" className="panel mb-5 flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <p className="flex items-center gap-3 text-bone">
            {next ? (
              <><span className="text-xs whitespace-nowrap text-signal">Next step</span>{nextActionHint[next]}</>
            ) : (
              <><ShieldCheck className="size-5 text-phosphor" aria-hidden />Fixed and verified. You can rerun the exploit to confirm it stays blocked.</>
            )}
          </p>
          <div className="flex flex-wrap gap-2">
            {(['poc', 'patch', 'verify'] as const).map((a) => {
              const Icon = stepIcon[a]
              const running = busyHere && pending?.action === a
              return (
                <Button key={a} size="lg" variant={a === next ? 'default' : 'outline'} disabled={pending !== null || !enabled[a]}
                  onClick={() => act(a)}
                  className={cn(a === next && 'shadow-[var(--glow-signal)]', 'disabled:shadow-none')}>
                  <Icon /> {running ? stepRunning[a] : stepLabel[a]}
                </Button>
              )
            })}
          </div>
        </section>
      )}

      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
        <Panel title="Pipeline" className="self-start">
          <div className={cn('relative', stamped && 'ring-jolt')}>
            <PipelineRing
              label={`Pipeline status: ${verdict}`}
              title={verdict}
              subline={sublineFor[verdict]}
              titleClass={verdictTitleClass[verdict]}
              hot={verdict === 'Verified'}
              busy={busyHere}
              segments={ringSegments(stages)}
              hideCenter={stamped}
            />
            {stamped && <span className="stamp" aria-hidden>Verified</span>}
          </div>
          <ol className="mt-6 space-y-4">
            {stages.map((s) => (
              <li key={s.key} className="grid grid-cols-[0.75rem_1fr] gap-3">
                <span aria-hidden className={cn('mt-1.5 size-2.5 rounded-full', stageDot[s.state])} />
                <div>
                  <p className={cn('text-sm font-semibold', s.state === 'pending' || s.state === 'skipped' ? 'text-ash' : 'text-bone')}>{s.label}</p>
                  <p className="text-xs text-ash">{stageDetail(s, vuln)}</p>
                </div>
              </li>
            ))}
          </ol>
        </Panel>

        <Tabs value={tab} onValueChange={setTab} className="panel min-w-0 gap-0">
          <TabsList variant="line" className="h-auto w-full justify-start gap-0 overflow-x-auto border-b border-border px-3">
            {[
              { v: 'summary', label: 'Summary' },
              { v: 'evidence', label: 'Exploit evidence', count: vuln.poc_log.length || undefined },
              { v: 'patch', label: 'Patch', count: vuln.diff ? `+${d.added} −${d.removed}` : undefined },
              { v: 'tests', label: 'Tests', count: vuln.patchable ? `${passed}/${cases.length}` : undefined },
            ].map((t) => (
              <TabsTrigger key={t.v} value={t.v}
                className="h-12 flex-none rounded-none px-4 text-sm text-ash transition-colors duration-100 data-active:bg-blood-950/70! data-active:text-bone after:bg-signal after:shadow-[0_0_8px_var(--color-signal)] group-data-horizontal/tabs:after:bottom-0">
                {t.label}
                {t.count !== undefined && <span className="text-xs text-ash tabular-nums">{t.count}</span>}
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="summary" className="space-y-7 p-5">
            <div>
              <h3 className="mb-2 text-xs text-signal">Why it matters</h3>
              <p className="max-w-[70ch] leading-relaxed text-bone/90">{vuln.severity_rationale}</p>
            </div>

            <dl className="grid gap-px border border-border bg-border sm:grid-cols-2">
              {[
                { k: 'Weakness class', v: `${vuln.cwe}: ${info.cweName}` },
                { k: 'OWASP Top 10 for LLM apps', v: info.owasp },
                { k: 'Who can exploit it', v: info.attacker },
                { k: 'Data at risk', v: info.dataAtRisk },
              ].map((r) => (
                <div key={r.k} className="bg-panel px-4 py-3">
                  <dt className="label">{r.k}</dt>
                  <dd className="mt-1 text-sm text-bone">{r.v}</dd>
                </div>
              ))}
            </dl>

            <div>
              <h3 className="mb-2 text-xs text-signal">Affected code</h3>
              <CodeBlock code={vuln.original_code} startLine={vuln.line_number} label={codeLocation(vuln)} />
            </div>

            {vuln.patch_rationale ? (
              <div>
                <h3 className="mb-2 text-xs text-signal">How the patch fixes it</h3>
                <p className="max-w-[70ch] leading-relaxed text-bone/90">{vuln.patch_rationale}</p>
              </div>
            ) : (
              <div>
                <h3 className="mb-3 text-xs text-signal">{vuln.patchable ? 'How it gets fixed' : 'How to fix it'}</h3>
                <ol className="max-w-[70ch] space-y-2">
                  {info.remediation.map((step, i) => (
                    <li key={step} className="grid grid-cols-[1.75rem_1fr] gap-2 text-bone/90">
                      <span className="flex size-6 items-center justify-center border border-signal/50 text-xs text-signal tabular-nums">{i + 1}</span>
                      <span className="leading-relaxed">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </TabsContent>

          <TabsContent value="evidence" className="space-y-6 p-5">
            {vuln.patchable ? (
              <>
                {proofs.length > 0 && proofsShown && (
                  <div key={proofKey} className={cn('border border-ember/60 bg-ember/8 p-4', proofsAreNew && 'glitch-in-box')}>
                    <h3 className="flex items-center gap-2 text-xs text-ember"><CircleAlert className="size-4" aria-hidden />What the exploit proved</h3>
                    <ul className="mt-3 space-y-1.5">
                      {proofs.map((p) => (
                        <li key={p} className="text-bone"><Highlight text={p} /></li>
                      ))}
                    </ul>
                  </div>
                )}
                <div>
                  <h3 className="mb-3 text-xs text-signal">Exploit log</h3>
                  <EvidenceLog lines={vuln.poc_log} empty="Run the exploit to capture evidence. Every database query and every prompt sent to the model is recorded." />
                </div>
                <div>
                  <h3 className="mb-3 text-xs text-signal">Exploit cases</h3>
                  <ul className="grid gap-3 md:grid-cols-2">
                    {cases.filter((c) => c.kind === 'Security').map((c) => (
                      <li key={c.id} className="border border-border bg-void/70 p-4">
                        <p className="flex items-center gap-2 text-xs text-ash"><Bug className="size-3.5 text-signal" aria-hidden />{c.id} as {c.user}</p>
                        <p className="mt-2 text-bone">“{c.input}”</p>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            ) : (
              <p className="text-ash">This finding is reported for review. The MVP has no exploit case for {typeName[vuln.type].toLowerCase()}.</p>
            )}
          </TabsContent>

          <TabsContent value="patch" className="space-y-5 p-5">
            {vuln.diff ? (
              <>
                {vuln.patch_rationale && <p className="max-w-[70ch] leading-relaxed text-bone/90">{vuln.patch_rationale}</p>}
                <DiffView filePath={vuln.file_path} diff={vuln.diff} vulnId={vuln.id} />
              </>
            ) : (
              <p className="text-ash">
                {vuln.patchable
                  ? 'No patch yet. Prove the weakness with the exploit first, then apply the patch.'
                  : 'Auto-patching is not available for this finding type. Use the summary to fix it by hand.'}
              </p>
            )}
          </TabsContent>

          <TabsContent value="tests" className="space-y-6 p-5">
            {vuln.patchable ? (
              <>
                <p className="max-w-[70ch] text-sm leading-relaxed text-ash">
                  A fix only counts when both kinds of case pass: the original exploit must be blocked, and ordinary requests must still get a normal answer.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[40rem] table-fixed border-collapse text-sm">
                    <colgroup>
                      <col className="w-[9.5rem]" /><col /><col className="w-[9.5rem]" /><col className="w-[13rem]" />
                    </colgroup>
                    <thead>
                      <tr className="border-b border-border text-left text-xs text-ash">
                        <th scope="col" className="py-2 pr-4 font-medium">Case</th>
                        <th scope="col" className="py-2 pr-4 font-medium">Message sent</th>
                        <th scope="col" className="py-2 pr-4 font-medium">Before the patch</th>
                        <th scope="col" className="py-2 font-medium">After the patch</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {cases.map((c) => {
                        const r = caseResult(c, vuln)
                        const before = baselineResult(c, vuln)
                        const after = r === 'Exploit reproduced' ? 'Not run' : r
                        return (
                          <tr key={c.id}>
                            <td className="py-3 pr-4 align-top">
                              <p className="font-semibold text-bone">{c.id}</p>
                              <p className="mt-1 flex items-center gap-1.5 text-xs text-ash">
                                {c.kind === 'Security' ? <ShieldCheck className="size-3.5 text-signal" aria-hidden /> : <FlaskConical className="size-3.5" aria-hidden />}
                                {c.kind === 'Security' ? 'Exploit must be blocked' : 'Normal use must work'}
                              </p>
                            </td>
                            <td className="py-3 pr-4 align-top text-bone/85">“{c.input}” <span className="block text-xs text-ash">as {c.user}</span></td>
                            <td className="py-3 pr-4 align-top"><Pill tone={baselineTone[before]}>{before}</Pill></td>
                            <td className="py-3 align-top">
                              <Pill tone={caseTone[after]}>{after}</Pill>
                              <p className="mt-1.5 pr-2 text-xs leading-relaxed text-ash">{c.expected}</p>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                <div>
                  <h3 className="mb-3 text-xs text-signal">Verification log</h3>
                  <EvidenceLog lines={vuln.verification_log} empty="Not verified yet. Apply the patch, then verify the fix to run these cases." />
                </div>
              </>
            ) : (
              <p className="text-ash">Report-only findings have no automated tests.</p>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </>
  )
}

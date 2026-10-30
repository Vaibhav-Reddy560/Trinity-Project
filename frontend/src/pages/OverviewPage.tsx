import { ArrowRight, Bug, ChevronRight, FileText, Play, ScanSearch } from 'lucide-react'
import { Highlight, headline, levelIcon, levelTone } from '@/components/EvidenceLog'
import { Lockup } from '@/components/Logo'
import { Panel } from '@/components/Panel'
import { SeverityTag, VerdictPill } from '@/components/Pills'
import { PipelineRing } from '@/components/PipelineRing'
import { Button } from '@/components/ui/button'
import type { Pending } from '@/hooks/useVulns'
import { activityOf } from '@/lib/activity'
import { SEVERITIES, ago, severityColor, severityLabel, typeName } from '@/lib/format'
import { nextAction, summarize, verdictFor, type StepAction } from '@/lib/pipeline'
import { href } from '@/lib/router'
import { TARGET } from '@/lib/scope'
import type { Action, Vuln } from '@/lib/types'
import { cn } from '@/lib/utils'
import { EmptyFindings } from './EmptyFindings'

const stepLabel: Record<StepAction, string> = { poc: 'Run exploit', patch: 'Apply patch', verify: 'Verify fix' }

export function OverviewPage({ vulns, pending, onRun }: {
  vulns: Vuln[]
  pending: Pending
  onRun: (a: Action, id?: string) => void
}) {
  const s = summarize(vulns)
  const ratio = (n: number) => (s.patchable ? n / s.patchable : 0)
  const attention = vulns.filter((v) => nextAction(v) !== null || v.status === 'FAILED')
  const recent = activityOf(vulns).slice(0, 6)
  const lastScan = vulns.reduce<string | null>((m, v) => (!m || v.created_at > m ? v.created_at : m), null)

  const allVerified = s.patchable > 0 && s.verified === s.patchable
  const busy = pending !== null

  return (
    <>
      <section className="panel relative mb-6 overflow-hidden" aria-labelledby="hero-title">
        <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_55%_90%_at_0%_40%,rgb(225_6_0/0.2),transparent_70%)]" />
        {/* Rings are centred on the target card (20rem column + 2.5rem padding) and sized so
            their outer edge stops short of the title and copy. Shown only when the card sits
            beside the text (xl); when it stacks underneath there is no free space for them. */}
        <svg aria-hidden viewBox="0 0 400 400"
          className="pointer-events-none absolute top-1/2 right-[calc(12.5rem-13rem)] hidden size-[26rem] -translate-y-1/2 opacity-60 xl:block">
          {[190, 160, 130, 100, 70].map((r, i) => (
            <circle key={r} cx="200" cy="200" r={r} fill="none"
              stroke={i % 2 ? 'var(--color-blood-800)' : 'var(--color-blood-600)'}
              strokeWidth={i === 0 ? 2 : 1}
              strokeDasharray={i === 1 ? '4 6' : i === 3 ? '24 10 4 10' : undefined}
              className={i === 1 ? 'spin-slow' : undefined} />
          ))}
          <path d="M200 0v40M200 360v40M0 200h40M360 200h40" stroke="var(--color-signal)" strokeWidth="2" />
        </svg>

        <div className="relative grid gap-8 px-6 py-8 md:px-10 md:py-10 xl:grid-cols-[minmax(0,1fr)_20rem] xl:items-end">
          <div className="min-w-0">
            <h1 id="hero-title" aria-label="PatchProof" className="tracking-normal normal-case">
              <Lockup intro className="gap-[clamp(0.75rem,1.6vw,1.5rem)]" markClass="h-[clamp(2.9rem,7.8vw,6.6rem)]" textClass="text-[clamp(3.75rem,10vw,8.5rem)]" />
            </h1>
            <p className="mt-5 font-heading text-base tracking-[0.14em] text-bone uppercase md:text-xl">Find the flaw. Prove the fix.</p>
            <p className="mt-4 max-w-[62ch] text-base leading-relaxed text-bone/80">
              PatchProof scans the {TARGET.module} module of {TARGET.name}, proves each weakness with a live exploit, patches the code and verifies that the exploit is blocked while normal use still works.
            </p>
            <div className="mt-7 flex flex-wrap gap-2">
              {vulns.length === 0 ? (
                <Button size="lg" disabled={busy} onClick={() => onRun('scan')} className="shadow-[var(--glow-signal)]"><ScanSearch /> Scan target</Button>
              ) : allVerified ? (
                <Button size="lg" asChild className="shadow-[var(--glow-signal)]"><a href={href.report}><FileText /> View report</a></Button>
              ) : (
                <Button size="lg" disabled={busy} onClick={() => onRun('run-all')} className="shadow-[var(--glow-signal)]"><Play /> Run full pipeline</Button>
              )}
              <Button size="lg" variant="outline" asChild><a href={href.findings}><Bug /> Open findings</a></Button>
            </div>
          </div>

          <div className="relative border border-border bg-void/70 p-5 backdrop-blur">
            <span className="sticker absolute -top-3 right-4">Synthetic data</span>
            <dl className="space-y-3 text-sm">
              <div><dt className="label">Target</dt><dd className="mt-0.5 text-bone">{TARGET.name} at commit {TARGET.commit}</dd></div>
              <div><dt className="label">Module under test</dt><dd className="mt-0.5 text-bone">{TARGET.module}</dd></div>
              <div><dt className="label">Patch target</dt><dd className="mt-0.5 text-bone">ai_agent_deepseek.py</dd></div>
              <div><dt className="label">Exploits run</dt><dd className="mt-0.5 text-bone">Offline, against an isolated copy</dd></div>
            </dl>
            <a href={href.scope} className="mt-4 inline-flex items-center gap-1 text-sm text-ember hover:underline">See full scope <ArrowRight className="size-3.5" /></a>
          </div>
        </div>
      </section>

      {vulns.length === 0 ? (
        <EmptyFindings pending={pending} onScan={() => onRun('scan')} />
      ) : (
        <div className="flex flex-col gap-5">
        <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
          <Panel title="Progress" aside={lastScan && <span className="whitespace-nowrap">Scanned {ago(lastScan)}</span>}>
            <PipelineRing
              label={`${s.verified} of ${s.patchable} patchable findings verified`}
              title={`${s.verified} / ${s.patchable}`}
              subline="patchable findings fixed and verified"
              titleClass={s.verified === s.patchable && s.patchable > 0 ? 'text-phosphor text-glow-hot' : 'text-bone'}
              hot={s.verified === s.patchable && s.patchable > 0}
              busy={pending !== null}
              segments={[
                { label: 'Scan', fill: s.total ? 1 : 0, tone: 'signal' },
                { label: 'Prove', fill: ratio(s.proven), tone: s.exploitable ? 'amber' : 'signal', pulse: s.exploitable > 0 },
                { label: 'Patch', fill: ratio(s.patched), tone: 'signal' },
                { label: 'Verify', fill: ratio(s.verified), tone: 'hot' },
              ]}
            />
          </Panel>

          <div className="flex min-w-0 flex-col gap-5">
            <Panel title="Results" className="flex-1">
              <ol className="grid grid-cols-2 gap-px bg-border md:grid-cols-4">
                {[
                  { n: s.total, label: 'Weaknesses found', note: `${s.reportOnly} reported only` },
                  { n: s.exploitable, label: 'Proven exploitable', note: 'Exploit reproduced, not yet fixed' },
                  { n: s.patched, label: 'Patched', note: `of ${s.patchable} patchable` },
                  { n: s.verified, label: 'Verified fixed', note: 'Exploit blocked, behaviour intact' },
                ].map((m, i) => (
                  <li key={m.label} className="relative bg-panel p-4">
                    <p className="font-heading text-[2.25rem] leading-none text-bone tabular-nums">{m.n}</p>
                    <p className="mt-3 text-sm font-semibold text-bone">{m.label}</p>
                    <p className="mt-1 text-xs text-ash">{m.note}</p>
                    {i < 3 && <ChevronRight aria-hidden className="absolute top-4 right-3 hidden size-4 text-blood-600 md:block" />}
                  </li>
                ))}
              </ol>

              <div className="mt-6">
                <h3 className="mb-3 text-xs text-ash">By severity</h3>
                <ul className="space-y-2.5">
                  {SEVERITIES.map((sev) => {
                    const n = vulns.filter((v) => v.severity === sev).length
                    return (
                      <li key={sev} className="grid grid-cols-[5.5rem_1fr_2rem] items-center gap-3 text-sm">
                        <span style={{ color: severityColor[sev] }} className="font-semibold">{severityLabel[sev]}</span>
                        <span className="h-2 bg-blood-950">
                          <span className="block h-full" style={{ width: `${(n / s.total) * 100}%`, background: severityColor[sev] }} />
                        </span>
                        <span className="text-right text-bone tabular-nums">{n}</span>
                      </li>
                    )
                  })}
                </ul>
              </div>
            </Panel>
          </div>
        </div>

        <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-5 xl:grid-cols-2">
          <Panel title="Needs attention" aside={<span>{attention.length} waiting</span>} bodyClassName="p-0">
            {attention.length === 0 ? (
              <p className="p-5 text-sm text-ash">Nothing is waiting. Every patchable finding is fixed and verified.</p>
            ) : (
              <ul className="divide-y divide-border">
                {attention.map((v) => {
                  const step = nextAction(v)
                  return (
                    <li key={v.id} className="flex flex-wrap items-center gap-x-4 gap-y-3 px-5 py-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-3">
                          <SeverityTag severity={v.severity} />
                          <VerdictPill verdict={verdictFor(v)} />
                        </div>
                        <a href={href.finding(v.id)} className="mt-2 block font-semibold text-bone hover:text-ember">{typeName[v.type]}</a>
                        <p className="text-sm text-ash">{v.title}</p>
                      </div>
                      {step && (
                        <Button size="lg" variant={step === 'poc' ? 'outline' : 'default'} disabled={pending !== null} onClick={() => onRun(step, v.id)}>
                          {stepLabel[step]}
                        </Button>
                      )}
                    </li>
                  )
                })}
              </ul>
            )}
          </Panel>

          <Panel title="Recent activity" aside={<a href={href.activity} className="flex items-center gap-1 hover:text-bone">View all <ArrowRight className="size-3.5" /></a>} bodyClassName="p-0">
            {recent.length === 0 ? (
              <p className="p-5 text-sm text-ash">No exploit or verification runs yet.</p>
            ) : (
              <ul className="divide-y divide-border/60">
                {recent.map((a, i) => {
                  const Icon = levelIcon[a.level]
                  return (
                    <li key={i} className={cn('grid grid-cols-[1.25rem_1fr] gap-3 px-5 py-3 text-sm', levelTone[a.level])}>
                      <Icon className="mt-0.5 size-4" aria-hidden />
                      <div className="min-w-0">
                        <p className="leading-relaxed"><Highlight text={headline(a.msg)} /></p>
                        <p className="mt-1 text-xs text-ash">
                          <a href={href.finding(a.vuln.id)} className="hover:text-bone">{typeName[a.vuln.type]}</a>
                          <span className="mx-2 text-blood-600">/</span>
                          {a.phase}
                          <span className="mx-2 text-blood-600">/</span>
                          {ago(a.ts)}
                        </p>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
          </Panel>
        </div>
        </div>
      )}
    </>
  )
}

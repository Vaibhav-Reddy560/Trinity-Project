import { Download, Printer } from 'lucide-react'
import { Highlight } from '@/components/EvidenceLog'
import { PageHeader, Panel } from '@/components/Panel'
import { TYPE_INFO } from '@/lib/knowledge'
import { Pill, SeverityTag, VerdictPill, caseTone } from '@/components/Pills'
import { ProofChecks } from '@/components/ProofChecks'
import { Button } from '@/components/ui/button'
import { codeLocation, downloadFile, fixSourceLabel, typeName } from '@/lib/format'
import { caseResult, diffStats, provenLeaks, summarize, verdictFor } from '@/lib/pipeline'
import { href } from '@/lib/router'
import { proofCases, securityIds, targetLabel } from '@/lib/scope'
import { useActiveTarget } from '@/lib/targetContext'
import type { Vuln } from '@/lib/types'

export function ReportPage({ vulns }: { vulns: Vuln[] }) {
  const s = summarize(vulns)
  const target = useActiveTarget()
  const security = securityIds(target)
  const generated = new Date().toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
  const fixed = vulns.filter((v) => v.diff)

  const exportJson = () =>
    downloadFile(
      `patchproof-report-${target.name.replace(/[^\w.-]+/g, '-')}.json`,
      JSON.stringify({
        target: { ...target, cases: undefined },
        generated_at: new Date().toISOString(),
        summary: s,
        vulnerabilities: vulns.map(({ base_code: _base, patched_code: _patched, ...v }) => v),
      }, null, 2),
      'application/json',
    )

  return (
    <>
      <PageHeader
        title="Report"
        description={<p>A shareable summary of every finding, the evidence behind it and the result of each fix. Generated {generated}.</p>}
        actions={
          <>
            <Button variant="outline" size="lg" onClick={exportJson} disabled={vulns.length === 0}><Download /> Download JSON</Button>
            <Button size="lg" onClick={() => window.print()} disabled={vulns.length === 0}><Printer /> Print or save as PDF</Button>
          </>
        }
      />

      {vulns.length === 0 ? (
        <p className="panel px-5 py-10 text-center text-ash">Nothing to report yet. Scan the target first.</p>
      ) : (
        <div className="space-y-5">
          <Panel title="Summary">
            <p className="max-w-[75ch] leading-relaxed text-bone/90">
              PatchProof scanned {target.module.toLowerCase()} of {targetLabel(target)} and found{' '}
              <strong className="text-bone">{s.total} weaknesses</strong>.{' '}
              {s.byAI > 0 && <>{s.byAI} of them came from the AI deep scan and quote the exact lines they point at. </>}
              {s.patchable} can be fixed automatically; {s.verified} {s.verified === 1 ? 'is' : 'are'} patched and verified
              {s.aiFixes > 0 && <> ({s.aiFixes} written by AI and checked like the rest)</>}.{' '}
              {target.kind === 'project'
                ? <>The project&apos;s code was never run: every fix was applied to a copy and had to compile, make the rule stop flagging the code, flag nothing new, stay inside the flagged function and keep its signature.</>
                : <>On this practice target, verified means the original exploit is blocked, the whole regression suite still passes, and the static proof checks hold.</>}{' '}
              {s.reportOnly > 0 && <>{s.reportOnly} {s.reportOnly === 1 ? 'is' : 'are'} left to fix by hand, with steps for each.</>}
            </p>
          </Panel>

          <Panel title="All findings" bodyClassName="p-0 overflow-x-auto">
            <table className="w-full min-w-[48rem] border-collapse text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-ash">
                  <th scope="col" className="py-3 pr-4 pl-5 font-medium">Finding</th>
                  <th scope="col" className="py-3 pr-4 font-medium">Severity</th>
                  <th scope="col" className="py-3 pr-4 font-medium">Weakness</th>
                  <th scope="col" className="py-3 pr-4 font-medium">Location</th>
                  <th scope="col" className="py-3 pr-5 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {vulns.map((v) => (
                  <tr key={v.id}>
                    <td className="py-3 pr-4 pl-5">
                      <a href={href.finding(v.id)} className="font-semibold text-bone hover:text-ember">{typeName[v.type]}</a>
                      <p className="text-ash">{v.title}</p>
                    </td>
                    <td className="py-3 pr-4"><SeverityTag severity={v.severity} /></td>
                    <td className="py-3 pr-4 text-bone/85">{v.cwe}</td>
                    <td className="py-3 pr-4 text-bone/85 tabular-nums">{codeLocation(v)}</td>
                    <td className="py-3 pr-5"><VerdictPill verdict={verdictFor(v)} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          {fixed.map((v) => {
            const d = diffStats(v.diff)
            return (
              <Panel key={v.id} title={typeName[v.type]} aside={<VerdictPill verdict={verdictFor(v)} />}>
                <div className="grid gap-6 lg:grid-cols-2">
                  <div className="space-y-4">
                    <div>
                      <h3 className="mb-1 text-xs text-signal">Why it matters</h3>
                      <p className="leading-relaxed text-bone/90">{v.severity_rationale}</p>
                      <p className="mt-2 text-sm text-ash">{v.cwe}: {TYPE_INFO[v.type].cweName}. {TYPE_INFO[v.type].owasp}.</p>
                    </div>
                    {provenLeaks(v, security).length > 0 && (
                      <div>
                        <h3 className="mb-1 text-xs text-signal">What the exploit proved</h3>
                        <ul className="list-disc space-y-1 pl-5 text-bone/90 marker:text-ember">
                          {provenLeaks(v, security).map((leak) => (
                            <li key={leak}><Highlight text={leak} /></li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <div>
                      <h3 className="mb-1 text-xs text-signal">The fix{v.fix_source && <span className="ml-2 text-ash">{fixSourceLabel[v.fix_source]}</span>}</h3>
                      <p className="leading-relaxed text-bone/90">{v.patch_rationale}</p>
                      <p className="mt-2 text-sm text-ash">{codeLocation(v)} / {d.hunks} changes, +{d.added} / −{d.removed} lines</p>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <h3 className="mb-2 text-xs text-signal">Proof checks</h3>
                      <ProofChecks checks={v.checks} compact />
                    </div>
                    {proofCases(target, v.type).length > 0 && (
                    <div>
                    <h3 className="mb-2 text-xs text-signal">Test results</h3>
                    <ul className="divide-y divide-border/60 border border-border">
                      {proofCases(target, v.type).map((c) => {
                        const r = caseResult(c, v)
                        return (
                          <li key={c.id} className="flex items-center justify-between gap-4 px-4 py-2.5 text-sm">
                            <span className="text-bone/85"><strong className="text-bone">{c.id}</strong> {c.kind === 'Security' ? 'exploit blocked' : 'normal use works'}</span>
                            <Pill tone={caseTone[r]}>{r}</Pill>
                          </li>
                        )
                      })}
                    </ul>
                    </div>
                    )}
                  </div>
                </div>
              </Panel>
            )
          })}
        </div>
      )}
    </>
  )
}

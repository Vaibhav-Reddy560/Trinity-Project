import { Ban, Database, FileCode2, ShieldAlert } from 'lucide-react'
import { PageHeader, Panel } from '@/components/Panel'
import { CASES, HARNESS_POINTS, IN_SCOPE, OUT_OF_SCOPE, TARGET } from '@/lib/scope'

const harnessIcons = [FileCode2, Database, ShieldAlert]

export function ScopePage() {
  return (
    <>
      <PageHeader
        title="Target & scope"
        description={<p>Exactly what PatchProof tests, how exploits are proven, and which cases decide whether a fix works.</p>}
      />

      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
        <Panel title="Target">
          <dl className="space-y-4 text-sm">
            {[
              ['Application', `${TARGET.name}, a deliberately vulnerable banking app`],
              ['Source', TARGET.repo],
              ['Pinned commit', `${TARGET.commit} (${TARGET.commitDate})`],
              ['Module under test', TARGET.module],
              ['Licence', TARGET.license],
              ['Snapshot', TARGET.snapshot],
            ].map(([k, v]) => (
              <div key={k}>
                <dt className="label">{k}</dt>
                <dd className="mt-1 break-words text-bone">{v}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-5 border-t border-border pt-4 text-xs leading-relaxed text-ash">
            The snapshot is never edited. Patches are applied to a working copy that Reset restores.
          </p>
        </Panel>

        <div className="flex min-w-0 flex-col gap-5">
          <Panel title="In scope" bodyClassName="p-0">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-ash">
                  <th scope="col" className="py-3 pr-4 pl-5 font-medium">File</th>
                  <th scope="col" className="py-3 pr-4 font-medium">Lines</th>
                  <th scope="col" className="py-3 pr-5 font-medium">What we do with it</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {IN_SCOPE.map((f) => (
                  <tr key={f.file}>
                    <td className="py-3 pr-4 pl-5 font-semibold text-bone">{f.file}</td>
                    <td className="py-3 pr-4 text-bone/85 tabular-nums">{f.lines}</td>
                    <td className="py-3 pr-5 text-ash">{f.role}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <Panel title="Out of scope">
            <ul className="grid gap-2 md:grid-cols-2">
              {OUT_OF_SCOPE.map((o) => (
                <li key={o} className="flex items-start gap-3 text-sm text-bone/85">
                  <Ban className="mt-0.5 size-4 shrink-0 text-blood-600" aria-hidden />
                  {o}
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>

      <Panel title="How exploits are proven" className="mt-5">
        <ul className="grid gap-5 md:grid-cols-3">
          {HARNESS_POINTS.map((p, i) => {
            const Icon = harnessIcons[i]
            return (
              <li key={p.title} className="border-l-2 border-signal/60 pl-4">
                <p className="flex items-center gap-2 font-semibold text-bone"><Icon className="size-4 text-signal" aria-hidden />{p.title}</p>
                <p className="mt-2 text-sm leading-relaxed text-ash">{p.body}</p>
              </li>
            )
          })}
        </ul>
      </Panel>

      <Panel title="Test cases" className="mt-5" bodyClassName="p-0 overflow-x-auto">
        <table className="w-full min-w-[44rem] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-ash">
              <th scope="col" className="py-3 pr-4 pl-5 font-medium">Case</th>
              <th scope="col" className="py-3 pr-4 font-medium">Kind</th>
              <th scope="col" className="py-3 pr-4 font-medium">Signed in as</th>
              <th scope="col" className="py-3 pr-4 font-medium">Message sent</th>
              <th scope="col" className="py-3 pr-5 font-medium">Expected after the fix</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {CASES.map((c) => (
              <tr key={c.id}>
                <td className="py-3 pr-4 pl-5 font-semibold text-bone">{c.id}</td>
                <td className="py-3 pr-4 text-bone/85">{c.kind}</td>
                <td className="py-3 pr-4 text-bone/85">{c.user}</td>
                <td className="py-3 pr-4 text-bone">“{c.input}”</td>
                <td className="py-3 pr-5 text-ash">{c.expected}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </>
  )
}

import { ArrowRight, Ban, Database, FileCode2, FolderOpen, GitBranch, Loader, ScanSearch, ShieldAlert } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { PageHeader, Panel } from '@/components/Panel'
import { Pill } from '@/components/Pills'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { ApiState, Pending } from '@/hooks/useVulns'
import { href } from '@/lib/router'
import { harnessPoints, scopeLines, targetCases } from '@/lib/scope'
import { useTargets } from '@/lib/targetContext'
import type { TargetSelection } from '@/lib/types'
import { cn } from '@/lib/utils'

const harnessIcons = [FileCode2, Database, ShieldAlert]

type Mode = 'git_url' | 'path'

function problemWith(mode: Mode, value: string): string | null {
  const v = value.trim()
  if (!v) return null
  if (mode === 'git_url' && !/^https:\/\/[^\s]+\/[^\s]+$/.test(v)) return 'Use a public https:// address, like https://github.com/owner/repo.'
  if (mode === 'path' && !(v.startsWith('/') || v.startsWith('~'))) return 'Use the full path to the folder, like /Users/you/code/my-app.'
  return null
}

export function ScopePage({ pending, apiState, onSelect }: {
  pending: Pending
  apiState: ApiState
  onSelect: (s: TargetSelection) => void
}) {
  const { active, profiles, error } = useTargets()
  const [mode, setMode] = useState<Mode>('git_url')
  const [value, setValue] = useState('')
  const busy = pending !== null
  const selecting = pending?.action === 'select'
  const problem = problemWith(mode, value)
  const cases = targetCases(active)
  const live = apiState !== 'mock'

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!value.trim() || problem) return
    onSelect(mode === 'git_url' ? { git_url: value.trim() } : { path: value.trim() })
  }

  return (
    <>
      <PageHeader
        title="Targets"
        description={
          <p>
            Choose what PatchProof tests. Practice targets get the full loop: find, prove with a live exploit, patch and
            verify. Your own projects are never run: findings are located to the exact lines, fixed in a copy and proven by static checks.
          </p>
        }
      />

      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-2">
        <Panel title="Practice targets" aside={<span>Full pipeline</span>} bodyClassName="p-0">
          <ul className="divide-y divide-border">
            {profiles.map((p) => {
              const isActive = p.id === active.id
              return (
                <li key={p.id} className={cn('flex flex-wrap items-start justify-between gap-4 px-5 py-4', isActive && 'bg-blood-950/60')}>
                  <div className="min-w-0 flex-1">
                    <p className="font-semibold text-bone">{p.name}</p>
                    <p className="mt-1 text-sm leading-relaxed text-ash">{p.summary}</p>
                    <p className="mt-2 text-xs text-ash">{p.commit ? `Pinned at ${p.commit}` : p.source}</p>
                  </div>
                  {isActive ? (
                    <Pill tone="hot">Active</Pill>
                  ) : (
                    <Button variant="outline" size="lg" disabled={busy || !live} onClick={() => onSelect({ id: p.id })}>
                      Switch to this target
                    </Button>
                  )}
                </li>
              )
            })}
          </ul>
        </Panel>

        <Panel title="Scan your own project" aside={<span>Never run</span>}>
          <form onSubmit={submit} className="space-y-4" noValidate>
            <div role="radiogroup" aria-label="Where the project is" className="flex border border-border">
              {([['git_url', 'Git URL', GitBranch], ['path', 'Local folder', FolderOpen]] as const).map(([m, label, Icon]) => (
                <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}
                  className={cn('flex flex-1 items-center justify-center gap-2 py-2 text-sm', mode === m ? 'bg-blood-800 text-bone' : 'text-ash hover:text-bone')}>
                  <Icon className="size-4" aria-hidden /> {label}
                </button>
              ))}
            </div>
            <label className="block">
              <span className="label">{mode === 'git_url' ? 'Public repository address' : 'Folder on this machine'}</span>
              <Input value={value} onChange={(e) => setValue(e.target.value)} disabled={!live}
                placeholder={mode === 'git_url' ? 'https://github.com/owner/repo' : '/Users/you/code/my-app'}
                aria-invalid={problem ? true : undefined} aria-describedby="project-help" className="mt-1.5 h-10" />
            </label>
            {problem && <p role="alert" className="text-sm text-ember">{problem}</p>}
            {error && !busy && <p role="alert" className="border border-ember/60 bg-ember/10 px-3 py-2 text-sm text-ember">{error.message}</p>}
            <ul id="project-help" className="space-y-1 text-xs text-ash">
              <li>Python files are analysed. Dependencies, virtual environments and build output are skipped.</li>
              <li>Your code is read, never run, and your folder is never changed: fixes go to a copy you can download as one patch.</li>
              <li>{live ? 'Git repositories are cloned shallowly into PatchProof’s data folder.' : 'Needs the live API: start it with make api.'}</li>
            </ul>
            <Button type="submit" size="lg" disabled={!live || busy || !value.trim() || !!problem} className="w-full shadow-[var(--glow-signal)] disabled:shadow-none">
              {selecting ? <><Loader className="spin-scan" /> Loading and scanning</> : <><ScanSearch /> Scan project</>}
            </Button>
          </form>
        </Panel>
      </div>

      <Panel title={`Active target: ${active.name}`} className="mt-5"
        aside={<a href={href.findings} className="flex items-center gap-1 hover:text-bone">Open findings <ArrowRight className="size-3.5" /></a>}>
        <div className="grid gap-6 xl:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <dl className="space-y-4 text-sm">
            {[
              ['What it is', active.summary],
              ['Source', active.source],
              ['Version', active.commit ? `Pinned at commit ${active.commit}` : active.kind === 'project' ? 'As it is on disk now' : 'Shipped with PatchProof'],
              ['Under test', active.module],
              ...(active.stats ? [['Last scan', `${active.stats.files_scanned} files scanned` + (active.stats.parse_errors ? `, ${active.stats.parse_errors} could not be parsed` : '') + (active.stats.files_skipped ? `, ${active.stats.files_skipped} skipped` : '')]] : []),
            ].map(([k, v]) => (
              <div key={k}>
                <dt className="label">{k}</dt>
                <dd className="mt-1 break-words text-bone">{v}</dd>
              </div>
            ))}
          </dl>

          <div className="min-w-0 space-y-6">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <caption className="mb-2 text-left text-xs text-signal">In scope</caption>
                <thead>
                  <tr className="border-b border-border text-left text-xs text-ash">
                    <th scope="col" className="py-2 pr-4 font-medium">Files</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Lines</th>
                    <th scope="col" className="py-2 font-medium">What we do with it</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {active.in_scope.map((f) => (
                    <tr key={f.file}>
                      <td className="py-2.5 pr-4 font-semibold text-bone">{f.file === '**/*.py' ? 'Every Python file' : f.file}</td>
                      <td className="py-2.5 pr-4 text-bone/85 tabular-nums">{scopeLines(f.lines)}</td>
                      <td className="py-2.5 text-ash">{f.role}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div>
              <h3 className="mb-2 text-xs text-signal">Out of scope</h3>
              <ul className="grid gap-2 md:grid-cols-2">
                {active.out_of_scope.map((o) => (
                  <li key={o} className="flex items-start gap-3 text-sm text-bone/85">
                    <Ban className="mt-0.5 size-4 shrink-0 text-blood-600" aria-hidden />
                    {o}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </Panel>

      <Panel title={active.provable ? 'How exploits are proven' : 'How this scan works'} className="mt-5">
        <ul className="grid gap-5 md:grid-cols-3">
          {harnessPoints(active).map((p, i) => {
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

      {cases.length > 0 && (
        <Panel title="Test cases" className="mt-5" bodyClassName="p-0 overflow-x-auto">
          <table className="w-full min-w-[44rem] border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-ash">
                <th scope="col" className="py-3 pr-4 pl-5 font-medium">Case</th>
                <th scope="col" className="py-3 pr-4 font-medium">Kind</th>
                <th scope="col" className="py-3 pr-4 font-medium">As</th>
                <th scope="col" className="py-3 pr-4 font-medium">Input</th>
                <th scope="col" className="py-3 pr-5 font-medium">Expected after the fix</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {cases.map((c) => (
                <tr key={c.id}>
                  <td className="py-3 pr-4 pl-5 font-semibold text-bone">{c.id}</td>
                  <td className="py-3 pr-4 text-bone/85">{c.kind}</td>
                  <td className="py-3 pr-4 text-bone/85">{c.user}</td>
                  <td className="py-3 pr-4 break-words text-bone">{c.input}</td>
                  <td className="py-3 pr-5 text-ash">{c.expected}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </>
  )
}

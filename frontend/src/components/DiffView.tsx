import { Download } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { downloadFile } from '@/lib/format'
import { diffStats } from '@/lib/pipeline'
import { cn } from '@/lib/utils'

type Kind = 'add' | 'del' | 'ctx' | 'hunk'
type Row = { kind: Kind; text: string; oldNo?: number; newNo?: number }

function parseUnified(diff: string): Row[] {
  const rows: Row[] = []
  let oldNo = 0
  let newNo = 0
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('---') || raw.startsWith('+++')) continue
    const hunk = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunk) {
      oldNo = Number(hunk[1])
      newNo = Number(hunk[2])
      rows.push({ kind: 'hunk', text: `Original from line ${oldNo}, patched from line ${newNo}` })
    } else if (raw.startsWith('+')) rows.push({ kind: 'add', text: raw.slice(1), newNo: newNo++ })
    else if (raw.startsWith('-')) rows.push({ kind: 'del', text: raw.slice(1), oldNo: oldNo++ })
    else if (raw.length) rows.push({ kind: 'ctx', text: raw.slice(1), oldNo: oldNo++, newNo: newNo++ })
  }
  return rows
}

type Pair = { hunk?: string; left?: Row; right?: Row }

function toSplit(rows: Row[]): Pair[] {
  const out: Pair[] = []
  let dels: Row[] = []
  let adds: Row[] = []
  const flush = () => {
    for (let i = 0; i < Math.max(dels.length, adds.length); i++) out.push({ left: dels[i], right: adds[i] })
    dels = []
    adds = []
  }
  for (const r of rows) {
    if (r.kind === 'del') dels.push(r)
    else if (r.kind === 'add') adds.push(r)
    else {
      flush()
      out.push(r.kind === 'hunk' ? { hunk: r.text } : { left: r, right: r })
    }
  }
  flush()
  return out
}

const tone: Record<Kind, string> = {
  add: 'bg-signal/12 text-phosphor',
  del: 'bg-blood-950 text-ash',
  ctx: 'text-bone/70',
  hunk: 'text-blood-600',
}
const mark = { add: '+', del: '−', ctx: '', hunk: '' }

function Num({ n }: { n?: number }) {
  return <td className="w-11 pr-3 text-right align-top text-ash/45 select-none">{n ?? ''}</td>
}

function Cell({ row, side }: { row?: Row; side: 'old' | 'new' }) {
  if (!row) return <><Num /><td className="bg-void/40" /></>
  const kind = row.kind === 'ctx' ? 'ctx' : row.kind
  return (
    <>
      <Num n={side === 'old' ? row.oldNo : row.newNo} />
      <td className={cn('pr-4 break-words whitespace-pre-wrap', tone[kind])}>
        <span aria-hidden className="mr-2 inline-block w-3 select-none">{mark[kind]}</span>
        {row.text || ' '}
      </td>
    </>
  )
}

export function DiffView({ filePath, diff, vulnId }: { filePath: string; diff: string; vulnId: string }) {
  const [mode, setMode] = useState<'unified' | 'split'>('unified')
  const rows = parseUnified(diff)
  const stats = diffStats(diff)

  return (
    <div className="min-w-0 border border-border bg-void/70">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-2">
        <div className="flex items-center gap-3 text-xs">
          <span className="text-bone">{filePath}</span>
          <span className="text-phosphor">+{stats.added}</span>
          <span className="text-ash">−{stats.removed}</span>
        </div>
        <div className="no-print flex items-center gap-2">
          <div role="group" aria-label="Diff layout" className="flex border border-border">
            {(['unified', 'split'] as const).map((m) => (
              <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)}
                className={cn('px-3 py-1 text-xs', mode === m ? 'bg-blood-800 text-bone' : 'text-ash hover:text-bone')}>
                {m === 'unified' ? 'Unified' : 'Side by side'}
              </button>
            ))}
          </div>
          <Button variant="ghost" size="xs" className="text-ash hover:text-bone" onClick={() => downloadFile(`${vulnId}.patch`, diff, 'text/x-diff')}>
            <Download /> Download .patch
          </Button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className={cn('code w-full border-collapse', mode === 'split' && 'table-fixed')}>
          <caption className="sr-only">Changes to {filePath}</caption>
          {mode === 'split' && (
            <colgroup>
              <col className="w-11" /><col /><col className="w-11" /><col />
            </colgroup>
          )}
          {mode === 'split' && (
            <thead>
              <tr className="border-b border-border text-left text-xs text-ash">
                <th scope="col" colSpan={2} className="py-1.5 pl-14 font-medium">Original</th>
                <th scope="col" colSpan={2} className="py-1.5 pl-14 font-medium">Patched</th>
              </tr>
            </thead>
          )}
          <tbody>
            {mode === 'unified'
              ? rows.map((r, i) =>
                  r.kind === 'hunk' ? (
                    <tr key={i}><td colSpan={3} className="border-y border-border/60 bg-blood-950/60 px-4 py-1 text-xs text-ash">{r.text}</td></tr>
                  ) : (
                    <tr key={i} className={tone[r.kind]}>
                      <Num n={r.oldNo} />
                      <Num n={r.newNo} />
                      <td className="pr-4">
                        <span aria-hidden className="mr-2 inline-block w-3 select-none">{mark[r.kind]}</span>
                        <span className="sr-only">{r.kind === 'add' ? 'Added: ' : r.kind === 'del' ? 'Removed: ' : ''}</span>
                        {r.text || ' '}
                      </td>
                    </tr>
                  ),
                )
              : toSplit(rows).map((p, i) =>
                  p.hunk ? (
                    <tr key={i}><td colSpan={4} className="border-y border-border/60 bg-blood-950/60 px-4 py-1 text-xs text-ash">{p.hunk}</td></tr>
                  ) : (
                    <tr key={i}>
                      <Cell row={p.left} side="old" />
                      <Cell row={p.right} side="new" />
                    </tr>
                  ),
                )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

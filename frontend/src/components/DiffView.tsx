import { cn } from '@/lib/utils'

type Row = { kind: 'add' | 'del' | 'ctx' | 'hunk'; text: string; oldNo?: number; newNo?: number }

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
      rows.push({ kind: 'hunk', text: raw })
    } else if (raw.startsWith('+')) rows.push({ kind: 'add', text: raw.slice(1), newNo: newNo++ })
    else if (raw.startsWith('-')) rows.push({ kind: 'del', text: raw.slice(1), oldNo: oldNo++ })
    else if (raw.length) rows.push({ kind: 'ctx', text: raw.slice(1), oldNo: oldNo++, newNo: newNo++ })
  }
  return rows
}

const rowTone = {
  add: 'bg-signal/12 text-phosphor',
  del: 'bg-blood-950 text-ash line-through decoration-blood-600',
  ctx: 'text-bone/70',
  hunk: 'text-blood-600',
} as const

export function DiffView({ filePath, diff, rationale }: { filePath: string; diff: string | null; rationale: string | null }) {
  return (
    <div className="panel flex min-h-0 flex-col">
      <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="text-sm text-bone">Patch</h2>
        <span className="truncate text-xs text-ash">{filePath}</span>
      </header>
      {diff ? (
        <div className="min-h-0 flex-1 overflow-auto">
          {rationale && <p className="border-b border-border px-4 py-3 text-sm text-bone/85">{rationale}</p>}
          <table className="w-full border-collapse text-[0.75rem] leading-[1.7]">
            <caption className="sr-only">Unified diff of {filePath}</caption>
            <tbody>
              {parseUnified(diff).map((r, i) => (
                <tr key={i} className={rowTone[r.kind]}>
                  <td className="w-10 pr-2 text-right align-top text-ash/50 tabular-nums select-none">{r.oldNo ?? ''}</td>
                  <td className="w-10 pr-2 text-right align-top text-ash/50 tabular-nums select-none">{r.newNo ?? ''}</td>
                  <td aria-hidden className={cn('w-4 align-top select-none', r.kind === 'add' && 'text-signal', r.kind === 'del' && 'text-blood-600')}>
                    {r.kind === 'add' ? '+' : r.kind === 'del' ? '−' : ''}
                  </td>
                  <td className="pr-4 whitespace-pre">
                    <span className="sr-only">{r.kind === 'add' ? 'added: ' : r.kind === 'del' ? 'removed: ' : ''}</span>
                    {r.text}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="px-4 py-4 text-sm text-ash">No patch yet. A patch is generated once the exploit has been reproduced.</p>
      )}
    </div>
  )
}

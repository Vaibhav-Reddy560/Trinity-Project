import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'

export function CodeBlock({ code, startLine, label }: { code: string; startLine: number; label: string }) {
  const [copied, setCopied] = useState(false)
  const lines = code.split('\n')

  const copy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  return (
    <figure className="min-w-0 border border-border bg-void/70">
      <figcaption className="flex items-center justify-between gap-3 border-b border-border px-4 py-2">
        <span className="truncate text-xs text-ash">{label}</span>
        <Button variant="ghost" size="xs" onClick={copy} className="no-print text-ash hover:text-bone">
          {copied ? <Check /> : <Copy />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </figcaption>
      <div className="overflow-x-auto py-3">
        <table className="code border-collapse">
          <tbody>
            {lines.map((line, i) => (
              <tr key={i}>
                <td className="w-12 pr-4 pl-4 text-right align-top text-ash/50 select-none">{startLine + i}</td>
                <td className="pr-6 text-bone/90">{line || ' '}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </figure>
  )
}

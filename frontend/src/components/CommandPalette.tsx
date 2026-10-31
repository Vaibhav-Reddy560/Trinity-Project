import { Bug, Crosshair, FileText, LayoutDashboard, Play, ScanSearch, ScrollText, Sparkles } from 'lucide-react'
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from '@/components/ui/command'
import type { Pending } from '@/hooks/useVulns'
import { useAI } from '@/lib/aiContext'
import { severityLabel, typeName } from '@/lib/format'
import { verdictFor } from '@/lib/pipeline'
import { href } from '@/lib/router'
import type { Action, Vuln } from '@/lib/types'

const PAGES = [
  { label: 'Overview', icon: LayoutDashboard, to: href.overview },
  { label: 'Findings', icon: Bug, to: href.findings },
  { label: 'Targets', icon: Crosshair, to: href.scope },
  { label: 'Activity', icon: ScrollText, to: href.activity },
  { label: 'Report', icon: FileText, to: href.report },
]

export function CommandPalette({ open, onOpenChange, vulns, pending, onRun }: {
  open: boolean
  onOpenChange: (o: boolean) => void
  vulns: Vuln[]
  pending: Pending
  onRun: (a: Action) => void
}) {
  const ai = useAI()
  const go = (to: string) => {
    window.location.hash = to
    onOpenChange(false)
  }
  const act = (a: Action) => {
    onRun(a)
    onOpenChange(false)
  }

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Search PatchProof" description="Jump to a page or finding, or run an action."
      className="rounded-none! border border-border bg-panel sm:max-w-xl">
      <Command className="rounded-none! bg-panel">
        <CommandInput placeholder="Search pages, findings and actions" />
        <CommandList className="max-h-96">
          <CommandEmpty>Nothing matches. Try a weakness name, a CWE or a page.</CommandEmpty>
          <CommandGroup heading="Actions">
            <CommandItem disabled={pending !== null} onSelect={() => act('run-all')}>
              <Play className="text-signal" /> Run full pipeline
            </CommandItem>
            <CommandItem disabled={pending !== null} onSelect={() => act('scan')}>
              <ScanSearch /> Scan target
            </CommandItem>
            {ai.enabled && (
              <>
                <CommandItem disabled={pending !== null} onSelect={() => act('deep-scan')}>
                  <Sparkles className="text-signal" /> AI deep scan
                </CommandItem>
                <CommandItem disabled={pending !== null || vulns.length === 0} onSelect={() => act('review-all')}>
                  <Sparkles /> AI review all findings
                </CommandItem>
                <CommandItem disabled={pending !== null || vulns.length === 0} onSelect={() => act('fix-all')}>
                  <Sparkles /> AI fix all open findings
                </CommandItem>
              </>
            )}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="Pages">
            {PAGES.map((p) => (
              <CommandItem key={p.to} onSelect={() => go(p.to)}>
                <p.icon /> {p.label}
              </CommandItem>
            ))}
          </CommandGroup>
          {vulns.length > 0 && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Findings">
                {vulns.map((v) => (
                  <CommandItem key={v.id} value={`${typeName[v.type]} ${v.title} ${v.cwe} ${v.id}`} onSelect={() => go(href.finding(v.id))}>
                    <Bug className="text-signal" />
                    <span className="truncate">{typeName[v.type]}</span>
                    <CommandShortcut className="tracking-normal">{severityLabel[v.severity]} / {verdictFor(v)}</CommandShortcut>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}
        </CommandList>
      </Command>
    </CommandDialog>
  )
}

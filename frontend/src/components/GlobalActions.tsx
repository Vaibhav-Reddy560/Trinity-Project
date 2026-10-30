import { Play, RotateCcw, ScanSearch } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import type { Pending } from '@/hooks/useVulns'
import type { Action } from '@/lib/types'

export function GlobalActions({ pending, onRun }: { pending: Pending; onRun: (a: Action) => void }) {
  const busy = pending !== null
  return (
    <div className="flex flex-wrap items-center gap-2">
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <Button variant="ghost" size="lg" disabled={busy} className="text-ash hover:text-bone" aria-label="Reset workspace">
            <RotateCcw /> <span className="hidden sm:inline">Reset</span>
          </Button>
        </AlertDialogTrigger>
        <AlertDialogContent className="border-border bg-panel">
          <AlertDialogHeader>
            <AlertDialogTitle className="font-heading tracking-[0.06em] uppercase">Reset the workspace?</AlertDialogTitle>
            <AlertDialogDescription className="text-bone/80">
              This removes every finding and restores the target code to its original, unpatched state. Run a new scan afterwards.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep findings</AlertDialogCancel>
            <AlertDialogAction onClick={() => onRun('reset')}>Reset workspace</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <Button variant="outline" size="lg" disabled={busy} onClick={() => onRun('scan')} aria-label="Scan target">
        <ScanSearch /> <span className="hidden sm:inline">Scan target</span>
      </Button>
      <Button size="lg" disabled={busy} onClick={() => onRun('run-all')} className="shadow-[var(--glow-signal)] disabled:shadow-none">
        <Play /> {pending?.action === 'run-all' ? 'Running pipeline' : 'Run full pipeline'}
      </Button>
    </div>
  )
}

import { ScanSearch } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { Pending } from '@/hooks/useVulns'
import { useActiveTarget } from '@/lib/targetContext'

export function EmptyFindings({ pending, onScan }: { pending: Pending; onScan: () => void }) {
  const target = useActiveTarget()
  const scanning = pending?.action === 'scan' || pending?.action === 'run-all' || pending?.action === 'select'
  return (
    <section className="panel grid place-items-center px-6 py-16 text-center">
      <div className="max-w-md">
        <ScanSearch className="mx-auto size-10 text-signal" aria-hidden />
        <h2 className="mt-5 text-xl text-bone">{scanning ? 'Scanning target' : 'No findings yet'}</h2>
        <p className="mt-3 text-ash">
          {scanning
            ? `Reading the in-scope files of ${target.name} for weaknesses.`
            : `Scan ${target.name} to find weaknesses in its ${target.module.toLowerCase()}.`}
        </p>
        {!scanning && (
          <Button size="lg" className="mt-6" onClick={onScan}>
            <ScanSearch /> Scan target
          </Button>
        )}
      </div>
    </section>
  )
}

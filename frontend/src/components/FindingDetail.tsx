import { Button } from '@/components/ui/button'
import { canPatch, canRunPoc, canVerify, severityColor, severityLabel } from '@/lib/pipeline'
import type { Vuln } from '@/lib/types'
import { DiffView } from './DiffView'
import { EvidenceDisc } from './EvidenceDisc'
import { EvidenceLog } from './EvidenceLog'

export type StepAction = 'poc' | 'patch' | 'verify'

export function FindingDetail({ vuln, busy, error, onAction }: {
  vuln: Vuln
  busy: boolean
  error: string | null
  onAction: (a: StepAction) => void
}) {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <section className="panel grid grid-cols-[minmax(0,1fr)] gap-6 p-5 md:grid-cols-[minmax(15rem,22rem)_minmax(0,1fr)] md:p-6" aria-labelledby="finding-title">
        <div className="relative">
          <EvidenceDisc vuln={vuln} busy={busy} />
          <span className="sticker absolute -bottom-1 left-2">Synthetic data</span>
        </div>

        <div className="flex min-w-0 flex-col">
          <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ash">
            <span className="font-semibold" style={{ color: severityColor[vuln.severity] }}>
              {severityLabel[vuln.severity]} severity
            </span>
            <span>{vuln.cwe}</span>
            <span className="tabular-nums">
              {vuln.file_path} lines {vuln.line_number}-{vuln.end_line}
            </span>
          </p>
          <h1 id="finding-title" className="mt-3 text-[1.45rem] text-bone md:text-[1.7rem]">
            {vuln.title}
          </h1>
          <p className="mt-4 max-w-[62ch] text-bone/80">{vuln.severity_rationale}</p>

          <figure className="mt-5 min-w-0">
            <figcaption className="mb-2 text-xs text-ash">Affected code</figcaption>
            <pre className="overflow-x-auto border-l-2 border-signal bg-void/80 px-4 py-3 text-[0.75rem] leading-relaxed text-bone/90">
              {vuln.original_code}
            </pre>
          </figure>

          <div className="mt-auto pt-6">
            {vuln.patchable ? (
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" disabled={busy || !canRunPoc(vuln)} onClick={() => onAction('poc')}>
                  Run exploit
                </Button>
                <Button disabled={busy || !canPatch(vuln)} onClick={() => onAction('patch')} className="shadow-[var(--glow-signal)] disabled:bg-blood-950 disabled:text-ash disabled:opacity-100 disabled:shadow-none">
                  Apply patch
                </Button>
                <Button variant="outline" disabled={busy || !canVerify(vuln)} onClick={() => onAction('verify')}>
                  Verify fix
                </Button>
              </div>
            ) : (
              <p className="text-sm text-ash">Reported only. Auto-patching isn't available for this finding type yet.</p>
            )}
            {error && (
              <p role="alert" className="mt-3 text-sm text-ember">
                {error}
              </p>
            )}
          </div>
        </div>
      </section>

      <div className="grid min-h-[22rem] grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <EvidenceLog poc={vuln.poc_log} verification={vuln.verification_log} />
        <DiffView filePath={vuln.file_path} diff={vuln.diff} rationale={vuln.patch_rationale} />
      </div>
    </div>
  )
}

import { Sparkles } from 'lucide-react'
import { Pill, type Tone } from '@/components/Pills'
import { Button } from '@/components/ui/button'
import { aiName, useAI } from '@/lib/aiContext'
import { ago, modelName } from '@/lib/format'
import type { AIReview } from '@/lib/types'

const VERDICT: Record<NonNullable<AIReview['verdict']>, { label: string; tone: Tone }> = {
  confirmed: { label: 'Likely real', tone: 'amber' },
  false_positive: { label: 'Likely false positive', tone: 'neutral' },
  uncertain: { label: 'Needs a closer look', tone: 'muted' },
}

/** The AI model's second opinion on a finding. Labelled as opinion: it never changes a finding's status. */
export function AIReviewCard({ review, busy, running, onReview }: {
  review: AIReview | null
  busy: boolean
  running: boolean
  onReview: () => void
}) {
  const ai = useAI()
  const verdict = review?.verdict ? VERDICT[review.verdict] : null
  return (
    <div className="border border-border bg-void/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-xs text-signal"><Sparkles className="size-4" aria-hidden />AI review</h3>
        {verdict && (
          <div className="flex items-center gap-2">
            <Pill tone={verdict.tone}>{verdict.label}</Pill>
            {review?.confidence && <span className="text-xs text-ash">{review.confidence} confidence</span>}
          </div>
        )}
      </div>

      {review?.verdict ? (
        <div className="mt-3 space-y-3 text-sm leading-relaxed">
          <p className="text-bone/90">{review.reasoning}</p>
          {review.attack_scenario && <p><span className="text-ash">Attack: </span><span className="text-bone/90">{review.attack_scenario}</span></p>}
          {review.fix_hint && <p><span className="text-ash">Fix: </span><span className="text-bone/90">{review.fix_hint}</span></p>}
          <p className="text-xs text-ash">
            Opinion from {modelName(review.model)}, {ago(review.reviewed_at)}. It informs you; it never marks anything fixed or proven.
          </p>
        </div>
      ) : (
        <p className="mt-3 text-sm text-ash">
          {review?.error
            ? <span className="text-ember">Review failed: {review.error}</span>
            : ai.enabled
              ? `Ask ${modelName(ai.model)} whether this is a real, reachable weakness or a false positive, and how an attack would work.`
              : `AI review is off. ${ai.reason ?? ''}`}
        </p>
      )}

      {ai.enabled && (
        <Button variant="outline" size="lg" className="mt-4" disabled={busy} onClick={onReview}>
          <Sparkles /> {running ? 'Reviewing' : review ? 'Review again' : `Ask ${aiName(ai)} to review`}
        </Button>
      )}
    </div>
  )
}

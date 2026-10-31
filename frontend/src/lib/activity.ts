import type { LogLine, Vuln } from './types'

export interface ActivityItem extends LogLine {
  vuln: Vuln
  phase: 'Exploit' | 'Baseline' | 'Verification'
}

export function activityOf(vulns: Vuln[]): ActivityItem[] {
  return vulns
    .flatMap((vuln) => [
      ...vuln.poc_log.map((l) => ({ ...l, vuln, phase: vuln.provable ? ('Exploit' as const) : ('Baseline' as const) })),
      ...vuln.verification_log.map((l) => ({ ...l, vuln, phase: 'Verification' as const })),
    ])
    .sort((a, b) => b.ts.localeCompare(a.ts))
}

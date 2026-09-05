import type { AlertInfo, TechniqueInfo } from '../api'

/** One MITRE technique and the alerts on this incident that were tagged
 *  with it -- "Technique -> Evidence -> Events -> Detection Rule"
 *  (final_plan.md Phase 10), not a bare technique badge with no path back
 *  to what actually produced it. `alerts` is a filtered view of the same
 *  IncidentDetailResponse.alerts list the Evidence tab already renders;
 *  no separate fetch, no new backend data. */
export interface TechniqueEvidenceGroup {
  technique: TechniqueInfo
  alerts: AlertInfo[]
}

export function groupAlertsByTechnique(techniques: TechniqueInfo[], alerts: AlertInfo[]): TechniqueEvidenceGroup[] {
  return techniques.map((technique) => ({
    technique,
    alerts: alerts.filter((alert) => alert.technique_id === technique.id),
  }))
}

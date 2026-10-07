import type { IncidentSummary, MitreTechnique } from '../api'
import type { IncidentFilterState } from '../components/incidents/IncidentFilters'
import { incidentRef } from './format'
import { isTactic } from './tactics'

/**
 * Incident filtering, shared by the Incidents page and anything else that
 * needs the same semantics (deep links from the dashboard, reports).
 *
 * Filtering happens client-side because the incidents snapshot is already
 * fully loaded in context; going back to the API per keystroke would be
 * slower and would make the stat cards disagree with the table.
 */
export function filterIncidents(
  incidents: IncidentSummary[],
  filters: IncidentFilterState,
  techniqueById: Map<string, MitreTechnique>,
): IncidentSummary[] {
  const term = filters.search.trim().toLowerCase()
  // Windows are measured back from the newest incident in the data, not
  // from wall-clock now: incidents carry the historical event time of the
  // logs they came from, so "last 24 hours" of Date.now() was empty for any
  // imported archive (the page's stat cards already anchored this way).
  const anchor = incidents.reduce((max, incident) => Math.max(max, Date.parse(incident.created_at) || 0), 0)
  const cutoff = filters.window === 'all' || anchor === 0 ? null : anchor - Number(filters.window) * 3600_000

  return incidents.filter((incident) => {
    if (filters.severity !== 'all' && incident.severity !== filters.severity) return false
    if (filters.status !== 'all' && incident.status !== filters.status) return false
    if (cutoff !== null && new Date(incident.created_at).getTime() < cutoff) return false

    if (filters.tactic !== 'all') {
      const tactics = incidentTactics(incident, techniqueById)
      if (!tactics.includes(filters.tactic)) return false
    }

    if (term) {
      const haystack = [incident.title, incident.host, incidentRef(incident.id), ...incident.mitre_technique_ids]
        .join(' ')
        .toLowerCase()
      if (!haystack.includes(term)) return false
    }

    return true
  })
}

/** Every MITRE tactic an incident touches, via its techniques. */
export function incidentTactics(incident: IncidentSummary, techniqueById: Map<string, MitreTechnique>): string[] {
  const tactics = new Set<string>()
  for (const techniqueId of incident.mitre_technique_ids) {
    for (const tactic of techniqueById.get(techniqueId)?.tactics ?? []) {
      if (isTactic(tactic)) tactics.add(tactic)
    }
  }
  return [...tactics]
}

/** The tactic shown in the incident table -- the first tactic of the first
 *  technique, matching attackVectorBreakdown primary-vector attribution. */
export function primaryTactic(incident: IncidentSummary, techniqueById: Map<string, MitreTechnique>): string | null {
  const first = incident.mitre_technique_ids[0]
  if (!first) return null
  return techniqueById.get(first)?.tactics.find(isTactic) ?? null
}

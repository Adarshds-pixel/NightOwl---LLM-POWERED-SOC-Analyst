import { ChevronDown, ChevronRight, Crosshair } from 'lucide-react'
import { useState } from 'react'
import type { AlertInfo, TechniqueInfo } from '../../api'
import { eventTypeLabel } from '../../lib/events'
import { formatDateTime } from '../../lib/format'
import { groupAlertsByTechnique } from '../../lib/mitreLinks'
import { Badge, Card, ListRow, SeverityDotMarker } from '../ui'

/**
 * "MITRE should not just be Alert -> T1003. Make it investigation-
 * oriented: Technique -> Evidence -> Events -> Detection Rule."
 * (final_plan.md Phase 10 / pending.md item 5). Each technique this
 * incident rolled up is expandable into the real alerts that carried it
 * -- click one to open the exact same evidence drawer the Evidence tab
 * uses, so "which rule/event backs this technique" is never more than
 * one click away. Purely a reshaping of data IncidentDetailResponse
 * already returns; no new backend work.
 */
export function MitreEvidenceLinks({
  techniques,
  alerts,
  onSelectAlert,
  className,
}: {
  techniques: TechniqueInfo[]
  alerts: AlertInfo[]
  onSelectAlert: (alert: AlertInfo) => void
  className?: string
}) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const groups = groupAlertsByTechnique(techniques, alerts)

  function toggle(techniqueId: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(techniqueId)) next.delete(techniqueId)
      else next.add(techniqueId)
      return next
    })
  }

  return (
    <Card title="MITRE techniques" icon={<Crosshair className="h-3.5 w-3.5" />} accent="magenta" className={className}>
      {groups.length === 0 ? (
        <p className="text-meta text-text-muted">No techniques resolved for this incident.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {groups.map(({ technique, alerts: evidence }) => {
            const isOpen = expandedIds.has(technique.id)
            return (
              <li key={technique.id} className="rounded-control border border-line bg-surface-2/40">
                <button
                  type="button"
                  onClick={() => toggle(technique.id)}
                  aria-expanded={isOpen}
                  className="flex w-full items-start justify-between gap-2 px-3 py-2 text-left"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-meta text-accent-magenta">{technique.id}</span>
                      <span className="text-body text-text-dim">{technique.name}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {technique.tactics.map((tactic) => (
                        <Badge key={tactic} accent="violet">
                          {tactic.replace(/-/g, ' ')}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <span className="flex shrink-0 items-center gap-1 pt-0.5 text-micro whitespace-nowrap text-text-faint">
                    {evidence.length} evidence
                    {isOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                  </span>
                </button>

                {isOpen && (
                  <div className="border-t border-line-soft px-1 pt-1 pb-2">
                    {evidence.length === 0 ? (
                      <p className="px-2 py-1.5 text-micro text-text-faint">No alerts tagged with this technique.</p>
                    ) : (
                      <ul className="flex flex-col gap-0.5">
                        {evidence.map((alert) => (
                          <ListRow
                            key={alert.id}
                            onClick={() => onSelectAlert(alert)}
                            marker={<SeverityDotMarker severity={alert.severity} />}
                            title={alert.rule_title ?? eventTypeLabel(alert.event.event_id)}
                            meta={alert.event.process ?? alert.event.command_line ?? undefined}
                            trailing={
                              <span className="font-mono text-micro whitespace-nowrap text-text-faint">
                                {formatDateTime(alert.matched_at)}
                              </span>
                            }
                          />
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </Card>
  )
}

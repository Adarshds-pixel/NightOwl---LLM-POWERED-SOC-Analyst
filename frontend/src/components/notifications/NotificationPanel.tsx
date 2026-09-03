import { BellOff, CheckCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { IncidentSummary } from '../../api'
import { formatRelativeTime, incidentRef } from '../../lib/format'
import { EmptyState, SeverityBadge } from '../ui'

/**
 * The bell panel. NightOwl has no notifications table, so rather than
 * inventing one this lists the real thing a notification would be about:
 * open incidents this browser has not acknowledged yet, newest first.
 * Acknowledging is local (see useUnseenIncidents) and says so.
 */
export function NotificationPanel({
  unseen,
  onMarkAllSeen,
  onMarkSeen,
  onNavigate,
}: {
  unseen: IncidentSummary[]
  onMarkAllSeen: () => void
  onMarkSeen: (id: number) => void
  onNavigate: () => void
}) {
  return (
    <div className="w-[336px]">
      <header className="flex items-center justify-between border-b border-line px-3.5 py-2.5">
        <div>
          <p className="text-meta font-semibold tracking-[0.1em] text-text-dim uppercase">Notifications</p>
          <p className="text-micro text-text-faint">
            {unseen.length === 0 ? 'Nothing new' : `${unseen.length} unacknowledged open incident${unseen.length === 1 ? '' : 's'}`}
          </p>
        </div>
        {unseen.length > 0 && (
          <button
            type="button"
            onClick={onMarkAllSeen}
            className="flex items-center gap-1 text-micro font-semibold tracking-wide text-accent-primary uppercase transition-colors hover:text-accent-magenta"
          >
            <CheckCheck className="h-3 w-3" />
            Mark all read
          </button>
        )}
      </header>

      <div className="max-h-[380px] overflow-y-auto p-1.5">
        {unseen.length === 0 ? (
          <EmptyState
            icon={<BellOff className="h-5 w-5" />}
            message="You are all caught up"
            hint="New open incidents appear here as soon as detection creates them."
          />
        ) : (
          unseen.slice(0, 20).map((incident) => (
            <Link
              key={incident.id}
              to={`/incidents/${incident.id}`}
              onClick={() => {
                onMarkSeen(incident.id)
                onNavigate()
              }}
              className="flex items-start gap-2.5 rounded-control border-l-2 border-accent-primary/60 bg-accent-primary/6 px-3 py-2 transition-colors hover:bg-accent-primary/12"
            >
              <div className="min-w-0 flex-1">
                <p className="truncate text-body text-text-dim">{incident.title}</p>
                <p className="mt-0.5 truncate text-micro text-text-faint">
                  {incidentRef(incident.id)} - {incident.host} - {formatRelativeTime(incident.created_at)}
                </p>
              </div>
              <SeverityBadge severity={incident.severity} dot={false} />
            </Link>
          ))
        )}
      </div>

      <footer className="border-t border-line px-3.5 py-2">
        <p className="text-micro text-text-faint">Read state is stored in this browser only.</p>
      </footer>
    </div>
  )
}

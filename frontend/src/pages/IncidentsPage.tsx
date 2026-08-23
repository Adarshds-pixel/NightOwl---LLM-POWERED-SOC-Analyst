import { Link } from 'react-router-dom'
import { EmptyState, ErrorState, LoadingState, SeverityBadge } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { formatRelativeTime } from '../lib/format'

function IncidentsPage() {
  const { incidents, loading, error, refresh } = useIncidentsSnapshot()

  return (
    <div className="space-y-4 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Incidents</h1>
        <p className="mt-1 text-sm text-text-muted">Real incidents from the live API.</p>
      </div>

      {loading && <LoadingState label="Fetching incidents" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}
      {!loading && !error && incidents.length === 0 && <EmptyState message="No incidents ingested yet" />}

      {!loading && !error && incidents.length > 0 && (
        <div className="overflow-hidden rounded border border-border">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-surface/60 text-left text-[10px] tracking-widest text-text-muted uppercase">
              <tr>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Title</th>
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id} className="border-b border-border last:border-0 hover:bg-surface/40">
                  <td className="px-4 py-2">
                    <SeverityBadge severity={incident.severity} />
                  </td>
                  <td className="px-4 py-2">
                    <Link to={`/incidents/${incident.id}`} className="text-text hover:text-accent-cyan">
                      {incident.title}
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-text-muted">{incident.host}</td>
                  <td className="px-4 py-2 text-text-muted uppercase">{incident.status}</td>
                  <td className="px-4 py-2 text-text-muted">{formatRelativeTime(incident.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default IncidentsPage

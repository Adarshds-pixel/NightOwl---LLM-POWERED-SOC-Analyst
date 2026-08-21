import { useParams } from 'react-router-dom'

function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()

  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold text-slate-100">
        Incident #{id}
      </h1>
      <p className="mt-2 text-slate-400">
        Alerts, events, resolved MITRE techniques, and the explain/recommended-response
        panel (GET /incidents/{'{id}'}) land here.
      </p>

      {/* TODO(Pair 2, Day 15): <ChatPanel incidentId={id} /> goes here */}
    </div>
  )
}

export default IncidentDetailPage

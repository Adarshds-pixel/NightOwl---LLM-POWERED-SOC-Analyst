import { Link, useNavigate } from 'react-router-dom'
import { useIncidentsSnapshot } from '../../context/incidents/useIncidentsSnapshot'
import { LogUploadControl } from '../ingest/LogUploadControl'
import { selectMostActionableIncident } from '../../lib/aggregations'
import { Panel } from '../ui'

// Only real capabilities -- no "Add Rule"/"Export Report", which have no
// backing endpoint and would be fabricated.
export function QuickActionsPanel() {
  const { incidents } = useIncidentsSnapshot()
  const navigate = useNavigate()

  function handleRunAnalysis() {
    const target = selectMostActionableIncident(incidents)
    navigate(target ? `/incidents/${target.id}` : '/incidents')
  }

  return (
    <Panel title="Quick Actions" accent="cyan">
      <div className="flex flex-col gap-3">
        <LogUploadControl />

        <button
          type="button"
          onClick={handleRunAnalysis}
          className="rounded border border-accent-purple bg-accent-purple/10 px-3 py-2 text-xs font-semibold tracking-widest text-accent-purple uppercase"
        >
          Run AI Analysis
        </button>

        <Link
          to="/demo"
          className="rounded border border-accent-green bg-accent-green/10 px-3 py-2 text-center text-xs font-semibold tracking-widest text-accent-green uppercase"
        >
          Open Demo Mode
        </Link>
      </div>
    </Panel>
  )
}

import { HeatmapGrid } from '../components/mitre/HeatmapGrid'
import { ErrorState, LoadingState } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'

function HeatmapPage() {
  const { incidents, loading: incidentsLoading, error: incidentsError, refresh } = useIncidentsSnapshot()
  const { byId, loading: catalogLoading, error: catalogError } = useMitreCatalog()

  const loading = incidentsLoading || catalogLoading
  const error = incidentsError ?? catalogError

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">MITRE ATT&amp;CK Heatmap</h1>
        <p className="mt-1 text-sm text-text-muted">
          Real technique coverage -- only techniques actually observed in ingested incidents, never the full catalog.
        </p>
      </div>

      {loading && <LoadingState label="Loading heatmap" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}
      {!loading && !error && <HeatmapGrid incidents={incidents} techniqueById={byId} />}
    </div>
  )
}

export default HeatmapPage

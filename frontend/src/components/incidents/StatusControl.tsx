import { useState } from 'react'
import { ApiError, updateIncidentStatus, type IncidentStatus } from '../../api'
import { StatusPill } from '../ui'

const STATUS_ORDER: IncidentStatus[] = ['open', 'investigating', 'resolved', 'closed']

const STATUS_TONE: Record<IncidentStatus, 'good' | 'bad' | 'warn' | 'neutral'> = {
  open: 'bad',
  investigating: 'warn',
  resolved: 'good',
  closed: 'neutral',
}

interface StatusControlProps {
  incidentId: number
  currentStatus: IncidentStatus
  onChanged: () => void
}

export function StatusControl({ incidentId, currentStatus, onChanged }: StatusControlProps) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleChange(status: IncidentStatus) {
    if (status === currentStatus || pending) return
    setPending(true)
    setError(null)
    try {
      await updateIncidentStatus(incidentId, { status })
      onChanged()
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Failed to update status')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <StatusPill tone={STATUS_TONE[currentStatus]} label={currentStatus.toUpperCase()} />
      <div className="flex flex-wrap gap-2">
        {STATUS_ORDER.filter((status) => status !== currentStatus).map((status) => (
          <button
            key={status}
            type="button"
            disabled={pending}
            onClick={() => handleChange(status)}
            className="rounded border border-border px-2 py-1 text-xs tracking-wide text-text-muted uppercase hover:border-accent-cyan hover:text-accent-cyan disabled:opacity-50"
          >
            Mark {status}
          </button>
        ))}
      </div>
      {error && <span className="text-xs text-accent-red">{error}</span>}
    </div>
  )
}

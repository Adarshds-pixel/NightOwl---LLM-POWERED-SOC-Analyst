import { useState } from 'react'
import { ApiError, updateIncidentStatus, type IncidentStatus } from '../../api'
import { useToast } from '../../context/toast/useToast'
import { Button, StatusBadge } from '../ui'

const STATUS_ORDER: IncidentStatus[] = ['open', 'investigating', 'resolved', 'closed']

/**
 * Incident status transitions (PATCH /incidents/{id}/status). Every change
 * is written to the backend audit log with an actor, so the trail below the
 * incident reflects exactly what happened here.
 */
export function StatusControl({
  incidentId,
  currentStatus,
  onChanged,
}: {
  incidentId: number
  currentStatus: IncidentStatus
  onChanged: () => void
}) {
  const [pending, setPending] = useState<IncidentStatus | null>(null)
  const { push } = useToast()

  async function handleChange(status: IncidentStatus) {
    if (status === currentStatus || pending) return
    setPending(status)
    try {
      await updateIncidentStatus(incidentId, { status, actor: 'analyst' })
      push({ tone: 'success', title: `Incident marked ${status}` })
      onChanged()
    } catch (err) {
      push({
        tone: 'error',
        title: 'Status update failed',
        description: err instanceof ApiError ? err.detail : 'Unknown error',
      })
    } finally {
      setPending(null)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <StatusBadge status={currentStatus} />
      <span className="text-micro text-text-faint">Move to</span>
      {STATUS_ORDER.filter((status) => status !== currentStatus).map((status) => (
        <Button
          key={status}
          size="sm"
          variant={status === 'resolved' ? 'primary' : 'secondary'}
          disabled={pending !== null}
          onClick={() => handleChange(status)}
        >
          {pending === status ? 'Saving...' : status}
        </Button>
      ))}
    </div>
  )
}

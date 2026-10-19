import type { IngestState } from '../context/ingest/IngestContext'

/**
 * The one progress wording for an upload, shared by the upload buttons and
 * the header pill. Real transfer percentage while uploading; once the
 * transfer is done, the server's own record count and ETA -- never a
 * fabricated percentage for a phase with no progress signal.
 */
export function ingestProgressLabel(state: Pick<IngestState, 'phase' | 'progress' | 'recordsRead' | 'job'>): string | null {
  const { phase, progress, recordsRead, job } = state
  if (phase === 'uploading') return `Uploading... ${Math.round(progress * 100)}%`
  if (phase !== 'processing') return null
  if (job?.status === 'analysing') return 'Analysing events...'
  if (recordsRead > 0) return readingLabel(recordsRead, job?.records_total ?? null, job?.eta_seconds ?? null)
  return 'Processing...'
}

function formatEta(seconds: number): string {
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))}s`
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
}

/** "Reading 12,000 of 48,125 records (25%) - about 1m 20s left" */
function readingLabel(read: number, total: number | null, eta: number | null): string {
  if (!total || total < read) return `Reading... ${read.toLocaleString()} records`
  const pct = Math.min(99, Math.round((read / total) * 100))
  const left = eta !== null ? ` - about ${formatEta(eta)} left` : ''
  return `Reading ${read.toLocaleString()} of ${total.toLocaleString()} records (${pct}%)${left}`
}

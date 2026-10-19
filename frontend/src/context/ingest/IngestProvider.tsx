import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { ApiError, ingestEvtxFileWithProgress, type IngestJobStatus, type IngestResponse } from '../../api'
import { invalidateRulesCache } from '../../hooks/useRules'
import { computeVerdict } from '../../lib/verdict'
import { useIncidentsSnapshot } from '../incidents/useIncidentsSnapshot'
import type { Toast, ToastTone } from '../toast/ToastContext'
import { useToast } from '../toast/useToast'
import { IngestContext, type IngestPhase } from './IngestContext'

/**
 * The EVTX upload, held above the router. It used to live inside each
 * page's upload button, so leaving the page mid-upload threw away the
 * progress and the result toast while the transfer and the server job
 * carried on unseen -- it looked cancelled. Here it survives navigation:
 * every upload button and the header pill read the same state, and the
 * result is reported on whichever page is open when it finishes.
 */
export function IngestProvider({ children }: { children: ReactNode }) {
  const { refresh } = useIncidentsSnapshot()
  const { push } = useToast()
  const [pending, setPending] = useState(false)
  const [phase, setPhase] = useState<IngestPhase>('idle')
  const [filename, setFilename] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)
  const [recordsRead, setRecordsRead] = useState(0)
  const [job, setJob] = useState<IngestJobStatus | null>(null)
  const [result, setResult] = useState<IngestResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const upload = useCallback(
    async (file: File) => {
      setPending(true)
      setPhase('uploading')
      setFilename(file.name)
      setProgress(0)
      setRecordsRead(0)
      setJob(null)
      setError(null)
      try {
        const res = await ingestEvtxFileWithProgress(file, (fraction) => {
          setProgress(fraction)
          // The transfer hitting 100% doesn't mean the request is done --
          // the server still has to parse/normalize/detect, reported
          // through the job status below rather than a frozen 100% bar.
          if (fraction >= 1) setPhase('processing')
        }, (status) => {
          setRecordsRead(status.records_read)
          setJob(status)
        })
        setResult(res)
        setPhase('done')
        // An ingest changes both the incident snapshot and the per-rule match
        // counts, so the session-cached rule set has to be dropped too --
        // otherwise the Rules page would keep showing pre-ingest counts.
        invalidateRulesCache()
        refresh()
        push(resultToast(res))
        return res
      } catch (err) {
        const message = err instanceof ApiError ? err.detail : 'Failed to ingest file'
        setError(message)
        setPhase('idle')
        push({ tone: 'error', title: 'Ingest failed', description: message })
        return null
      } finally {
        setPending(false)
      }
    },
    [refresh, push],
  )

  // Moving between pages keeps the upload; closing or reloading the tab
  // would stop the transfer and lose track of the job, so the browser asks.
  useEffect(() => {
    if (!pending) return
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [pending])

  const value = useMemo(
    () => ({ pending, phase, filename, progress, recordsRead, job, result, error, upload }),
    [pending, phase, filename, progress, recordsRead, job, result, error, upload],
  )

  return <IngestContext.Provider value={value}>{children}</IngestContext.Provider>
}

function resultToast(result: IngestResponse): Omit<Toast, 'id'> {
  // A file (or a re-export overlapping an earlier upload) NightOwl has
  // already ingested: every record matched an existing event by its own
  // (host, channel, Windows EventRecordID) identity, so nothing new was
  // stored -- no alert/coverage tone applies, since nothing was evaluated.
  if (result.events_ingested === 0 && result.duplicate_events_skipped > 0) {
    return {
      tone: 'info',
      title: 'Already ingested',
      description: `All ${result.duplicate_events_skipped.toLocaleString()} event(s) in ${result.filename} were already in NightOwl — nothing new to add.`,
    }
  }

  // Same verdict-kind split TelemetryProfilePanel's banner shows
  // (lib/verdict.ts) -- one shared source of truth for "which category
  // applies". "0 alerts" does NOT mean verified clean (an Inconclusive file
  // must never read as success), so the tone only says success for a
  // genuinely fully-evaluated, clean file. A real detection stays a warning
  // even when other events in the same file were never checked.
  const verdict = computeVerdict(result)
  const isDetected = verdict.kind === 'detected' || verdict.kind === 'detected_with_uncovered'
  const tone: ToastTone = isDetected
    ? 'warning'
    : verdict.kind === 'review' || verdict.kind === 'empty'
      ? 'info'
      : 'success'
  const duplicateNote =
    result.duplicate_events_skipped > 0
      ? ` (${result.duplicate_events_skipped.toLocaleString()} already ingested, skipped)`
      : ''
  const description = isDetected
    ? `${result.alerts_created} alert(s), ${result.incident_ids.length} incident(s) from ${result.filename}${duplicateNote}` +
      (verdict.kind === 'detected_with_uncovered'
        ? ` — ${result.uncovered_events} other event(s) not checked by any rule`
        : '')
    : `${verdict.label}: ${verdict.explanation}${duplicateNote}`
  const anomalyNote =
    result.ml_anomalies > 0 ? ` · ${result.ml_anomalies} ML anomaly record(s) (experimental, not detections)` : ''
  return {
    tone,
    title: `${result.events_ingested.toLocaleString()} events ingested`,
    description: description + anomalyNote,
  }
}

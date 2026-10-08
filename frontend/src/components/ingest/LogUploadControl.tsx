import { Upload } from 'lucide-react'
import { useEffect, useRef, type ChangeEvent } from 'react'
import type { IngestResponse } from '../../api'
import { useToast } from '../../context/toast/useToast'
import { useLogIngest } from '../../hooks/useLogIngest'
import { computeVerdict } from '../../lib/verdict'
import { Button } from '../ui'

/**
 * EVTX upload. The button is the whole control: the file input stays
 * hidden, and the result is reported through the global toast system
 * instead of a line of text under the button, so it reads the same
 * wherever the control is placed (header, logs page, demo page).
 */
export function LogUploadControl({
  onSuccess,
  variant = 'secondary',
  label = 'Upload logs',
}: {
  onSuccess?: (res: IngestResponse) => void
  variant?: 'primary' | 'secondary' | 'ghost'
  label?: string
}) {
  const { pending, phase, progress, recordsRead, result, error, upload } = useLogIngest()
  const inputRef = useRef<HTMLInputElement>(null)
  const { push } = useToast()
  const reported = useRef<IngestResponse | null>(null)

  useEffect(() => {
    if (result && reported.current !== result) {
      reported.current = result

      // A file (or a re-export overlapping an earlier upload) NightOwl has
      // already ingested: every record matched an existing event by its
      // own (host, channel, Windows EventRecordID) identity, so nothing
      // new was stored -- no alert/coverage tone applies, since nothing
      // was actually evaluated this time.
      if (result.events_ingested === 0 && result.duplicate_events_skipped > 0) {
        push({
          tone: 'info',
          title: 'Already ingested',
          description: `All ${result.duplicate_events_skipped.toLocaleString()} event(s) in ${result.filename} were already in NightOwl — nothing new to add.`,
        })
        return
      }

      // Same verdict-kind split TelemetryProfilePanel's banner shows
      // (lib/verdict.ts) -- one shared source of truth for "which category
      // applies," not a second, independently-drifting tone ternary. "0
      // alerts" here does NOT mean verified clean (an Inconclusive file
      // must never read as success), so the tone only ever says success
      // for a genuinely fully-evaluated, clean file. A real detection
      // stays a warning even when other events in the same file were
      // never checked (detected_with_uncovered) -- the match is still real.
      const verdict = computeVerdict(result)
      const isDetected = verdict.kind === 'detected' || verdict.kind === 'detected_with_uncovered'
      const tone = isDetected ? 'warning' : verdict.kind === 'review' || verdict.kind === 'empty' ? 'info' : 'success'
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
        result.ml_anomalies > 0
          ? ` · ${result.ml_anomalies} ML anomaly record(s) (experimental, not detections)`
          : ''
      push({
        tone,
        title: `${result.events_ingested.toLocaleString()} events ingested`,
        description: description + anomalyNote,
      })
    }
  }, [result, push])

  useEffect(() => {
    if (error) push({ tone: 'error', title: 'Ingest failed', description: error })
  }, [error, push])

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    const response = await upload(file)
    if (response) onSuccess?.(response)
  }

  // Real transfer percentage while uploading; a distinct label once the
  // transfer itself is done and the server is parsing/detecting -- never a
  // fabricated percentage for that phase, since there's no progress signal
  // for it (see client.ts's ingestEvtxFileWithProgress docstring).
  const buttonLabel =
    phase === 'uploading'
      ? `Uploading... ${Math.round(progress * 100)}%`
      : phase === 'processing'
        ? recordsRead > 0
          ? `Reading... ${recordsRead.toLocaleString()} records`
          : 'Processing...'
        : label

  return (
    <>
      <input ref={inputRef} type="file" accept=".evtx" onChange={handleFileChange} className="hidden" aria-hidden />
      <Button
        variant={variant}
        onClick={() => inputRef.current?.click()}
        disabled={pending}
        icon={<Upload className="h-3.5 w-3.5" />}
      >
        {buttonLabel}
      </Button>
    </>
  )
}

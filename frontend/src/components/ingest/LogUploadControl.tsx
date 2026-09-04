import { Upload } from 'lucide-react'
import { useEffect, useRef, type ChangeEvent } from 'react'
import type { IngestResponse } from '../../api'
import { useToast } from '../../context/toast/useToast'
import { useLogIngest } from '../../hooks/useLogIngest'
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
  const { pending, phase, progress, result, error, upload } = useLogIngest()
  const inputRef = useRef<HTMLInputElement>(null)
  const { push } = useToast()
  const reported = useRef<IngestResponse | null>(null)

  useEffect(() => {
    if (result && reported.current !== result) {
      reported.current = result
      // Three distinct outcomes, not two: a real detection (warning), a
      // file with events no loaded rule could evaluate (info -- "0 alerts"
      // here does NOT mean verified clean, so this must never read as
      // success), and a file every event of which was actually evaluated
      // with nothing found (success, the only case that word is honest).
      const tone = result.alerts_created > 0 ? 'warning' : result.uncovered_events > 0 ? 'info' : 'success'
      const description =
        result.alerts_created > 0
          ? `${result.alerts_created} alert(s), ${result.incident_ids.length} incident(s) from ${result.filename}`
          : result.uncovered_events > 0
            ? `${result.covered_events}/${result.events_ingested} events had rule coverage — ${result.uncovered_events} not evaluated by any loaded rule`
            : `All ${result.events_ingested.toLocaleString()} events were evaluated against loaded rules — no matches`
      push({
        tone,
        title: `${result.events_ingested.toLocaleString()} events ingested`,
        description,
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
    phase === 'uploading' ? `Uploading... ${Math.round(progress * 100)}%` : phase === 'processing' ? 'Processing...' : label

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

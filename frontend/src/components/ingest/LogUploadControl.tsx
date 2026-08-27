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
  const { pending, result, error, upload } = useLogIngest()
  const inputRef = useRef<HTMLInputElement>(null)
  const { push } = useToast()
  const reported = useRef<IngestResponse | null>(null)

  useEffect(() => {
    if (result && reported.current !== result) {
      reported.current = result
      push({
        tone: result.alerts_created > 0 ? 'warning' : 'success',
        title: `${result.events_ingested.toLocaleString()} events ingested`,
        description: `${result.alerts_created} alert(s), ${result.incident_ids.length} incident(s) from ${result.filename}`,
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

  return (
    <>
      <input ref={inputRef} type="file" accept=".evtx" onChange={handleFileChange} className="hidden" aria-hidden />
      <Button
        variant={variant}
        onClick={() => inputRef.current?.click()}
        disabled={pending}
        icon={<Upload className="h-3.5 w-3.5" />}
      >
        {pending ? 'Uploading...' : label}
      </Button>
    </>
  )
}

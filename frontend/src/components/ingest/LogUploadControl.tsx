import { Upload } from 'lucide-react'
import { useEffect, useRef, type ChangeEvent } from 'react'
import type { IngestResponse } from '../../api'
import { useIngest } from '../../context/ingest/useIngest'
import { ingestProgressLabel } from '../../lib/ingestProgress'
import { Button } from '../ui'

/**
 * EVTX upload. The button is the whole control: the file input stays
 * hidden, and the upload itself lives in IngestProvider, so it keeps
 * running when the page that started it is left. Every page's button shows
 * the same live progress, and the result is reported through the global
 * toast system by the provider, wherever the user is when it finishes.
 */
export function LogUploadControl({
  onSuccess,
  variant = 'secondary',
  label = 'Upload logs',
}: {
  /** Called when an upload finishes while this page is open. */
  onSuccess?: (res: IngestResponse) => void
  variant?: 'primary' | 'secondary' | 'ghost'
  label?: string
}) {
  const ingest = useIngest()
  const { pending, result, upload } = ingest
  const inputRef = useRef<HTMLInputElement>(null)
  // The result already there when this page opened belongs to an earlier
  // visit; only a completion seen while mounted is passed to onSuccess.
  const seen = useRef<IngestResponse | null>(result)
  const onSuccessRef = useRef(onSuccess)

  useEffect(() => {
    onSuccessRef.current = onSuccess
  }, [onSuccess])

  useEffect(() => {
    if (result && seen.current !== result) {
      seen.current = result
      onSuccessRef.current?.(result)
    }
  }, [result])

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    void upload(file)
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
        {ingestProgressLabel(ingest) ?? label}
      </Button>
    </>
  )
}

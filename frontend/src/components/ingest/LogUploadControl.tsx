import { useRef, type ChangeEvent } from 'react'
import type { IngestResponse } from '../../api'
import { useLogIngest } from '../../hooks/useLogIngest'

interface LogUploadControlProps {
  onSuccess?: (res: IngestResponse) => void
}

export function LogUploadControl({ onSuccess }: LogUploadControlProps) {
  const { pending, result, error, upload } = useLogIngest()
  const inputRef = useRef<HTMLInputElement>(null)

  async function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const res = await upload(file)
    if (res) onSuccess?.(res)
  }

  return (
    <div className="flex flex-col gap-1">
      <input ref={inputRef} type="file" accept=".evtx" onChange={handleFileChange} className="hidden" />
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        disabled={pending}
        className="rounded border border-accent-cyan bg-accent-cyan/10 px-3 py-2 text-xs font-semibold tracking-widest text-accent-cyan uppercase disabled:opacity-50"
      >
        {pending ? 'Uploading...' : 'Upload Logs'}
      </button>
      {result && (
        <span className="text-xs text-accent-green">
          {result.events_ingested} events, {result.alerts_created} alert(s), {result.incident_ids.length} incident(s)
        </span>
      )}
      {error && <span className="text-xs text-accent-red">{error}</span>}
    </div>
  )
}

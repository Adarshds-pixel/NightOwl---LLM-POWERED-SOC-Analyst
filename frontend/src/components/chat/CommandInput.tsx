import { SendHorizontal } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Button } from '../ui'

/**
 * The prompt box used by both the incident chat panel and the assistant
 * page. Enter sends, Shift+Enter adds a newline, and the control disables
 * itself while a request is in flight so a question cannot be double-sent.
 */
export function CommandInput({
  onSubmit,
  disabled,
  placeholder = 'Ask about incidents, threats, techniques, or request analysis...',
  note,
}: {
  onSubmit: (message: string) => void
  disabled?: boolean
  placeholder?: string
  note?: string
}) {
  const [draft, setDraft] = useState('')

  function submit(event: FormEvent) {
    event.preventDefault()
    const trimmed = draft.trim()
    if (!trimmed || disabled) return
    onSubmit(trimmed)
    setDraft('')
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-1.5">
      <div className="flex items-end gap-2 rounded-card border border-line bg-surface-2/50 px-3 py-2 focus-within:border-accent-violet/45">
        <textarea
          value={draft}
          rows={1}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault()
              submit(event)
            }
          }}
          placeholder={placeholder}
          disabled={disabled}
          aria-label={placeholder}
          className="max-h-32 min-h-8 w-full resize-none bg-transparent py-1 text-body text-text placeholder:text-text-faint focus:outline-none disabled:opacity-60"
        />
        <Button
          type="submit"
          variant="primary"
          size="sm"
          disabled={disabled || draft.trim().length === 0}
          aria-label="Send message"
        >
          <SendHorizontal className="h-3.5 w-3.5" />
        </Button>
      </div>
      {note && <p className="text-center text-micro text-text-faint">{note}</p>}
    </form>
  )
}

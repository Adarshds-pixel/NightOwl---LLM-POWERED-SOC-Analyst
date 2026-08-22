export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-start gap-2 py-8 text-sm">
      <span className="text-accent-red">{message}</span>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="rounded border border-accent-red px-2 py-1 text-xs tracking-widest text-accent-red uppercase hover:bg-accent-red/10"
        >
          Retry
        </button>
      )}
    </div>
  )
}

export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-8 text-xs tracking-widest text-text-muted uppercase">
      <span className="h-2 w-2 animate-pulse rounded-full bg-accent-cyan" />
      <span className="animate-pulse">{label}...</span>
    </div>
  )
}

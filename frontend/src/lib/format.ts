export function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  const now = Date.now()
  const diffSeconds = Math.round((now - then) / 1000)

  if (diffSeconds < 5) return 'just now'
  if (diffSeconds < 60) return `${diffSeconds}s ago`
  const diffMinutes = Math.round(diffSeconds / 60)
  if (diffMinutes < 60) return `${diffMinutes}m ago`
  const diffHours = Math.round(diffMinutes / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.round(diffHours / 24)
  return `${diffDays}d ago`
}

export function formatPercent(value: number, digits = 0): string {
  return `${value.toFixed(digits)}%`
}

export function formatSessionDuration(startedAt: number): string {
  const totalSeconds = Math.floor((Date.now() - startedAt) / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  return `${hours}h ${minutes}m ${seconds}s`
}

export function formatClock(date: Date): string {
  return date.toLocaleTimeString('en-US', { hour12: false })
}

export function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
}

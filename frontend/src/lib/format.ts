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

export function formatDateTime(iso: string): string {
  const date = new Date(iso)
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function formatTimeOfDay(iso: string): string {
  return new Date(iso).toLocaleTimeString('en-US', { hour12: false })
}

export function formatShortDate(date: Date): string {
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

/** Compact counts for KPI cards: 4 -> "4", 1240 -> "1,240", 2847392 -> "2.85M".
 *  Keeps a metric readable at 32px without the card having to reflow. */
export function formatCount(value: number): string {
  if (Math.abs(value) >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`
  if (Math.abs(value) >= 100_000) return `${(value / 1_000).toFixed(0)}K`
  return value.toLocaleString()
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

/** Milliseconds -> "1.2s" / "820ms", for latency readouts. */
export function formatLatency(ms: number | null): string {
  if (ms === null) return '--'
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`
}

/** Elapsed time between two ISO timestamps, e.g. "12m 34s" -- used for
 *  incident duration readouts where a relative "2h ago" isn't the point. */
export function formatDuration(fromIso: string, toIso?: string): string {
  const from = new Date(fromIso).getTime()
  const to = toIso ? new Date(toIso).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((to - from) / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ${minutes % 60}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

/** Incident id -> the display id analysts read out loud ("INC-0042").
 *  Purely a presentation concern: the API's numeric id is what every
 *  request uses, so this never leaves the UI layer. */
export function incidentRef(id: number): string {
  return `INC-${String(id).padStart(4, '0')}`
}

export function alertRef(id: number): string {
  return `ALT-${String(id).padStart(5, '0')}`
}

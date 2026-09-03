import clsx from 'clsx'
import { Crosshair, CornerDownLeft, ScrollText, ShieldAlert, SlidersHorizontal, Compass } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getEvents, type EventLogRow } from '../../api'
import { useIncidentsSnapshot } from '../../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../../context/mitre/useMitreCatalog'
import { useRules } from '../../hooks/useRules'
import { formatDateTime, incidentRef } from '../../lib/format'
import { NAV_ENTRIES } from '../../lib/navigation'
import { Modal, SeverityBadge } from '../ui'

/**
 * Global search (Cmd/Ctrl+K). Searches everything the app can actually
 * reach: incidents and MITRE techniques from the caches already in memory,
 * detection rules from GET /rules, raw events through the server-side q=
 * parameter, plus the navigation itself.
 *
 * Local sources are matched instantly; the event lookup is debounced
 * because it is a real request.
 */

interface Result {
  id: string
  group: 'Navigation' | 'Incidents' | 'Techniques' | 'Rules' | 'Events'
  title: string
  meta?: string
  badge?: React.ReactNode
  to: string
}

const GROUP_ICON = {
  Navigation: Compass,
  Incidents: ShieldAlert,
  Techniques: Crosshair,
  Rules: SlidersHorizontal,
  Events: ScrollText,
} as const

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [events, setEvents] = useState<EventLogRow[]>([])
  const [activeIndex, setActiveIndex] = useState(0)
  const { incidents } = useIncidentsSnapshot()
  const { techniques } = useMitreCatalog()
  const { rules } = useRules()
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setQuery('')
      setEvents([])
      setActiveIndex(0)
      window.setTimeout(() => inputRef.current?.focus(), 20)
    }
  }, [open])

  // Debounced server-side event search -- the only source that is not
  // already in memory.
  useEffect(() => {
    if (!open || query.trim().length < 3) {
      setEvents([])
      return
    }
    let cancelled = false
    const timer = window.setTimeout(() => {
      getEvents({ q: query.trim(), limit: 5 })
        .then((response) => {
          if (!cancelled) setEvents(response.events)
        })
        .catch(() => {
          if (!cancelled) setEvents([])
        })
    }, 250)

    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [query, open])

  const results = useMemo<Result[]>(() => {
    const term = query.trim().toLowerCase()

    const nav: Result[] = NAV_ENTRIES.filter(
      (entry) =>
        term.length === 0 ||
        entry.label.toLowerCase().includes(term) ||
        entry.keywords?.some((keyword) => keyword.includes(term)),
    )
      .slice(0, term ? 4 : 6)
      .map((entry) => ({ id: `nav-${entry.to}`, group: 'Navigation', title: entry.label, meta: entry.subtitle, to: entry.to }))

    if (term.length === 0) return nav

    const incidentResults: Result[] = incidents
      .filter((incident) => incident.title.toLowerCase().includes(term) || incident.host.toLowerCase().includes(term) || incidentRef(incident.id).toLowerCase().includes(term))
      .slice(0, 5)
      .map((incident) => ({
        id: `incident-${incident.id}`,
        group: 'Incidents',
        title: incident.title,
        meta: `${incidentRef(incident.id)} - ${incident.host}`,
        badge: <SeverityBadge severity={incident.severity} dot={false} />,
        to: `/incidents/${incident.id}`,
      }))

    const techniqueResults: Result[] = techniques
      .filter((technique) => technique.id.toLowerCase().includes(term) || technique.name.toLowerCase().includes(term))
      .slice(0, 5)
      .map((technique) => ({
        id: `technique-${technique.id}`,
        group: 'Techniques',
        title: `${technique.id} - ${technique.name}`,
        meta: technique.tactics.join(', '),
        to: `/mitre?technique=${technique.id}`,
      }))

    const ruleResults: Result[] = rules
      .filter((rule) => rule.title.toLowerCase().includes(term) || (rule.technique_id ?? '').toLowerCase().includes(term))
      .slice(0, 5)
      .map((rule) => ({
        id: `rule-${rule.rule_id}`,
        group: 'Rules',
        title: rule.title,
        meta: `${rule.technique_id ?? 'no technique'} - ${rule.match_count} matches`,
        to: `/rules?rule=${rule.rule_id}`,
      }))

    const eventResults: Result[] = events.map((event) => ({
      id: `event-${event.id}`,
      group: 'Events',
      title: event.process ?? `Event ${event.event_id}`,
      meta: `${event.host} - ${formatDateTime(event.timestamp)}`,
      to: `/logs?event=${event.id}`,
    }))

    return [...nav, ...incidentResults, ...techniqueResults, ...ruleResults, ...eventResults]
  }, [query, incidents, techniques, rules, events])

  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  function select(result: Result | undefined) {
    if (!result) return
    navigate(result.to)
    onClose()
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActiveIndex((index) => Math.min(index + 1, results.length - 1))
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActiveIndex((index) => Math.max(index - 1, 0))
    }
    if (event.key === 'Enter') {
      event.preventDefault()
      select(results[activeIndex])
    }
  }

  let lastGroup = ''

  return (
    <Modal open={open} onClose={onClose} width="max-w-2xl">
      <div onKeyDown={onKeyDown}>
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search incidents, techniques, rules, events..."
            aria-label="Global search"
            className="h-8 w-full bg-transparent text-body text-text placeholder:text-text-faint focus:outline-none"
          />
          <kbd className="rounded border border-line px-1.5 py-0.5 font-mono text-micro text-text-faint">ESC</kbd>
        </div>

        <div className="max-h-[52vh] overflow-y-auto py-2">
          {results.length === 0 ? (
            <p className="px-4 py-8 text-center text-meta text-text-muted">No matches for {query}</p>
          ) : (
            results.map((result, index) => {
              const showGroup = result.group !== lastGroup
              lastGroup = result.group
              const Icon = GROUP_ICON[result.group]
              const active = index === activeIndex
              return (
                <div key={result.id}>
                  {showGroup && (
                    <p className="px-4 pt-3 pb-1 text-micro font-semibold tracking-[0.14em] text-text-faint uppercase">
                      {result.group}
                    </p>
                  )}
                  <button
                    type="button"
                    onMouseEnter={() => setActiveIndex(index)}
                    onClick={() => select(result)}
                    className={clsx(
                      'flex w-full items-center gap-3 px-4 py-2 text-left transition-colors',
                      active ? 'bg-accent-primary/12' : 'hover:bg-white/4',
                    )}
                  >
                    <Icon className="h-4 w-4 shrink-0 text-text-faint" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-body text-text-dim">{result.title}</span>
                      {result.meta && <span className="block truncate text-micro text-text-faint">{result.meta}</span>}
                    </span>
                    {result.badge}
                    {active && <CornerDownLeft className="h-3.5 w-3.5 shrink-0 text-text-faint" />}
                  </button>
                </div>
              )
            })
          )}
        </div>
      </div>
    </Modal>
  )
}

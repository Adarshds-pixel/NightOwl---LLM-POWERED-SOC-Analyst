import clsx from 'clsx'
import { NavLink } from 'react-router-dom'
import { RingGauge, type Accent } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { computeThreatLevel, type ThreatLevel } from '../lib/aggregations'

const NAV_ITEMS = [
  {
    to: '/',
    label: 'Dashboard',
    end: true,
    icon: (
      <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5}>
        <rect x="3" y="3" width="6" height="6" rx="1" />
        <rect x="11" y="3" width="6" height="6" rx="1" />
        <rect x="3" y="11" width="6" height="6" rx="1" />
        <rect x="11" y="11" width="6" height="6" rx="1" />
      </svg>
    ),
  },
  {
    to: '/incidents',
    label: 'Incidents',
    end: false,
    icon: (
      <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5}>
        <path d="M10 2 L18 17 H2 Z" strokeLinejoin="round" />
        <path d="M10 8 V11.5" strokeLinecap="round" />
        <circle cx="10" cy="14" r="0.75" fill="currentColor" stroke="none" />
      </svg>
    ),
  },
  {
    to: '/heatmap',
    label: 'Heatmap',
    end: false,
    icon: (
      <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5}>
        <rect x="2.5" y="2.5" width="15" height="15" rx="1" />
        <path d="M2.5 8 H17.5 M2.5 13 H17.5 M8 2.5 V17.5 M13 2.5 V17.5" />
      </svg>
    ),
  },
  // Day 17 (Pair 2) adds a 4th link here: Rules Manager.
]

// Placeholders only -- there is no accounts/login system yet (see
// docs/02_NightOwl_Handbook_Vol2_Roadmap.md "Deferred / Future Work").
// Disabled and tooltipped rather than wired to fake behavior.
const ACCOUNT_ITEMS = [
  {
    label: 'Settings',
    icon: (
      <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5}>
        <circle cx="10" cy="10" r="2.5" />
        <path
          d="M10 2.5v2M10 15.5v2M17.5 10h-2M4.5 10h-2M15.1 4.9l-1.4 1.4M6.3 13.7l-1.4 1.4M15.1 15.1l-1.4-1.4M6.3 6.3 4.9 4.9"
          strokeLinecap="round"
        />
      </svg>
    ),
  },
  {
    label: 'Logout',
    icon: (
      <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5}>
        <path d="M8 3H4.5a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1H8" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M13 6.5 16.5 10 13 13.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M7 10h9.5" strokeLinecap="round" />
      </svg>
    ),
  },
]

const THREAT_LEVEL_FILL: Record<ThreatLevel, number> = {
  NOMINAL: 15,
  LOW: 30,
  MODERATE: 55,
  ELEVATED: 80,
  CRITICAL: 100,
}

const THREAT_LEVEL_ACCENT: Record<ThreatLevel, Accent> = {
  NOMINAL: 'green',
  LOW: 'green',
  MODERATE: 'amber',
  ELEVATED: 'red',
  CRITICAL: 'red',
}

function Sidebar() {
  const { incidents } = useIncidentsSnapshot()
  const threat = computeThreatLevel(incidents)

  return (
    <aside className="flex w-56 shrink-0 flex-col overflow-y-auto border-r border-accent-cyan/30 bg-surface/80">
      <div className="px-4 py-5">
        <div className="font-display text-lg font-bold tracking-widest text-accent-cyan">NIGHTOWL</div>
        <div className="text-[10px] tracking-widest text-text-muted uppercase">AI-Powered SOC</div>
      </div>
      <nav className="flex flex-col gap-1 px-2">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2 border-l-2 px-3 py-2 text-sm font-medium tracking-wide transition-colors',
                isActive
                  ? 'border-accent-cyan bg-accent-cyan/10 text-accent-cyan'
                  : 'border-transparent text-text-muted hover:text-text',
              )
            }
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-6 flex flex-col items-center gap-2 border-t border-border px-4 py-5">
        <span className="text-[10px] tracking-widest text-text-muted uppercase">Threat Level</span>
        <RingGauge
          value={THREAT_LEVEL_FILL[threat.level]}
          label={threat.level}
          sublabel={`${threat.activeCount} active`}
          accent={THREAT_LEVEL_ACCENT[threat.level]}
          size={104}
        />
      </div>

      <div className="mt-auto flex flex-col gap-1 border-t border-border px-2 py-3">
        {ACCOUNT_ITEMS.map((item) => (
          <button
            key={item.label}
            type="button"
            disabled
            title="Coming soon -- requires a real login system"
            className="flex cursor-not-allowed items-center gap-2 rounded px-3 py-2 text-sm font-medium text-text-muted/50"
          >
            {item.icon}
            {item.label}
          </button>
        ))}
      </div>
    </aside>
  )
}

export default Sidebar

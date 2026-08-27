import clsx from 'clsx'
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { AnalystAvatar, NightOwlMark } from '../components/brand/NightOwlMark'
import { ActivityIndicator, StatusDot, Tooltip } from '../components/ui'
import { useHealth } from '../context/health/useHealth'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { computeThreatLevel } from '../lib/aggregations'
import { PRIMARY_NAV, SECONDARY_NAV, type NavEntry } from '../lib/navigation'

/**
 * The application rail: brand, primary navigation, a live system-status
 * block and the deployment identity card.
 *
 * The identity card says what is actually true -- NightOwl has no accounts,
 * sessions or roles, only an optional shared API key -- so it describes the
 * deployment rather than inventing a signed-in user with an email address
 * and an ADMIN badge.
 */
export function Sidebar({
  collapsed,
  onToggleCollapsed,
}: {
  collapsed: boolean
  onToggleCollapsed: () => void
}) {
  const { status } = useHealth()
  const { incidents } = useIncidentsSnapshot()
  const threat = computeThreatLevel(incidents)
  const healthy = status === 'healthy'
  const apiKeyConfigured = Boolean(import.meta.env.VITE_API_KEY)

  return (
    <aside
      className={clsx(
        'relative z-20 flex shrink-0 flex-col border-r border-line bg-surface/85 backdrop-blur-md transition-[width] duration-200',
        collapsed ? 'w-[68px]' : 'w-[228px]',
      )}
    >
      <span aria-hidden className="pointer-events-none absolute -top-24 -left-16 h-56 w-56 rounded-full bg-accent-blue/12 blur-3xl" />

      <div className={clsx('relative flex items-center gap-2.5 px-4 py-4', collapsed && 'justify-center px-0')}>
        <NightOwlMark size={collapsed ? 32 : 38} />
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-[15px] leading-none font-semibold tracking-[0.16em] text-text">NIGHTOWL</p>
            <p className="mt-1 text-[9px] leading-none font-medium tracking-[0.22em] text-accent-cyan uppercase">
              AI-Powered SOC
            </p>
          </div>
        )}
      </div>

      <nav className="relative flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto px-2 pt-1 pb-3" aria-label="Main">
        {PRIMARY_NAV.map((entry) => (
          <SidebarLink key={entry.to} entry={entry} collapsed={collapsed} />
        ))}
        <div className="my-2 border-t border-line-soft" />
        {SECONDARY_NAV.map((entry) => (
          <SidebarLink key={entry.to} entry={entry} collapsed={collapsed} />
        ))}
      </nav>

      <div className="relative mt-auto flex flex-col gap-2 px-2 pb-2">
        {!collapsed ? (
          <div className="rounded-card border border-line bg-surface-2/50 px-3 py-2.5">
            <p className="text-[9px] font-semibold tracking-[0.18em] text-text-faint uppercase">System status</p>
            <div className="mt-1.5 flex items-center justify-between gap-2">
              <span className="flex items-center gap-1.5 text-meta text-text-dim">
                <StatusDot tone={healthy ? 'good' : status === 'checking' ? 'idle' : 'bad'} />
                {healthy ? 'API operational' : status === 'checking' ? 'Checking...' : 'API unreachable'}
              </span>
              <ActivityIndicator accent={healthy ? 'green' : 'red'} active={healthy} />
            </div>
            <p className="mt-1 text-micro text-text-faint">
              Threat level <span className="text-text-dim">{threat.level}</span> - {threat.activeCount} active
            </p>
          </div>
        ) : (
          <Tooltip label={healthy ? 'API operational' : 'API unreachable'}>
            <span className="flex h-9 w-full items-center justify-center rounded-control border border-line bg-surface-2/50">
              <StatusDot tone={healthy ? 'good' : 'bad'} />
            </span>
          </Tooltip>
        )}

        <div
          className={clsx(
            'flex items-center gap-2.5 rounded-card border border-line bg-surface-2/50 px-3 py-2.5',
            collapsed && 'justify-center px-0',
          )}
        >
          <AnalystAvatar size={collapsed ? 30 : 36} />
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-meta font-medium text-text">Administrator</p>
              <p className="truncate text-micro tracking-[0.14em] text-accent-cyan uppercase">NightOwl SOC</p>
              <p className="mt-0.5 truncate text-micro text-text-faint">
                {apiKeyConfigured ? 'API key configured' : 'Local deployment - no auth'}
              </p>
            </div>
          )}
        </div>

        <button
          type="button"
          onClick={onToggleCollapsed}
          className={clsx(
            'flex h-9 items-center gap-2 rounded-control px-3 text-meta text-text-muted transition-colors hover:bg-white/5 hover:text-text',
            collapsed && 'justify-center px-0',
          )}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          {!collapsed && 'Collapse'}
        </button>
      </div>
    </aside>
  )
}

function SidebarLink({ entry, collapsed }: { entry: NavEntry; collapsed: boolean }) {
  const Icon = entry.icon

  const link = (
    <NavLink
      to={entry.to}
      end={entry.end}
      className={({ isActive }) =>
        clsx(
          'group relative flex h-9 items-center gap-2.5 rounded-control px-3 text-meta font-medium transition-colors duration-200',
          collapsed && 'justify-center px-0',
          isActive
            ? 'border border-accent-blue/35 bg-gradient-to-r from-accent-blue/25 to-accent-violet/10 text-text shadow-glow-blue'
            : 'border border-transparent text-text-muted hover:bg-white/5 hover:text-text-dim',
        )
      }
    >
      {({ isActive }) => (
        <>
          {isActive && !collapsed && (
            <span aria-hidden className="absolute top-1/2 left-0 h-4 w-0.5 -translate-y-1/2 rounded-full bg-accent-cyan" />
          )}
          <Icon className={clsx('h-4 w-4 shrink-0', isActive && 'text-accent-cyan')} />
          {!collapsed && <span className="truncate">{entry.label}</span>}
        </>
      )}
    </NavLink>
  )

  return collapsed ? <Tooltip label={entry.label}>{link}</Tooltip> : link
}

export default Sidebar

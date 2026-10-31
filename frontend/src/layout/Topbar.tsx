import clsx from 'clsx'
import { Bell, Bot, Clock, LogOut, Menu, Moon, Search, Settings, Sparkles, Sun, Upload } from 'lucide-react'
import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { AnalystAvatar } from '../components/brand/NightOwlMark'
import { NotificationPanel } from '../components/notifications/NotificationPanel'
import { Popover, StatusDot, Tooltip } from '../components/ui'
import { useAuth } from '../context/auth/useAuth'
import { useHealth } from '../context/health/useHealth'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useIngest } from '../context/ingest/useIngest'
import { usePreferences } from '../context/preferences/usePreferences'
import { useClock } from '../hooks/useClock'
import { useUnseenIncidents } from '../hooks/useUnseenIncidents'
import { formatShortDate } from '../lib/format'
import { ingestProgressLabel } from '../lib/ingestProgress'
import { matchNavEntry } from '../lib/navigation'

/**
 * The global header: where you are on the left, live state and global
 * actions on the right. Title and subtitle come from lib/navigation so a
 * page never has to repeat its own name.
 */
export function Topbar({ onOpenSearch, onOpenSidebar }: { onOpenSearch: () => void; onOpenSidebar: () => void }) {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { prefs, setPref } = usePreferences()
  const { status } = useHealth()
  const { incidents } = useIncidentsSnapshot()
  const { unseen, unseenCount, markAllSeen, markSeen } = useUnseenIncidents(incidents)
  const { username, logout } = useAuth()
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  const now = useClock()
  const ingest = useIngest()

  async function handleLogout() {
    if (loggingOut) return
    setLoggingOut(true)
    setProfileOpen(false)
    // logout() clears local auth state even if the backend call fails (see
    // AuthProvider), so this navigate is safe to fire unconditionally --
    // RequireAuth will bounce back to /login anyway if it somehow isn't.
    try {
      await logout()
    } finally {
      navigate('/login', { replace: true })
    }
  }

  const entry = matchNavEntry(pathname)
  const title = entry?.title ?? entry?.label ?? 'NightOwl'
  const subtitle = entry?.subtitle ?? ''
  const apiOnline = status === 'healthy'

  return (
    <header className="relative z-30 flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-line bg-gradient-to-b from-surface-2/70 to-surface/60 px-5 py-3 backdrop-blur-[var(--blur-glass-heavy)] backdrop-saturate-[1.2]">
      {/* Lit underline, brightest under the page title. */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-gradient-to-r from-accent-violet/45 via-accent-magenta/20 to-transparent"
      />
      <div className="flex min-w-0 items-center gap-3">
        <button
          type="button"
          onClick={onOpenSidebar}
          aria-label="Open navigation"
          className="flex h-9 w-9 items-center justify-center rounded-control border border-line bg-surface-2/60 text-text-dim lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>
        <div className="min-w-0">
          <h1 className="truncate text-[1.35rem] leading-tight font-semibold tracking-tight text-text">{title}</h1>
          {subtitle && <p className="truncate text-meta text-text-muted">{subtitle}</p>}
        </div>
      </div>

      <div className="flex items-center gap-2">
        {/* A running upload, visible on every page -- it keeps going while
            the analyst moves around (see IngestProvider). */}
        {ingest.pending && (
          <Link
            to="/logs"
            title={ingest.filename ?? undefined}
            className="flex max-w-[22rem] items-center gap-2 rounded-control border border-accent-violet/35 bg-accent-violet/10 px-3 py-1.5 text-meta text-text transition-colors hover:border-accent-violet/60"
          >
            <Upload className="h-3.5 w-3.5 shrink-0 animate-pulse text-accent-violet" />
            <span className="min-w-0 leading-tight">
              <span className="block truncate font-medium">{ingest.filename ?? 'Uploading'}</span>
              <span className="block truncate text-micro text-text-muted">{ingestProgressLabel(ingest)}</span>
            </span>
          </Link>
        )}

        <div className="hidden items-center gap-2.5 rounded-control border border-line bg-surface-2/50 px-3 py-1.5 md:flex">
          <Clock className="h-4 w-4 text-accent-magenta" />
          <div className="leading-tight">
            <p className="font-mono text-meta text-text tabular-nums">
              {now.toLocaleTimeString('en-US', { hour12: !prefs.clock24h })}
            </p>
            <p className="text-micro text-text-faint">{formatShortDate(now)}</p>
          </div>
        </div>

        <Link
          to="/assistant"
          className="group relative hidden items-center gap-2.5 overflow-hidden rounded-control border border-accent-violet/35 bg-gradient-to-r from-accent-violet/18 to-accent-primary/10 px-3 py-1.5 transition-all duration-200 hover:-translate-y-px hover:border-accent-violet/60 hover:shadow-glow-violet sm:flex"
        >
          <span className="relative flex h-7 w-7 items-center justify-center rounded-full bg-accent-violet/20 text-accent-violet ring-1 ring-accent-violet/30">
            {/* The AI capsule breathes while the API is reachable -- this is
                the "intelligence layer is awake" cue, not a generic badge. */}
            {apiOnline && (
              <span aria-hidden className="absolute inset-0 rounded-full bg-accent-violet/30 blur-md animate-glow-pulse" />
            )}
            <Bot className="relative h-3.5 w-3.5" />
          </span>
          <span className="leading-tight">
            <span className="block text-meta font-medium text-text">AI Assistant</span>
            <span className="flex items-center gap-1 text-micro text-text-muted">
              <StatusDot tone={apiOnline ? 'good' : 'bad'} pulse={apiOnline} />
              {apiOnline ? 'Online' : 'Offline'}
            </span>
          </span>
          <Sparkles className="h-3.5 w-3.5 text-accent-violet/70" />
        </Link>

        <Tooltip label="Search (Ctrl+K)">
          <button
            type="button"
            onClick={onOpenSearch}
            aria-label="Open global search"
            className="flex h-10 w-10 items-center justify-center rounded-control border border-line bg-surface-2/50 text-text-dim transition-colors hover:border-accent-primary/40 hover:text-text"
          >
            <Search className="h-4 w-4" />
          </button>
        </Tooltip>

        <Tooltip label={prefs.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}>
          <button
            type="button"
            onClick={() => setPref('theme', prefs.theme === 'dark' ? 'light' : 'dark')}
            aria-label={prefs.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            className="flex h-10 w-10 items-center justify-center rounded-control border border-line bg-surface-2/50 text-text-dim transition-all hover:border-accent-primary/40 hover:text-text hover:shadow-glow-primary active:scale-95"
          >
            {prefs.theme === 'dark' ? (
              <Sun className="h-4 w-4 text-accent-amber transition-transform duration-300 hover:rotate-45" />
            ) : (
              <Moon className="h-4 w-4 text-accent-violet transition-transform duration-300 hover:-rotate-12" />
            )}
          </button>
        </Tooltip>

        <div className="relative">
          <button
            type="button"
            onClick={() => setNotificationsOpen((open) => !open)}
            aria-label={`Notifications: ${unseenCount} unacknowledged`}
            aria-expanded={notificationsOpen}
            className={clsx(
              'relative flex h-10 w-10 items-center justify-center rounded-control border bg-surface-2/50 transition-colors',
              notificationsOpen ? 'border-accent-primary/50 text-text' : 'border-line text-text-dim hover:text-text',
            )}
          >
            <Bell className="h-4 w-4" />
            {unseenCount > 0 && (
              <span className="absolute -top-1.5 -right-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-accent-red px-1 font-mono text-[9px] font-bold text-white shadow-glow-red">
                {unseenCount > 99 ? '99+' : unseenCount}
              </span>
            )}
          </button>
          <Popover open={notificationsOpen} onClose={() => setNotificationsOpen(false)}>
            <NotificationPanel
              unseen={unseen}
              onMarkAllSeen={markAllSeen}
              onMarkSeen={markSeen}
              onNavigate={() => setNotificationsOpen(false)}
            />
          </Popover>
        </div>

        <div className="relative">
          <button
            type="button"
            onClick={() => setProfileOpen((open) => !open)}
            aria-label="Account menu"
            aria-expanded={profileOpen}
            className={clsx(
              'flex h-10 w-10 items-center justify-center rounded-full border p-0.5 transition-colors',
              profileOpen ? 'border-accent-primary/50' : 'border-line hover:border-accent-primary/40',
            )}
          >
            <AnalystAvatar size={34} />
          </button>
          <Popover open={profileOpen} onClose={() => setProfileOpen(false)} className="w-64">
            <div className="border-b border-line px-3.5 py-3">
              <p className="text-body font-medium text-text">{username ?? 'Admin'}</p>
              <p className="mt-0.5 text-micro text-text-faint">
                NightOwl has a single administrator account. Signing out ends this session on this device.
              </p>
            </div>
            <div className="flex items-center justify-between px-3.5 py-2 text-meta text-text-muted">
              <span>API</span>
              <span className="flex items-center gap-1.5">
                <StatusDot tone={apiOnline ? 'good' : 'bad'} pulse={false} />
                {apiOnline ? 'Reachable' : 'Unreachable'}
              </span>
            </div>
            <Link
              to="/settings"
              onClick={() => setProfileOpen(false)}
              className="flex items-center gap-2 border-t border-line px-3.5 py-2.5 text-meta text-text-dim transition-colors hover:bg-line-soft hover:text-text"
            >
              <Settings className="h-3.5 w-3.5" />
              Settings and preferences
            </Link>
            <button
              type="button"
              onClick={handleLogout}
              disabled={loggingOut}
              className="flex w-full items-center gap-2 border-t border-line px-3.5 py-2.5 text-left text-meta text-text-dim transition-colors hover:bg-accent-red/10 hover:text-accent-red disabled:opacity-60"
            >
              <LogOut className="h-3.5 w-3.5" />
              {loggingOut ? 'Signing out...' : 'Sign out'}
            </button>
          </Popover>
        </div>
      </div>
    </header>
  )
}

export default Topbar

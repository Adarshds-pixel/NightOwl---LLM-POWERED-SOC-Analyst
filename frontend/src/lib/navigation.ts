import {
  Bot,
  Crosshair,
  FileBarChart,
  Gauge,
  LayoutDashboard,
  ScrollText,
  Settings,
  ShieldAlert,
  SlidersHorizontal,
  TerminalSquare,
  type LucideIcon,
} from 'lucide-react'

/**
 * One source of truth for the app's navigation: the sidebar renders it, the
 * top bar reads the current entry for its title/subtitle, breadcrumbs and
 * the command palette search it. Adding a page means adding a row here plus
 * a <Route> in App.tsx -- nothing else hard-codes a route label.
 *
 * Deliberately absent: Threat Intel and Threat Map. Neither has (or will
 * have) a backing feature, and a nav entry that leads nowhere is worse than
 * no entry at all.
 */

export interface NavEntry {
  to: string
  label: string
  /** Header title; defaults to `label` when omitted. */
  title?: string
  subtitle: string
  icon: LucideIcon
  /** react-router NavLink `end` -- only "/" needs exact matching. */
  end?: boolean
  /** Secondary entries render below a divider in the sidebar. */
  secondary?: boolean
  /** Extra terms the command palette should match on. */
  keywords?: string[]
}

export const NAV_ENTRIES: NavEntry[] = [
  {
    to: '/',
    label: 'Overview',
    title: 'Overview',
    subtitle: 'Detections, incidents and coverage across every log ingested so far.',
    icon: LayoutDashboard,
    end: true,
    keywords: ['dashboard', 'home', 'kpi', 'summary'],
  },
  {
    to: '/incidents',
    label: 'Incidents',
    subtitle: 'Grouped detections awaiting triage and response.',
    icon: ShieldAlert,
    keywords: ['triage', 'investigation', 'cases'],
  },
  {
    to: '/assistant',
    label: 'AI Assistant',
    title: 'AI Security Assistant',
    subtitle: 'Ask questions, analyse incidents, and get AI-backed insight.',
    icon: Bot,
    keywords: ['chat', 'copilot', 'explain', 'rag', 'llm'],
  },
  {
    to: '/mitre',
    label: 'MITRE ATT&CK',
    subtitle: 'Tactic and technique coverage across observed activity.',
    icon: Crosshair,
    keywords: ['heatmap', 'matrix', 'techniques', 'tactics', 'attack'],
  },
  {
    to: '/alerts',
    label: 'Alerts',
    subtitle: 'Every rule match, newest first.',
    icon: Gauge,
    keywords: ['detections', 'matches', 'signals'],
  },
  {
    to: '/logs',
    label: 'Logs',
    subtitle: 'The full ingested event timeline, signal and noise alike.',
    icon: ScrollText,
    keywords: ['events', 'telemetry', 'sysmon', 'evtx', 'raw'],
  },
  {
    to: '/rules',
    label: 'Rules Engine',
    subtitle: 'Detection rules currently loaded and what they have caught.',
    icon: SlidersHorizontal,
    keywords: ['sigma', 'detection', 'yaml', 'signatures'],
  },
  {
    to: '/reports',
    label: 'Reports',
    subtitle: 'Generate a shareable summary of the current security posture.',
    icon: FileBarChart,
    keywords: ['export', 'pdf', 'csv', 'summary', 'posture'],
  },
  {
    to: '/settings',
    label: 'Settings',
    subtitle: 'Local preferences, connection details and system information.',
    icon: Settings,
    keywords: ['preferences', 'configuration', 'api key', 'density', 'refresh'],
  },
  {
    to: '/demo',
    label: 'Demo Mode',
    subtitle: 'Run the real ingest to detection to AI pipeline end to end.',
    icon: TerminalSquare,
    secondary: true,
    keywords: ['walkthrough', 'presentation', 'pipeline'],
  },
]

export const PRIMARY_NAV = NAV_ENTRIES.filter((entry) => !entry.secondary)
export const SECONDARY_NAV = NAV_ENTRIES.filter((entry) => entry.secondary)

/** Longest-prefix match, so /incidents/42 still resolves to Incidents. */
export function matchNavEntry(pathname: string): NavEntry | undefined {
  if (pathname === '/') return NAV_ENTRIES[0]
  return NAV_ENTRIES.filter((entry) => entry.to !== '/' && pathname.startsWith(entry.to)).sort(
    (a, b) => b.to.length - a.to.length,
  )[0]
}

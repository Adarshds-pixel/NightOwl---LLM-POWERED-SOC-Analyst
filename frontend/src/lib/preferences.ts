/**
 * Local, per-browser preferences.
 *
 * There is no user/accounts concept in NightOwl (no auth beyond a shared
 * API key), so "settings" genuinely means "this browser's preferences" --
 * they live in localStorage and nothing is ever sent to the backend. Every
 * value here is actually honoured somewhere in the UI; a preference that
 * doesn't change behaviour doesn't belong in this file.
 */

export interface Preferences {
  /** Row height / padding across tables and cards. */
  density: 'comfortable' | 'compact'
  /** Background refresh of the incidents snapshot, ms. 0 = off. */
  refreshIntervalMs: number
  /** Live Log Stream poll interval, ms. 0 = off. */
  logStreamIntervalMs: number
  /** Rows per page on the incident/alert/log/rule tables. */
  pageSize: number
  /** Ambient background glow + grid. Off gives a plain flat surface. */
  ambientBackground: boolean
  /** Opt out of non-essential animation regardless of OS setting. */
  reduceMotion: boolean
  /** Count-up animation on KPI metrics. */
  animatedCounters: boolean
  /** 24h clock in the header and tables (12h when false). */
  clock24h: boolean
}

export const DEFAULT_PREFERENCES: Preferences = {
  density: 'comfortable',
  refreshIntervalMs: 30_000,
  logStreamIntervalMs: 10_000,
  pageSize: 25,
  ambientBackground: true,
  reduceMotion: false,
  animatedCounters: true,
  clock24h: true,
}

const STORAGE_KEY = 'nightowl:preferences'

export function loadPreferences(): Preferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_PREFERENCES
    const parsed = JSON.parse(raw) as Partial<Preferences>
    // Merge over the defaults so a preference added in a later version
    // doesn't come back undefined for an existing user.
    return { ...DEFAULT_PREFERENCES, ...parsed }
  } catch {
    // Private browsing / storage disabled -- defaults are always usable.
    return DEFAULT_PREFERENCES
  }
}

export function savePreferences(prefs: Preferences): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    // Nothing to do: preferences are a convenience, not state the app needs.
  }
}

export const REFRESH_INTERVAL_OPTIONS = [
  { label: 'Off', value: 0 },
  { label: '15 seconds', value: 15_000 },
  { label: '30 seconds', value: 30_000 },
  { label: '1 minute', value: 60_000 },
  { label: '5 minutes', value: 300_000 },
]

export const LOG_INTERVAL_OPTIONS = [
  { label: 'Off', value: 0 },
  { label: '5 seconds', value: 5_000 },
  { label: '10 seconds', value: 10_000 },
  { label: '30 seconds', value: 30_000 },
]

export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100]

export const MAX_INCIDENT_PAGES = 5
export const INCIDENT_PAGE_SIZE = 200
export const MAX_INCIDENTS_FETCHED = MAX_INCIDENT_PAGES * INCIDENT_PAGE_SIZE

// The Logs page (raw event timeline, GET /events) is genuinely
// server-paginated one page at a time -- unlike Incidents' eager-fetch-up-
// to-a-cap pattern above, which tops out at 1000 and would mean 1300+
// requests at the ~65k-event scale a real capture reaches.
export const EVENT_PAGE_SIZE = 50

// Mirrors backend/app/detection/engine.py's CATEGORY_TO_EVENT_ID (the
// Sysmon event IDs this project's rules actually evaluate) plus Process
// Terminate (5), which shows up in real captures but isn't a detection
// category. Unrecognized ids fall back to "Event <id>" in the Logs table.
// Event ids are per channel (Sysmon 1 = process creation, System 1 = clock
// change), so labels are looked up by channel family, never by id alone.
export const SYSMON_EVENT_TYPE_LABELS: Record<number, string> = {
  1: 'Process Creation',
  2: 'File Time Changed',
  3: 'Network Connection',
  5: 'Process Terminated',
  6: 'Driver Loaded',
  7: 'Image Loaded',
  8: 'Remote Thread Created',
  10: 'Process Access',
  11: 'File Created',
  12: 'Registry Key Create/Delete',
  13: 'Registry Value Set',
  14: 'Registry Rename',
  17: 'Pipe Created',
  18: 'Pipe Connected',
  19: 'WMI Filter',
  20: 'WMI Consumer',
  21: 'WMI Binding',
  22: 'DNS Query',
  23: 'File Deleted',
}

export const SECURITY_EVENT_TYPE_LABELS: Record<number, string> = {
  1102: 'Audit Log Cleared',
  4624: 'Logon',
  4625: 'Failed Logon',
  4634: 'Logoff',
  4648: 'Explicit-Credential Logon',
  4656: 'Object Handle Requested',
  4661: 'SAM Object Handle',
  4662: 'Directory Object Operation',
  4663: 'Object Access',
  4672: 'Special Privileges Assigned',
  4688: 'Process Creation',
  4697: 'Service Installed',
  4698: 'Scheduled Task Created',
  4719: 'Audit Policy Changed',
  4720: 'User Account Created',
  4728: 'Member Added to Global Group',
  4732: 'Member Added to Local Group',
  4738: 'User Account Changed',
  4741: 'Computer Account Created',
  4756: 'Member Added to Universal Group',
  4768: 'Kerberos TGT Requested',
  4771: 'Kerberos Pre-auth Failed',
  4781: 'Account Renamed',
  4798: 'User Group Membership Enumerated',
  4799: 'Local Group Membership Enumerated',
  5145: 'Network Share Object Access',
  5156: 'Network Connection Allowed',
}

export const POWERSHELL_EVENT_TYPE_LABELS: Record<number, string> = {
  4103: 'PowerShell Module Logging',
  4104: 'PowerShell Script Block',
}

export const SYSTEM_EVENT_TYPE_LABELS: Record<number, string> = {
  104: 'Event Log Cleared',
  7036: 'Service State Changed',
  7040: 'Service Start Type Changed',
  7045: 'Service Installed',
}

export const APPLICATION_EVENT_TYPE_LABELS: Record<number, string> = {
  1040: 'MSI Transaction Started',
  1042: 'MSI Transaction Ended',
  18456: 'SQL Server Login Failed',
}

export const HEALTH_POLL_INTERVAL_MS = 15_000

// Demo Mode fixture pool: reworked 2026-09-08 to draw from the real
// real-world fixture corpus (backend/sample_logs/real_world_fixtures/
// detected/) instead of a small bundled set of synthetic/sliced files.
// GET /demo/fixtures (backend/app/api/routes_demo.py) returns exactly the
// fixtures the *current* rule set detects, sourced live from
// build_failure_matrix.py's own output -- see that route's docstring.
// `nextDemoFixture` below is a pure shuffle-bag picker over whatever list
// comes back, so there's no second, hand-maintained pool here to go stale
// against the real one.
import type { DemoFixtureInfo } from '../api'

const SHUFFLE_ORDER_KEY = 'nightowl:demo-fixture-shuffle-order'
const SHUFFLE_POINTER_KEY = 'nightowl:demo-fixture-shuffle-pointer'

function shuffled<T>(items: T[]): T[] {
  const copy = [...items]
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[copy[i], copy[j]] = [copy[j], copy[i]]
  }
  return copy
}

// Shuffle-bag, not round-robin-by-index -- the pool itself can change
// between clicks (a rule addition/removal changes which fixtures are
// "detected"), so persisting an index would silently point at the wrong
// fixture once the list shifts. Guarantees every fixture in the current
// pool is shown exactly once before any repeat, and the reshuffle at the
// end of a pass is nudged so the pass boundary itself never repeats the
// fixture that was just shown. Wrapped in try/catch: same defensive
// posture as hooks/useUnseenIncidents.ts's localStorage access -- a
// storage failure just means every click reshuffles, never a crash.
export function nextDemoFixture(fixtures: DemoFixtureInfo[]): DemoFixtureInfo {
  if (fixtures.length === 0) throw new Error('No detected demo fixtures available')
  if (fixtures.length === 1) return fixtures[0]

  const filenames = fixtures.map((f) => f.filename)
  let order: string[] = []
  let pointer = 0
  let lastServed: string | null = null

  try {
    const storedOrder = JSON.parse(localStorage.getItem(SHUFFLE_ORDER_KEY) ?? '[]') as string[]
    const storedPointer = Number(localStorage.getItem(SHUFFLE_POINTER_KEY) ?? '0')
    const sameSet =
      storedOrder.length === filenames.length && filenames.every((name) => storedOrder.includes(name))
    if (sameSet) {
      order = storedOrder
      pointer = storedPointer
      lastServed = pointer > 0 ? storedOrder[pointer - 1] : null
    }
  } catch {
    // Storage unavailable or corrupt -- falls back to a fresh shuffle below.
  }

  if (order.length === 0 || pointer >= order.length) {
    order = shuffled(filenames)
    // Never let a reshuffle put the just-served fixture right back at the
    // front -- that would repeat it on the very next click, which is
    // exactly what this mechanism exists to prevent.
    if (lastServed && order[0] === lastServed) {
      const swapWith = 1 + Math.floor(Math.random() * (order.length - 1))
      ;[order[0], order[swapWith]] = [order[swapWith], order[0]]
    }
    pointer = 0
  }

  const filename = order[pointer]
  pointer += 1

  try {
    localStorage.setItem(SHUFFLE_ORDER_KEY, JSON.stringify(order))
    localStorage.setItem(SHUFFLE_POINTER_KEY, String(pointer))
  } catch {
    // Sequence just will not persist across reloads.
  }

  return fixtures.find((f) => f.filename === filename) ?? fixtures[0]
}

// A fixed, visibly-scripted prompt -- Demo Mode narrates that this question
// is scripted, but the reply comes from a real POST /incidents/{id}/chat
// call, never a canned answer.
export const DEMO_CHAT_QUESTION = 'What should I do first to contain this incident?'


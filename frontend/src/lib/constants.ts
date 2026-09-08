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
export const SYSMON_EVENT_TYPE_LABELS: Record<number, string> = {
  1: 'Process Creation',
  3: 'Network Connection',
  5: 'Process Terminated',
  11: 'File Created',
  13: 'Registry Event',
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


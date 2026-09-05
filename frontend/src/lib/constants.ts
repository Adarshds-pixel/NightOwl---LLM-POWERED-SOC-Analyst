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

// Day 19 Demo Mode: every fixture below is a real EVTX file, committed
// under frontend/public/ so Vite serves it at the site root and the
// browser can fetch() it and re-upload it through the real POST /ingest
// pipeline -- no mocked ingest response.
//
// As of 2026-08-29, this is a pool of 7 real fixture files (see
// backend/scripts/build_demo_evtx_fixtures.py), each independently
// verified to trip a distinct, real subset of NightOwl's detection rules --
// useDemoMode.ts cycles through them round-robin so "Run demo" no longer
// re-uploads the exact same file every click. `full_kill_chain` is the
// unmodified original fixture (all 10 techniques it covers); 5 more are
// natural, chronologically contiguous slices of it (one attack-stage
// narrative each), not hand-picked events. The 7th, `missing_rules_...`,
// covers the 1 of 3 rules (Certutil Download) that never fired anywhere in
// the original capture and had to be generated separately (see
// backend/scripts/generate_missing_rule_events.ps1) -- 2 registry-based
// rules (Registry Run Key Persistence, Registry IFEO Debugger Hijack)
// remain uncovered by any fixture: this machine's Sysmon config, like the
// original capture VM's, has no RegistryEvent rule enabled, so EventID 13
// is never logged regardless of what registry keys get written; closing
// that gap needs an actual Sysmon config change (`sysmon -c`), not more
// fixture generation. Together these fixtures cover 13/15 rules. The
// earlier benign fixture (sysmon_demo.evtx) is kept alongside for
// reference -- see docs/05_NightOwl_Manual_Testing_Guide.md §7.2/§12.7.
export interface DemoFixture {
  url: string
  filename: string
  label: string
  techniques: string[]
}

export const DEMO_FIXTURE_POOL: DemoFixture[] = [
  {
    url: '/demo/full_kill_chain.evtx',
    filename: 'full_kill_chain.evtx',
    label: 'Full incident: multi-stage kill chain',
    techniques: ['T1059.001', 'T1105', 'T1218.005', 'T1053.005', 'T1071.001', 'T1003.001', 'T1003.002', 'T1021.001', 'T1021.002', 'T1021.006'],
  },
  {
    url: '/demo/initial_execution_encoded_powershell.evtx',
    filename: 'initial_execution_encoded_powershell.evtx',
    label: 'Initial execution: encoded PowerShell',
    techniques: ['T1059.001', 'T1105'],
  },
  {
    url: '/demo/execution_policy_bypass.evtx',
    filename: 'execution_policy_bypass.evtx',
    label: 'Execution: PowerShell policy bypass',
    techniques: ['T1059.001', 'T1105'],
  },
  {
    url: '/demo/persistence_and_lolbin_beacon.evtx',
    filename: 'persistence_and_lolbin_beacon.evtx',
    label: 'Persistence & LOLBin beacon',
    techniques: ['T1053.005', 'T1071.001', 'T1105'],
  },
  {
    url: '/demo/credential_access_mshta_lsass_sam.evtx',
    filename: 'credential_access_mshta_lsass_sam.evtx',
    label: 'Credential access: mshta → LSASS → SAM',
    techniques: ['T1218.005', 'T1003.001', 'T1003.002'],
  },
  {
    url: '/demo/lateral_movement_rdp_admin_winrm.evtx',
    filename: 'lateral_movement_rdp_admin_winrm.evtx',
    label: 'Lateral movement: RDP, admin share & WinRM',
    techniques: ['T1021.001', 'T1021.002', 'T1021.006', 'T1071.001'],
  },
  {
    url: '/demo/missing_rules_registry_certutil.evtx',
    filename: 'missing_rules_registry_certutil.evtx',
    label: 'Command and control: certutil LOLBin download',
    techniques: ['T1105'],
  },
]

const LAST_FIXTURE_INDEX_KEY = 'nightowl:last-demo-fixture-index'

// Round-robin, not random -- guarantees the very next click differs from
// the last one, rather than a 1-in-6 chance of repeating it. Persisted so
// the sequence continues across reloads instead of always restarting at
// index 0. Wrapped in try/catch: same defensive posture as
// hooks/useUnseenIncidents.ts's localStorage access.
export function nextDemoFixture(): DemoFixture {
  let last = -1
  try {
    last = Number(localStorage.getItem(LAST_FIXTURE_INDEX_KEY) ?? '-1')
  } catch {
    // Storage unavailable -- falls back to always starting from index 0.
  }
  const next = (last + 1) % DEMO_FIXTURE_POOL.length
  try {
    localStorage.setItem(LAST_FIXTURE_INDEX_KEY, String(next))
  } catch {
    // Sequence just will not persist across reloads.
  }
  return DEMO_FIXTURE_POOL[next]
}

// A fixed, visibly-scripted prompt -- Demo Mode narrates that this question
// is scripted, but the reply comes from a real POST /incidents/{id}/chat
// call, never a canned answer.
export const DEMO_CHAT_QUESTION = 'What should I do first to contain this incident?'


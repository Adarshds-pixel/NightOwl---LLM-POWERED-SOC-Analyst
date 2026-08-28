// Static build-time constant, NOT live data -- there is no rules-count
// endpoint (no backend/app/api/routes_rules.py exists yet). Mirrors the
// real count of backend/app/detection/rules/*.yml, verified 2026-08-21.
// Update this by hand if rules are added/removed; never present this
// alongside live numbers without a visible "static" label.
export const DETECTION_RULE_COUNT = 15

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

// Day 19 Demo Mode: the fixture is a real EVTX file, committed under
// frontend/public/ so Vite serves it at the site root and the browser can
// fetch() it and re-upload it through the real POST /ingest pipeline --
// no mocked ingest response.
//
// As of 2026-08-25, points at a VM-generated fixture that genuinely trips
// 12 of 15 detection rules across 10 real MITRE techniques (verified via a
// read-only dry run through the real ingestion/detection pipeline), so a
// fresh Demo Mode run creates real incidents live instead of falling back
// to a pre-existing one. The earlier benign fixture (sysmon_demo.evtx) is
// kept alongside for reference -- see docs/05_NightOwl_Manual_Testing_Guide.md
// §7.2/§12.7.
export const DEMO_FIXTURE_URL = '/demo/sysmon_malicious_demo.evtx'
export const DEMO_FIXTURE_FILENAME = 'sysmon_malicious_demo.evtx'

// A fixed, visibly-scripted prompt -- Demo Mode narrates that this question
// is scripted, but the reply comes from a real POST /incidents/{id}/chat
// call, never a canned answer.
export const DEMO_CHAT_QUESTION = 'What should I do first to contain this incident?'

// Live SOC replay (backend/app/api/routes_demo.py). The provider polls
// /demo/replay/status on this interval only while a run is "running" --
// idle time costs zero extra requests.
export const REPLAY_STATUS_POLL_MS = 2_000
export const DEFAULT_DEMO_SCENARIO_ID = 'demo_shift'

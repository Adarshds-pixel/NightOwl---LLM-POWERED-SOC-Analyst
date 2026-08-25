// Static build-time constant, NOT live data -- there is no rules-count
// endpoint (no backend/app/api/routes_rules.py exists yet). Mirrors the
// real count of backend/app/detection/rules/*.yml, verified 2026-08-21.
// Update this by hand if rules are added/removed; never present this
// alongside live numbers without a visible "static" label.
export const DETECTION_RULE_COUNT = 15

export const MAX_INCIDENT_PAGES = 5
export const INCIDENT_PAGE_SIZE = 200
export const MAX_INCIDENTS_FETCHED = MAX_INCIDENT_PAGES * INCIDENT_PAGE_SIZE

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

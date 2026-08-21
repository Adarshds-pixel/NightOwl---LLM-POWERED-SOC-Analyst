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

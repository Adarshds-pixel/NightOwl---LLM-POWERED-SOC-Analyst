// Mirrors backend/app/api/routes_incidents.py, routes_chat.py, routes_mitre.py,
// routes_ingest.py's Pydantic response models 1:1. Datetimes are `string` --
// Pydantic serializes them as ISO 8601 over JSON; callers `new Date(...)` if
// they need a Date object.

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'closed'

export interface SourceChunk {
  chunk_id: string
  document: string
  metadata: Record<string, unknown>
  score: number
}

export interface ExplainResponse {
  incident_id: number
  explanation: string
  recommended_response: string
  sources: SourceChunk[]
}

export interface IncidentSummary {
  id: number
  title: string
  status: IncidentStatus
  severity: Severity
  /** 1-5 rank `severity` was derived from (base Sigma level + tactic weight). */
  severity_score: number
  host: string
  mitre_technique_ids: string[]
  created_at: string
}

export interface IncidentListResponse {
  incidents: IncidentSummary[]
  count: number
  total: number
  limit: number
  offset: number
}

export interface TechniqueInfo {
  id: string
  name: string
  tactics: string[]
}

export interface EventInfo {
  id: number
  host: string
  timestamp: string
  event_id: number
  process: string | null
  command_line: string | null
  user: string | null
}

export interface AlertInfo {
  id: number
  rule_id: string
  matched_at: string
  severity: Severity
  severity_score: number
  event: EventInfo
}

export interface IncidentDetailResponse {
  id: number
  title: string
  status: IncidentStatus
  severity: Severity
  severity_score: number
  host: string
  created_at: string
  mitre_technique_ids: string[]
  techniques: TechniqueInfo[]
  alerts: AlertInfo[]
}

export interface IncidentStatusUpdateRequest {
  status: IncidentStatus
  actor?: string
}

export interface IncidentStatusUpdateResponse {
  id: number
  status: string
}

export interface AuditLogEntry {
  id: number
  action: string
  actor: string
  details: Record<string, unknown> | null
  created_at: string
}

export interface AuditLogResponse {
  incident_id: number
  events: AuditLogEntry[]
  count: number
}

export interface ChatMessageResponse {
  incident_id: number
  role: string
  content: string
  sources: SourceChunk[]
}

export interface ChatHistoryMessage {
  id: number
  role: string
  content: string
  created_at: string
}

export interface ChatHistoryResponse {
  incident_id: number
  messages: ChatHistoryMessage[]
  count: number
}

export interface MitreTechnique {
  id: string
  name: string
  description: string
  tactics: string[]
  is_deprecated: boolean
  is_revoked: boolean
}

export interface MitreTechniquesResponse {
  techniques: MitreTechnique[]
  count: number
}

export interface UncoveredEventGroup {
  channel: string | null
  event_id: number
  count: number
}

export interface IngestResponse {
  filename: string
  records_read: number
  events_ingested: number
  events_skipped: number
  rule_matches: number
  matched_rule_titles: string[]
  alerts_created: number
  incident_ids: number[]
  // "rule_matches === 0" alone never distinguishes "scanned, genuinely
  // clean" from "no loaded rule could evaluate this event's channel/type
  // at all" -- these three fields make that explicit. See routes_ingest.py.
  covered_events: number
  uncovered_events: number
  uncovered_breakdown: UncoveredEventGroup[]
  // Non-null only when this ingest had zero rule matches AND at least one
  // uncovered event. Advisory only -- never a detection, never conflate
  // with alerts_created/incident_ids. Poll GET /ai-opinions/{id}.
  ai_opinion_id: number | null
}

export type AiOpinionStatus = 'pending' | 'ready' | 'failed'
export type AiOpinionAssessment = 'worth_reviewing' | 'nothing_unusual' | 'uncertain'

export interface AiOpinionResponse {
  id: number
  filename: string
  created_at: string
  status: AiOpinionStatus
  assessment_label: AiOpinionAssessment | null
  summary: string | null
  sample_event_ids: number[]
  error: string | null
}

export interface EventLogRow {
  id: number
  host: string
  timestamp: string
  event_id: number
  process: string | null
  command_line: string | null
  user: string | null
  is_alert: boolean
  severity: Severity | null
  severity_score: number | null
  rule_title: string | null
  technique_id: string | null
  // Present when this event's alert was grouped into an incident, so an
  // alert row can link straight to its investigation.
  incident_id: number | null
}

export interface EventListResponse {
  events: EventLogRow[]
  count: number
  total: number
  limit: number
  offset: number
}

// --- Alerts (GET /alerts, backend/app/api/routes_alerts.py) ------------
// One row per real Alert record -- never collapsed the way an
// alert-carrying EventLogRow can be when an event trips more than one rule.
// `id` is kept meaning "the underlying Event's row id" (same field, same
// meaning as EventLogRow.id), so code that already deep-links via
// `?event=${row.id}` needs no changes; `alert_id` is this row's own,
// always-unique identity -- use it for React keys/selection.
export interface AlertRow extends EventLogRow {
  alert_id: number
}

export interface AlertListResponse {
  alerts: AlertRow[]
  count: number
  total: number
  limit: number
  offset: number
}

// --- Rules Engine (GET /rules, backend/app/api/routes_rules.py) ---------
// The detection rule set is read-only by design: rules are version-
// controlled YAML reviewed like code, so `enabled` reports "loaded and
// running", not a switch the UI can flip.
export interface RuleInfo {
  rule_id: string
  title: string
  description: string
  level: Severity | 'unknown'
  category: string | null
  technique_id: string | null
  tactics: string[]
  condition: string
  selections: string[]
  author: string
  date: string
  status: string
  references: string[]
  filename: string
  enabled: boolean
  match_count: number
  matches_24h: number
  last_triggered: string | null
}

export interface RuleListResponse {
  rules: RuleInfo[]
  count: number
  total: number
}

// --- Single raw event (GET /events/{id}) --------------------------------
// Carries raw_json, which the list endpoint deliberately omits.
export interface EventDetailResponse {
  id: number
  host: string
  timestamp: string
  event_id: number
  process: string | null
  command_line: string | null
  user: string | null
  is_alert: boolean
  severity: Severity | null
  severity_score: number | null
  rule_title: string | null
  technique_id: string | null
  incident_id: number | null
  raw: Record<string, unknown> | null
  normalized: Record<string, unknown> | null
}

// --- Demo reset (POST /demo/reset, backend/app/api/routes_demo.py) -----
export interface DemoResetResponse {
  deleted: Record<string, number>
}

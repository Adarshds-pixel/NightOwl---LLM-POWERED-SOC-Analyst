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
  event: EventInfo
}

export interface IncidentDetailResponse {
  id: number
  title: string
  status: IncidentStatus
  severity: Severity
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

export interface IngestResponse {
  filename: string
  records_read: number
  events_ingested: number
  events_skipped: number
  rule_matches: number
  matched_rule_titles: string[]
  alerts_created: number
  incident_ids: number[]
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
  rule_title: string | null
  technique_id: string | null
}

export interface EventListResponse {
  events: EventLogRow[]
  count: number
  total: number
  limit: number
  offset: number
}

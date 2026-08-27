import type {
  AuditLogResponse,
  EventDetailResponse,
  ChatHistoryResponse,
  ChatMessageResponse,
  EventListResponse,
  ExplainResponse,
  IncidentDetailResponse,
  IncidentListResponse,
  IncidentStatusUpdateRequest,
  IncidentStatusUpdateResponse,
  IngestResponse,
  MitreTechniquesResponse,
  RuleListResponse,
} from './types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'
const API_KEY = import.meta.env.VITE_API_KEY ?? ''

export class ApiError extends Error {
  status: number
  detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.status = status
    this.detail = detail
  }
}

/** Message shown for HTTP 429. Exported (rather than matched by substring)
 *  so UI code can recognise throttling exactly -- see isRateLimited. */
export const RATE_LIMIT_MESSAGE =
  'The API is throttling requests from this browser. It will accept them again shortly.'

export function isRateLimited(error: unknown): boolean {
  if (error instanceof ApiError) return error.status === 429
  return error === RATE_LIMIT_MESSAGE
}

/**
 * In-flight GET de-duplication.
 *
 * Several independent components legitimately want the same data at the same
 * moment: the command palette and the pipeline panel both want /rules, the
 * dashboard and the logs page both want the event totals, and React's
 * StrictMode runs every effect twice in development. Without this, one
 * dashboard paint spent about a dozen requests where it needed half that,
 * which is what kept tripping the backend rate limiter.
 *
 * Deliberately NOT a response cache: entries live only while the request is
 * in flight, so a refresh always hits the network and no screen can show
 * stale data. The epoch in the key is what makes that guarantee hold across
 * writes -- after an ingest or a status change, a GET issued afterwards can
 * never be answered by a request that was already in flight before it, which
 * would have returned pre-write data.
 */
const inFlight = new Map<string, Promise<unknown>>()
let mutationEpoch = 0

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  if (method !== 'GET') {
    mutationEpoch += 1
    return rawFetch<T>(path, options)
  }

  const key = `${mutationEpoch}:${path}`
  const existing = inFlight.get(key) as Promise<T> | undefined
  if (existing) return existing

  const request = rawFetch<T>(path, options).finally(() => {
    inFlight.delete(key)
  })
  inFlight.set(key, request)
  return request
}

async function rawFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const isFormData = options.body instanceof FormData
  if (!isFormData && options.body) headers.set('Content-Type', 'application/json')
  // Empty API_KEY = disabled, matching backend/app/core/auth.py's convention.
  if (API_KEY) headers.set('X-API-Key', API_KEY)

  const res = await fetch(`${API_BASE_URL}${path}`, { ...options, headers })

  if (!res.ok) {
    // 429 is a temporary, self-healing condition rather than a failure of the
    // request itself, so it gets its own wording -- "rate limit exceeded" read
    // like a bug report in the middle of an otherwise working console.
    if (res.status === 429) throw new ApiError(429, RATE_LIMIT_MESSAGE)
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new ApiError(res.status, body.detail ?? res.statusText)
  }

  return res.json() as Promise<T>
}

export function getHealth() {
  return apiFetch<{ status: string }>('/health')
}

export interface ListIncidentsParams {
  severity?: string
  status?: string
  start_date?: string
  end_date?: string
  /** Case-insensitive substring match on incident title or host. */
  q?: string
  limit?: number
  offset?: number
}

export function getIncidents(params: ListIncidentsParams = {}) {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) qs.set(key, String(value))
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : ''
  return apiFetch<IncidentListResponse>(`/incidents${suffix}`)
}

export function getIncident(id: number) {
  return apiFetch<IncidentDetailResponse>(`/incidents/${id}`)
}

export function updateIncidentStatus(id: number, payload: IncidentStatusUpdateRequest) {
  return apiFetch<IncidentStatusUpdateResponse>(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export function getIncidentAudit(id: number) {
  return apiFetch<AuditLogResponse>(`/incidents/${id}/audit`)
}

export function explainIncident(id: number) {
  return apiFetch<ExplainResponse>(`/incidents/${id}/explain`, { method: 'POST' })
}

export function getChatHistory(id: number) {
  return apiFetch<ChatHistoryResponse>(`/incidents/${id}/chat`)
}

export function postChatMessage(id: number, message: string) {
  return apiFetch<ChatMessageResponse>(`/incidents/${id}/chat`, {
    method: 'POST',
    body: JSON.stringify({ message }),
  })
}

export function getMitreTechniques() {
  return apiFetch<MitreTechniquesResponse>('/mitre/techniques')
}

export function ingestEvtxFile(file: File) {
  const form = new FormData()
  form.append('file', file)
  // No Content-Type set -- the browser adds the multipart boundary itself.
  return apiFetch<IngestResponse>('/ingest', { method: 'POST', body: form })
}

export interface ListEventsParams {
  host?: string
  start_date?: string
  end_date?: string
  alert_only?: boolean
  /** Case-insensitive substring match on process, command line, user, host. */
  q?: string
  limit?: number
  offset?: number
}

export function getEvents(params: ListEventsParams = {}) {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) qs.set(key, String(value))
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : ''
  return apiFetch<EventListResponse>(`/events${suffix}`)
}

export function getEvent(id: number) {
  return apiFetch<EventDetailResponse>(`/events/${id}`)
}

export interface ListRulesParams {
  technique_id?: string
  level?: string
  category?: string
}

export function getRules(params: ListRulesParams = {}) {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) qs.set(key, String(value))
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : ''
  return apiFetch<RuleListResponse>(`/rules${suffix}`)
}

/** Round-trip latency of a /health call, for the Pipeline Health panel.
 *  Measured client-side (performance.now around the fetch), so it includes
 *  network + server time -- which is exactly what "is the API responsive
 *  from where I am sitting" means. */
export async function pingHealth(): Promise<{ ok: boolean; latencyMs: number; throttled: boolean }> {
  const started = performance.now()
  try {
    await getHealth()
    return { ok: true, latencyMs: performance.now() - started, throttled: false }
  } catch (error) {
    // /health is exempt from the backend limiter, so a 429 here would mean a
    // proxy in front of it -- report it as throttled, never as "unreachable",
    // which would wrongly tell the analyst the backend is down.
    return { ok: false, latencyMs: performance.now() - started, throttled: isRateLimited(error) }
  }
}

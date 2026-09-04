import type {
  AiOpinionResponse,
  AlertListResponse,
  AuditLogResponse,
  DemoResetResponse,
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
  Severity,
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

// `xhr.timeout` covers the whole request lifecycle (upload transfer +
// waiting for the response), not just the transfer -- and the response
// only comes back once the server has finished parsing/normalizing/
// detecting the whole file server-side, which is the slow part. A real
// 10.5MB/29k-record sample in this project's own benchmark corpus
// (CA_PetiPotam) takes ~234s end to end (see docs/pending.md's perf
// note) -- a shorter default (90s was tried and measured too short
// against that exact file) would abort a genuinely slow-but-successful
// ingest and misreport it as failed. 5 minutes clears the known worst
// case with real margin while still catching a genuine hang.
const DEFAULT_UPLOAD_TIMEOUT_MS = 300_000

/**
 * XMLHttpRequest-based upload, not fetch(): fetch has no reliable
 * cross-browser upload-progress event, and `xhr.upload.onprogress` is the
 * only way to show real transfer percentage during a large on-spot EVTX
 * upload rather than a static "Uploading..." with no feedback for
 * however long the transfer takes. Once the transfer itself hits 100%,
 * there is nothing left to report -- server-side parse/normalize/detect
 * has no progress channel -- so `onProgress` only ever covers the upload
 * phase; callers show a distinct "Processing..." label for what happens
 * after, never a fabricated percentage for it.
 *
 * Mirrors rawFetch's error-shape conventions (429 -> RATE_LIMIT_MESSAGE,
 * non-2xx -> ApiError) so error handling doesn't diverge between the two
 * upload paths.
 *
 * A timeout here only means the *client* gave up waiting -- aborting the
 * XHR does not reliably stop the server mid-request, so a very slow
 * ingest can still complete and commit after the client has already
 * shown an error (see ontimeout's message below, and this session's
 * established "never assume a client-side timeout means the server
 * stopped" rule). Retrying blindly risks a duplicate ingest of the same
 * file; check the Incidents/Logs page for it before re-uploading.
 */
export function ingestEvtxFileWithProgress(
  file: File,
  onProgress: (fraction: number) => void,
  timeoutMs: number = DEFAULT_UPLOAD_TIMEOUT_MS,
): Promise<IngestResponse> {
  return new Promise((resolve, reject) => {
    const form = new FormData()
    form.append('file', file)

    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${API_BASE_URL}/ingest`)
    if (API_KEY) xhr.setRequestHeader('X-API-Key', API_KEY)
    xhr.timeout = timeoutMs

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total)
    }

    xhr.onload = () => {
      if (xhr.status === 429) {
        reject(new ApiError(429, RATE_LIMIT_MESSAGE))
        return
      }
      let body: unknown = null
      try {
        body = JSON.parse(xhr.responseText)
      } catch {
        // non-JSON body -- fall through to the statusText-based error below
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as IngestResponse)
        return
      }
      const detail =
        body && typeof body === 'object' && 'detail' in body
          ? String((body as { detail: unknown }).detail)
          : xhr.statusText || `upload failed with status ${xhr.status}`
      reject(new ApiError(xhr.status, detail))
    }

    xhr.onerror = () => reject(new ApiError(0, 'Network error during upload'))
    xhr.ontimeout = () =>
      reject(
        new ApiError(
          0,
          `Upload timed out after ${Math.round(timeoutMs / 1000)}s -- the server may still be processing it in ` +
            'the background even though this timed out. Check Incidents/Logs for it before re-uploading, to ' +
            'avoid ingesting the same file twice.',
        ),
      )

    xhr.send(form)
  })
}

export interface ListEventsParams {
  host?: string
  start_date?: string
  end_date?: string
  alert_only?: boolean
  /** true = event's channel/type has rule coverage (matched or not), false =
   *  no loaded rule could ever evaluate it. Never conflate with alert_only:
   *  a covered event can simply not match anything (genuinely clean). */
  covered?: boolean
  /** Only events carrying an alert of this severity. Server-side, so a
   *  filtered page's `total` is the real total for that filter. */
  severity?: Severity
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

export function getAiOpinion(id: number) {
  return apiFetch<AiOpinionResponse>(`/ai-opinions/${id}`)
}

export interface ListAlertsParams {
  host?: string
  start_date?: string
  end_date?: string
  /** Only alerts of this severity. Server-side, so a filtered page's
   *  `total` is the real total for that filter. */
  severity?: Severity
  /** Case-insensitive substring match on process, command line, user, host. */
  q?: string
  limit?: number
  offset?: number
}

/** Every real rule match, one row per Alert record -- see
 *  backend/app/api/routes_alerts.py for why this is a distinct endpoint
 *  from GET /events?alert_only=true rather than the same query reused. */
export function getAlerts(params: ListAlertsParams = {}) {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) qs.set(key, String(value))
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : ''
  return apiFetch<AlertListResponse>(`/alerts${suffix}`)
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


// --- Demo reset -------------------------------------------------------

export function resetDemoData() {
  return apiFetch<DemoResetResponse>('/demo/reset', { method: 'POST' })
}

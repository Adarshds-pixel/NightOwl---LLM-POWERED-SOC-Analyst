import type {
  AiOpinionResponse,
  AlertListResponse,
  AuditLogResponse,
  DemoFixturesResponse,
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

/**
 * Global 401 hook. `AuthProvider` registers a handler here on mount so that
 * ANY request anywhere in the app that comes back 401 (a session that has
 * expired or been invalidated server-side mid-use, not just the one request
 * that happened to notice) flips the app's auth state and sends the user
 * back to /login -- rather than each of the dozens of independent
 * data-fetching hooks in this codebase separately deciding what a 401 means.
 *
 * Deliberately NOT fired for `/auth/login` or `/auth/me`: a login attempt
 * failing with 401 is an expected, locally-handled outcome (wrong
 * password), not a "your existing session just died" event, and `/auth/me`
 * returning 401 is the normal, expected way AuthProvider itself discovers
 * "not currently logged in" on first load -- neither should trigger a
 * "session expired" toast or an extra redirect on top of what's already
 * happening.
 */
const UNAUTHORIZED_EXEMPT_PATHS = new Set(['/auth/login', '/auth/me'])
let onUnauthorized: (() => void) | null = null

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler
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

  // Required for the browser to send/receive the signed session cookie
  // (Starlette SessionMiddleware, see backend/app/main.py) -- without this,
  // every request would be treated as logged-out regardless of a real
  // session existing, since fetch omits cookies by default for
  // cross-origin requests (the dev server on :5173 calling the API on
  // :8000 counts as cross-origin even though both are localhost).
  const res = await fetch(`${API_BASE_URL}${path}`, { ...options, headers, credentials: 'include' })

  if (!res.ok) {
    // 429 is a temporary, self-healing condition rather than a failure of the
    // request itself, so it gets its own wording -- "rate limit exceeded" read
    // like a bug report in the middle of an otherwise working console.
    if (res.status === 429) throw new ApiError(429, RATE_LIMIT_MESSAGE)
    if (res.status === 401 && !UNAUTHORIZED_EXEMPT_PATHS.has(path)) onUnauthorized?.()
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
    // rawFetch sets `credentials: 'include'` for the same reason (see its
    // own comment) -- XHR has no equivalent default-include behavior, so
    // without this the session cookie is silently omitted and every
    // upload 401s as "not authenticated" regardless of a real, valid
    // session, even though every other request in the app (all fetch-based)
    // works fine. Missed when session auth was added, since this upload
    // path is a bespoke XHR implementation that never went through
    // rawFetch/apiFetch.
    xhr.withCredentials = true
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
      // Same as rawFetch: a session that expired or was invalidated mid-
      // upload should flip the app to its logged-out state, not just fail
      // this one upload while the rest of the UI still thinks it's signed in.
      if (xhr.status === 401) onUnauthorized?.()
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

export function getDemoFixtures() {
  return apiFetch<DemoFixturesResponse>('/demo/fixtures')
}

/** Downloads one real fixture's raw bytes as a Blob so the caller can wrap
 *  it in a File and re-upload it through the real POST /ingest, same as a
 *  manual upload. Not routed through apiFetch/rawFetch -- those always
 *  parse the response as JSON, which a binary EVTX file is not -- but
 *  mirrors their auth headers and credentials handling by hand. */
export async function fetchDemoFixtureBytes(filename: string): Promise<Blob> {
  const headers = new Headers()
  if (API_KEY) headers.set('X-API-Key', API_KEY)
  const res = await fetch(`${API_BASE_URL}/demo/fixtures/${encodeURIComponent(filename)}`, {
    headers,
    credentials: 'include',
  })
  if (!res.ok) {
    if (res.status === 401) onUnauthorized?.()
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new ApiError(res.status, body.detail ?? res.statusText)
  }
  return res.blob()
}

// --- Admin auth (single admin, no registration -- see
// backend/app/api/routes_auth.py) ---------------------------------------

export interface SessionResponse {
  username: string
}

/** Not routed through apiFetch's in-flight GET de-dup / mutation-epoch
 *  bookkeeping -- that machinery exists for the app's own data endpoints,
 *  and login/logout are one-shot actions, not something two components
 *  would ever race to call at once. */
export function login(username: string, password: string) {
  return rawFetch<SessionResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
}

export function logout() {
  return rawFetch<{ ok: boolean }>('/auth/logout', { method: 'POST' })
}

/** Whether a valid session currently exists -- resolves with the logged-in
 *  username, or throws a 401 ApiError if not (never fires the global
 *  onUnauthorized handler for this one path, see UNAUTHORIZED_EXEMPT_PATHS
 *  above -- this call IS how AuthProvider finds that out safely). */
export function getCurrentSession() {
  return rawFetch<SessionResponse>('/auth/me')
}

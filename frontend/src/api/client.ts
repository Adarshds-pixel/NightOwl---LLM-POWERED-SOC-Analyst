import type {
  AuditLogResponse,
  ChatHistoryResponse,
  ChatMessageResponse,
  ExplainResponse,
  IncidentDetailResponse,
  IncidentListResponse,
  IncidentStatusUpdateRequest,
  IncidentStatusUpdateResponse,
  IngestResponse,
  MitreTechniquesResponse,
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

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const isFormData = options.body instanceof FormData
  if (!isFormData && options.body) headers.set('Content-Type', 'application/json')
  // Empty API_KEY = disabled, matching backend/app/core/auth.py's convention.
  if (API_KEY) headers.set('X-API-Key', API_KEY)

  const res = await fetch(`${API_BASE_URL}${path}`, { ...options, headers })

  if (!res.ok) {
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

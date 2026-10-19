import { createContext } from 'react'
import type { IngestJobStatus, IngestResponse } from '../../api'

export type IngestPhase = 'idle' | 'uploading' | 'processing' | 'done'

export interface IngestState {
  pending: boolean
  phase: IngestPhase
  /** Name of the file being (or last) uploaded. */
  filename: string | null
  /** Transfer progress, 0-1. */
  progress: number
  recordsRead: number
  job: IngestJobStatus | null
  /** The latest finished upload of this session. */
  result: IngestResponse | null
  error: string | null
  upload: (file: File) => Promise<IngestResponse | null>
}

export const IngestContext = createContext<IngestState | null>(null)

import { createContext } from 'react'

export type HealthStatus = 'checking' | 'healthy' | 'unreachable'

export interface HealthValue {
  status: HealthStatus
  /** Round-trip time of the last successful /health call, ms. */
  latencyMs: number | null
  /** Recent latency samples, oldest first -- drives the Pipeline Health
   *  sparkline. Only successful calls are recorded. */
  samples: number[]
  lastCheckedAt: number | null
  refresh: () => void
}

export const HealthContext = createContext<HealthValue>({
  status: 'checking',
  latencyMs: null,
  samples: [],
  lastCheckedAt: null,
  refresh: () => {},
})

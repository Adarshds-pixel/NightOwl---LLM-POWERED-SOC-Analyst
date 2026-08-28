import { createContext } from 'react'
import type { ReplayState, ReplayStatusResponse, ScenarioInfo } from '../../api'

export interface ReplayValue {
  status: ReplayStatusResponse | null
  state: ReplayState
  scenarios: ScenarioInfo[]
  loading: boolean
  error: string | null
  start: (scenarioId: string) => Promise<void>
  stop: () => Promise<void>
  reset: () => Promise<void>
}

const IDLE_STATUS: ReplayStatusResponse = {
  run_id: null,
  scenario_id: null,
  scenario_title: null,
  state: 'idle',
  started_at: null,
  finished_at: null,
  duration_seconds: 0,
  window_minutes: 0,
  elapsed_seconds: 0,
  records_emitted: 0,
  records_total: 0,
  events_ingested: 0,
  alerts_created: 0,
  incident_ids: [],
  matched_rule_titles: [],
  current_segment_id: null,
  error: null,
}

export const ReplayContext = createContext<ReplayValue>({
  status: IDLE_STATUS,
  state: 'idle',
  scenarios: [],
  loading: false,
  error: null,
  start: async () => {},
  stop: async () => {},
  reset: async () => {},
})

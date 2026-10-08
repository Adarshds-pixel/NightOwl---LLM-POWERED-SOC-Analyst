import { useEffect, useState } from 'react'
import { getMlModel, type MlModelResponse } from '../api'

/** The anomaly layer's training summary and held-out results (GET /ml/model). */
export function useMlModel() {
  const [model, setModel] = useState<MlModelResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    getMlModel()
      .then((value) => {
        if (!cancelled) setModel(value)
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return { model, error }
}

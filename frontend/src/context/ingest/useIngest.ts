import { useContext } from 'react'
import { IngestContext } from './IngestContext'

export function useIngest() {
  const ctx = useContext(IngestContext)
  if (!ctx) throw new Error('useIngest must be used within IngestProvider')
  return ctx
}

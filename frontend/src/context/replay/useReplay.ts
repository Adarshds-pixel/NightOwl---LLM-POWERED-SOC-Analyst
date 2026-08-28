import { useContext } from 'react'
import { ReplayContext } from './ReplayContext'

export function useReplay() {
  return useContext(ReplayContext)
}

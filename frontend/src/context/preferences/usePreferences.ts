import { useContext } from 'react'
import { PreferencesContext } from './PreferencesContext'

export function usePreferences() {
  return useContext(PreferencesContext)
}

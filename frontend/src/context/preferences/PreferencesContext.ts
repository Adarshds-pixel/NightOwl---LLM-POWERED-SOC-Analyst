import { createContext } from 'react'
import { DEFAULT_PREFERENCES, type Preferences } from '../../lib/preferences'

export interface PreferencesValue {
  prefs: Preferences
  setPref: <K extends keyof Preferences>(key: K, value: Preferences[K]) => void
  reset: () => void
}

export const PreferencesContext = createContext<PreferencesValue>({
  prefs: DEFAULT_PREFERENCES,
  setPref: () => {},
  reset: () => {},
})

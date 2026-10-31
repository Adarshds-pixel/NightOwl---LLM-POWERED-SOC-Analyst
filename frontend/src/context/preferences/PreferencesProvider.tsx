import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  DEFAULT_PREFERENCES,
  loadPreferences,
  savePreferences,
  type Preferences,
} from '../../lib/preferences'
import { PreferencesContext } from './PreferencesContext'

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Preferences>(() => loadPreferences())

  const setPref = useCallback(<K extends keyof Preferences>(key: K, value: Preferences[K]) => {
    setPrefs((current) => {
      const next = { ...current, [key]: value }
      savePreferences(next)
      return next
    })
  }, [])

  const reset = useCallback(() => {
    setPrefs(DEFAULT_PREFERENCES)
    savePreferences(DEFAULT_PREFERENCES)
  }, [])

  // Preferences that affect global chrome are applied as data-attributes and
  // classes on <html>, so plain CSS in index.css can react to them without every
  // component subscribing to this context.
  useEffect(() => {
    const root = document.documentElement
    root.dataset.theme = prefs.theme
    root.dataset.density = prefs.density
    root.dataset.ambient = prefs.ambientBackground ? 'on' : 'off'
    root.dataset.motion = prefs.reduceMotion ? 'reduced' : 'full'
    root.classList.remove('dark', 'light')
    root.classList.add(prefs.theme)
    root.style.colorScheme = prefs.theme
  }, [prefs.theme, prefs.density, prefs.ambientBackground, prefs.reduceMotion])

  const value = useMemo(() => ({ prefs, setPref, reset }), [prefs, setPref, reset])

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}

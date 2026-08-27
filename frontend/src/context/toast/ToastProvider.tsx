import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { ToastContext, type Toast } from './ToastContext'

const AUTO_DISMISS_MS = 5000

/**
 * Transient feedback for actions that happen away from where the user is
 * looking (an ingest finishing, a status change persisting, a background
 * refresh failing). Errors that block a view still render inline as an
 * ErrorState -- a toast is never the only place a failure is reported.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const push = useCallback(
    (toast: Omit<Toast, 'id'>) => {
      const id = Date.now() + Math.random()
      setToasts((current) => [...current, { ...toast, id }])
      window.setTimeout(() => dismiss(id), AUTO_DISMISS_MS)
    },
    [dismiss],
  )

  const value = useMemo(() => ({ toasts, push, dismiss }), [toasts, push, dismiss])

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>
}

import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useToast } from '../../context/toast/useToast'
import type { ToastTone } from '../../context/toast/ToastContext'

const TONE_ICON: Record<ToastTone, typeof Info> = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  error: XCircle,
}

const TONE_CLASS: Record<ToastTone, string> = {
  info: 'text-accent-blue',
  success: 'text-accent-green',
  warning: 'text-accent-amber',
  error: 'text-accent-red',
}

export function ToastViewport() {
  const { toasts, dismiss } = useToast()

  return (
    <div className="pointer-events-none fixed right-5 bottom-5 z-50 flex w-80 flex-col gap-2" role="region" aria-label="Notifications">
      <AnimatePresence initial={false}>
        {toasts.map((toast) => {
          const Icon = TONE_ICON[toast.tone]
          return (
            <motion.div
              key={toast.id}
              layout
              initial={{ opacity: 0, y: 12, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, x: 12 }}
              transition={{ duration: 0.2 }}
              role="status"
              className="pointer-events-auto flex items-start gap-2.5 rounded-card border border-line-strong bg-surface-1 px-3.5 py-3 shadow-elevated"
            >
              <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${TONE_CLASS[toast.tone]}`} />
              <div className="min-w-0 flex-1">
                <p className="text-body font-medium text-text">{toast.title}</p>
                {toast.description && <p className="mt-0.5 text-meta text-text-muted">{toast.description}</p>}
              </div>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                aria-label="Dismiss notification"
                className="shrink-0 rounded p-0.5 text-text-faint transition-colors hover:text-text"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          )
        })}
      </AnimatePresence>
    </div>
  )
}

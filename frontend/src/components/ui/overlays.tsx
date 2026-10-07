import clsx from 'clsx'
import { X } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

/**
 * Modal and Drawer share one implementation detail set: portal to body,
 * close on Escape, close on backdrop click, restore focus to whatever was
 * focused before opening, and lock body scroll while open. Motion handles
 * the 180-220ms transitions; the reduced-motion preference collapses them
 * globally via CSS (see index.css).
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function useOverlayBehaviour(open: boolean, onClose: () => void) {
  const previouslyFocused = useRef<HTMLElement | null>(null)
  // Callers pass inline arrows; keeping the latest one in a ref means a
  // parent re-render (e.g. the 30 s incident poll) no longer tears the
  // effect down -- which used to yank focus back to the trigger behind the
  // open overlay and re-run the scroll lock.
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  useEffect(() => {
    if (!open) return
    previouslyFocused.current = document.activeElement as HTMLElement

    function topDialog(): HTMLElement | null {
      const dialogs = document.querySelectorAll<HTMLElement>('[role="dialog"]')
      return dialogs.length ? dialogs[dialogs.length - 1] : null
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onCloseRef.current()
        return
      }
      // Focus trap: Tab cycles within the open dialog instead of escaping
      // to the page behind it.
      if (event.key !== 'Tab') return
      const dialog = topDialog()
      if (!dialog) return
      const items = [...dialog.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null)
      if (items.length === 0) {
        event.preventDefault()
        return
      }
      const first = items[0]
      const last = items[items.length - 1]
      if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)

    // The app scrolls inside <main>, not <body>; lock both.
    const scrollers = [document.body, ...document.querySelectorAll<HTMLElement>('main')]
    const previousOverflow = scrollers.map((el) => el.style.overflow)
    scrollers.forEach((el) => {
      el.style.overflow = 'hidden'
    })
    // Move focus into the dialog once it has rendered.
    const focusTimer = window.setTimeout(() => topDialog()?.querySelector<HTMLElement>(FOCUSABLE)?.focus(), 0)

    return () => {
      window.clearTimeout(focusTimer)
      document.removeEventListener('keydown', onKeyDown)
      scrollers.forEach((el, i) => {
        el.style.overflow = previousOverflow[i]
      })
      previouslyFocused.current?.focus?.()
    }
  }, [open])
}

export function Modal({
  open,
  onClose,
  title,
  children,
  width = 'max-w-lg',
}: {
  open: boolean
  onClose: () => void
  title?: ReactNode
  children: ReactNode
  width?: string
}) {
  useOverlayBehaviour(open, onClose)

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-bg-deep/70 p-6 backdrop-blur-sm"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          onClick={onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label={typeof title === 'string' ? title : undefined}
            onClick={(e) => e.stopPropagation()}
            initial={{ opacity: 0, y: 8, scale: 0.99 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.99 }}
            transition={{ duration: 0.2 }}
            className={clsx('mt-[8vh] w-full rounded-card border border-line-strong bg-surface-1 shadow-elevated', width)}
          >
            {title && (
              <header className="flex items-center justify-between border-b border-line px-4 py-3">
                <h2 className="text-title font-semibold text-text">{title}</h2>
                <CloseButton onClose={onClose} />
              </header>
            )}
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  )
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = 'w-full max-w-xl',
}: {
  open: boolean
  onClose: () => void
  title?: ReactNode
  subtitle?: ReactNode
  children: ReactNode
  width?: string
}) {
  useOverlayBehaviour(open, onClose)

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex justify-end bg-bg-deep/70 backdrop-blur-sm"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          onClick={onClose}
        >
          <motion.aside
            role="dialog"
            aria-modal="true"
            aria-label={typeof title === 'string' ? title : undefined}
            onClick={(e) => e.stopPropagation()}
            initial={{ x: 24, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 24, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            className={clsx('flex h-full flex-col border-l border-line-strong bg-surface-1 shadow-elevated', width)}
          >
            <header className="flex shrink-0 items-start justify-between gap-3 border-b border-line px-5 py-4">
              <div className="min-w-0">
                {title && <h2 className="truncate text-title font-semibold text-text">{title}</h2>}
                {subtitle && <p className="mt-0.5 truncate text-meta text-text-muted">{subtitle}</p>}
              </div>
              <CloseButton onClose={onClose} />
            </header>
            <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  )
}

function CloseButton({ onClose }: { onClose: () => void }) {
  return (
    <button
      type="button"
      onClick={onClose}
      aria-label="Close"
      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-line bg-surface-2/60 text-text-muted transition-colors hover:text-text"
    >
      <X className="h-3.5 w-3.5" />
    </button>
  )
}

/** Anchored popover used by the notification panel and the profile menu.
 *  Closes on outside click and Escape; the trigger stays in the DOM flow so
 *  focus order is preserved. */
export function Popover({
  open,
  onClose,
  children,
  align = 'right',
  className,
}: {
  open: boolean
  onClose: () => void
  children: ReactNode
  align?: 'left' | 'right'
  className?: string
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function onPointerDown(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) onClose()
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open, onClose])

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          ref={ref}
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.16 }}
          className={clsx(
            'absolute top-full z-40 mt-2 rounded-card border border-line-strong bg-surface-1 shadow-elevated',
            align === 'right' ? 'right-0' : 'left-0',
            className,
          )}
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  )
}

/** CSS-only tooltip. No positioning library: every tooltip in this app is a
 *  short label on a small control, so a centred bubble above the trigger is
 *  always adequate and costs nothing at render time. */
export function Tooltip({
  label,
  children,
  side = 'top',
  className,
}: {
  label: ReactNode
  children: ReactNode
  side?: 'top' | 'bottom'
  className?: string
}) {
  return (
    <span className={clsx('group/tooltip relative inline-flex', className)}>
      {children}
      <span
        role="tooltip"
        className={clsx(
          'pointer-events-none absolute left-1/2 z-50 hidden -translate-x-1/2 rounded-md border border-line-strong bg-surface-2 px-2 py-1 text-micro whitespace-nowrap text-text-dim shadow-elevated group-hover/tooltip:block group-focus-within/tooltip:block',
          side === 'top' ? 'bottom-full mb-1.5' : 'top-full mt-1.5',
        )}
      >
        {label}
      </span>
    </span>
  )
}

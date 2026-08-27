import { createContext } from 'react'

export type ToastTone = 'info' | 'success' | 'warning' | 'error'

export interface Toast {
  id: number
  tone: ToastTone
  title: string
  description?: string
}

export interface ToastValue {
  toasts: Toast[]
  push: (toast: Omit<Toast, 'id'>) => void
  dismiss: (id: number) => void
}

export const ToastContext = createContext<ToastValue>({
  toasts: [],
  push: () => {},
  dismiss: () => {},
})

import { Component, type ErrorInfo, type ReactNode } from 'react'
import { ErrorState } from './states'

/**
 * Catches a render error in one page so it shows an error panel inside the
 * console instead of unmounting the whole app to a blank screen (19 Oct 2026
 * audit, F-10). Mounted around the routed page in AppLayout and keyed on the
 * path there, so navigating to another page clears the error.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('NightOwl page crashed', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <ErrorState
          className="py-20"
          message="This page hit an unexpected error. Other pages still work; retry, or reload if it persists."
          onRetry={() => this.setState({ error: null })}
        />
      )
    }
    return this.props.children
  }
}

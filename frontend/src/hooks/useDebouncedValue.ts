import { useEffect, useState } from 'react'

/**
 * Delays a rapidly-changing value (a search box) until it settles.
 *
 * The list pages send their search term to the API, so without this every
 * keystroke was a request: typing "powershell" cost ten of them in about two
 * seconds and was the single biggest contributor to tripping the backend
 * rate limiter. The input itself stays fully responsive -- only the value
 * the query depends on is delayed.
 */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [settled, setSettled] = useState(value)

  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delayMs)
    return () => window.clearTimeout(timer)
  }, [value, delayMs])

  return settled
}

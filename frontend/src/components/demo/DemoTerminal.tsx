import clsx from 'clsx'
import { useEffect, useRef } from 'react'
import type { DemoLogLine } from '../../hooks/useDemoMode'

/**
 * Terminal-style narration for Demo Mode. Every line is emitted by the real
 * pipeline run (ingest, detection, explain, chat) as it happens -- the
 * terminal never prints a step that did not execute.
 */
export function DemoTerminal({ log }: { log: DemoLogLine[] }) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: 'smooth' })
  }, [log.length])

  return (
    <div
      ref={ref}
      className="max-h-80 overflow-y-auto rounded-control border border-line bg-bg-deep/70 px-3 py-2.5 font-mono text-micro leading-relaxed"
    >
      {log.length === 0 ? (
        <p className="text-text-faint">Waiting to start...</p>
      ) : (
        log.map((line) => (
          <p
            key={line.id}
            className={clsx(
              'py-0.5',
              line.tone === 'error'
                ? 'text-accent-red'
                : line.tone === 'success'
                  ? 'text-accent-green'
                  : 'text-text-muted',
            )}
          >
            <span className="text-text-faint">
              {line.tone === 'error' ? '[ERROR] ' : line.tone === 'success' ? '[OK] ' : '> '}
            </span>
            {line.text}
          </p>
        ))
      )}
    </div>
  )
}

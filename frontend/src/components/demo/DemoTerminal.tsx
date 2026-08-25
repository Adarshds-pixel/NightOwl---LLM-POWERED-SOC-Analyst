import clsx from 'clsx'
import { useEffect, useRef } from 'react'
import type { DemoLogLine } from '../../hooks/useDemoMode'
import { Panel } from '../ui'

const TONE_CLASSES: Record<DemoLogLine['tone'], string> = {
  info: 'text-accent-cyan',
  success: 'text-accent-green',
  error: 'text-accent-red',
}

const TONE_PREFIX: Record<DemoLogLine['tone'], string> = {
  info: '>',
  success: '[OK]',
  error: '[ERROR]',
}

// A styled scrolling log, not a real terminal emulator -- consistent with
// the project's existing Panel/HudCorners visual language rather than a new
// widget system.
export function DemoTerminal({ log }: { log: DemoLogLine[] }) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: 'nearest' })
  }, [log.length])

  return (
    <Panel title="Demo Terminal" accent="green">
      <div className="max-h-80 overflow-y-auto font-mono text-xs leading-relaxed">
        {log.length === 0 && <span className="text-text-muted">Waiting to start...</span>}
        {log.map((line) => (
          <div key={line.id} className={clsx(TONE_CLASSES[line.tone])}>
            {TONE_PREFIX[line.tone]} {line.text}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </Panel>
  )
}

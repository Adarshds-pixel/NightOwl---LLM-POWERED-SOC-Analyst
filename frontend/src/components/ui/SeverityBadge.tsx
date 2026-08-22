import clsx from 'clsx'
import type { Severity } from '../../api'
import {
  SEVERITY_BG_SOFT_CLASSES,
  SEVERITY_BORDER_CLASSES,
  SEVERITY_TEXT_CLASSES,
  severityLabel,
} from '../../lib/severity'

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold tracking-wider uppercase',
        SEVERITY_BG_SOFT_CLASSES[severity],
        SEVERITY_TEXT_CLASSES[severity],
        SEVERITY_BORDER_CLASSES[severity],
        className,
      )}
    >
      {severityLabel(severity)}
    </span>
  )
}

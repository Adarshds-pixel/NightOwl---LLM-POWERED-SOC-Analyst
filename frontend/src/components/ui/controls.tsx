import clsx from 'clsx'
import { Search, X } from 'lucide-react'
import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react'

/**
 * Form controls for the filter strips on the list pages. All three share
 * one height (36px), one radius and one focus treatment so a filter bar
 * lines up without per-page tweaking.
 */

const FIELD =
  'h-9 w-full rounded-control border border-line bg-bg-deep/80 px-3 text-meta text-text backdrop-blur-md placeholder:text-text-faint transition-all duration-200 focus:border-accent-violet/65 focus:shadow-glow-primary focus:outline-none'

export function TextInput({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={clsx(FIELD, className)} {...rest} />
}

export function SearchInput({
  value,
  onChange,
  placeholder = 'Search...',
  className,
  autoFocus,
}: {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
  autoFocus?: boolean
}) {
  return (
    <div className={clsx('relative', className)}>
      {/* z-10: a sibling <input> with no explicit stacking level still
          paints over an absolutely-positioned icon before it in some
          browsers (observed on `type="search"` here and on the login
          page's username/password fields) regardless of DOM order --
          without this the icon is invisible even though it's correctly
          positioned and never actually hidden by CSS. */}
      <Search className="pointer-events-none absolute top-1/2 left-3 z-10 h-3.5 w-3.5 -translate-y-1/2 text-text-faint" />
      <input
        type="search"
        value={value}
        autoFocus={autoFocus}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className={clsx(FIELD, 'pr-8 pl-9')}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          aria-label="Clear search"
          className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-1 text-text-faint transition-colors hover:text-text"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  )
}

interface SelectOption {
  label: string
  value: string
}

interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value'> {
  label?: string
  value: string
  options: SelectOption[]
  onChange: (value: string) => void
  className?: string
}

export function Select({ label, value, options, onChange, className, ...rest }: SelectProps) {
  return (
    <label className={clsx('flex flex-col gap-1', className)}>
      {label && <span className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">{label}</span>}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={clsx(FIELD, 'cursor-pointer appearance-none pr-8')}
        style={{
          backgroundImage:
            'url("data:image/svg+xml;utf8,<svg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 24 24%27 fill=%27none%27 stroke=%27%238b849d%27 stroke-width=%272%27><path d=%27M6 9l6 6 6-6%27/></svg>")',
          backgroundRepeat: 'no-repeat',
          backgroundPosition: 'right 8px center',
          backgroundSize: '14px',
        }}
        {...rest}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} className="bg-surface-2 text-text">
            {option.label}
          </option>
        ))}
      </select>
    </label>
  )
}

/** The filter strip itself: a card-height bar that keeps search on the
 *  left, filters in the middle and actions pinned right, and wraps
 *  gracefully instead of overflowing on narrow screens. */
export function FilterBar({
  search,
  filters,
  actions,
  className,
}: {
  search?: ReactNode
  filters?: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <div
      className={clsx(
        'flex flex-wrap items-end gap-3 rounded-card border border-line bg-surface-1/70 px-4 py-3 shadow-card backdrop-blur-xl',
        className,
      )}
    >
      {search && <div className="min-w-[200px] flex-1">{search}</div>}
      {filters && <div className="flex flex-wrap items-end gap-3">{filters}</div>}
      {actions && <div className="ml-auto flex items-end gap-2">{actions}</div>}
    </div>
  )
}

/** Segmented control -- used for time ranges and small view switches. */
export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  className,
}: {
  value: T
  options: { label: string; value: T }[]
  onChange: (value: T) => void
  className?: string
}) {
  return (
    <div className={clsx('inline-flex rounded-control border border-line bg-surface-2/60 p-0.5', className)}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          onClick={() => onChange(option.value)}
          aria-pressed={value === option.value}
          className={clsx(
            'rounded-[7px] px-2.5 py-1 text-micro font-semibold tracking-wide uppercase transition-colors duration-200',
            value === option.value
              ? 'bg-accent-primary/20 text-accent-primary'
              : 'text-text-muted hover:text-text',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
  title,
}: {
  checked: boolean
  onChange?: (checked: boolean) => void
  label: string
  disabled?: boolean
  title?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={title}
      disabled={disabled}
      onClick={() => onChange?.(!checked)}
      className={clsx(
        'relative h-5 w-9 shrink-0 rounded-full border transition-colors duration-200',
        // On-state is violet, not green: a switch being on is UI state, not a
        // security "healthy" signal, and green is reserved for the latter.
        checked ? 'border-accent-violet/55 bg-accent-primary/35 shadow-glow-primary' : 'border-line bg-surface-3',
        disabled ? 'cursor-not-allowed opacity-70' : 'cursor-pointer',
      )}
    >
      <span
        className={clsx(
          'absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all duration-200',
          checked ? 'left-4.5 bg-accent-violet' : 'left-0.5 bg-text-muted',
        )}
      />
    </button>
  )
}

import clsx from 'clsx'
import type { ReactNode } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { CHART, TEXT } from '../../lib/tokens'

/**
 * Recharts wrappers carrying all the NightOwl chart chrome: hairline grid,
 * micro-type axes, a glass tooltip and no default legend (legends are
 * hand-built HTML so they can carry counts and percentages the way the
 * mockups do). Pages pass data and colours; they never restyle recharts.
 */

const AXIS_TICK = { fill: TEXT.muted, fontSize: 10 }

export function ChartTooltipContent({
  active,
  payload,
  label,
  valueFormatter,
}: {
  active?: boolean
  payload?: { name?: string; value?: number | string; color?: string; payload?: Record<string, unknown> }[]
  label?: string | number
  valueFormatter?: (value: number | string) => string
}) {
  if (!active || !payload || payload.length === 0) return null

  return (
    <div className="rounded-md border border-line-strong bg-surface-2/95 px-2.5 py-2 shadow-elevated backdrop-blur-sm">
      {label !== undefined && <p className="mb-1 text-micro tracking-wide text-text-faint uppercase">{label}</p>}
      <div className="flex flex-col gap-0.5">
        {payload.map((entry, i) => (
          <div key={i} className="flex items-center gap-2 text-meta">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: entry.color }} />
            <span className="text-text-muted">{entry.name}</span>
            <span className="ml-auto font-mono text-text tabular-nums">
              {valueFormatter && entry.value !== undefined ? valueFormatter(entry.value) : entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

export interface DonutSlice {
  name: string
  value: number
  color: string
}

/** Donut with the total in the middle and a counted legend beside it --
 *  the shape used for severity, attack vectors and rule categories. */
export function Donut({
  slices,
  total,
  totalLabel = 'Total',
  height = 200,
  legend = true,
  onSliceClick,
}: {
  slices: DonutSlice[]
  total?: number
  totalLabel?: string
  height?: number
  legend?: boolean
  onSliceClick?: (slice: DonutSlice) => void
}) {
  const sum = total ?? slices.reduce((acc, slice) => acc + slice.value, 0)

  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="relative" style={{ height, width: height }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={slices}
              dataKey="value"
              nameKey="name"
              innerRadius="62%"
              outerRadius="88%"
              paddingAngle={2}
              stroke="none"
              onClick={(entry) => onSliceClick?.(entry as unknown as DonutSlice)}
              isAnimationActive={false}
            >
              {slices.map((slice) => (
                <Cell key={slice.name} fill={slice.color} className={onSliceClick ? 'cursor-pointer' : undefined} />
              ))}
            </Pie>
            <Tooltip
              content={<ChartTooltipContent valueFormatter={(v) => Number(v).toLocaleString()} />}
              cursor={false}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-[1.6rem] leading-none font-semibold text-text tabular-nums">
            {sum.toLocaleString()}
          </span>
          <span className="mt-1 text-micro tracking-[0.14em] text-text-faint uppercase">{totalLabel}</span>
        </div>
      </div>

      {legend && (
        <ul className="flex min-w-[120px] flex-1 flex-col gap-2">
          {slices.map((slice) => (
            <li key={slice.name} className="flex items-start gap-2 text-meta">
              <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: slice.color }} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-text-dim">{slice.name}</p>
                <p className="font-mono text-text tabular-nums">
                  {slice.value.toLocaleString()}
                  <span className="ml-1 text-text-faint">
                    ({sum > 0 ? ((slice.value / sum) * 100).toFixed(1) : '0.0'}%)
                  </span>
                </p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export interface Series {
  key: string
  label: string
  color: string
}

/** Multi-series line chart (severity over time, tactic coverage, rule
 *  activity). Points are hidden by default so a 24-bucket series does not
 *  turn into a dotted mess; hovering still reports every series. */
export function TrendChart({
  data,
  series,
  xKey = 'label',
  height = 200,
  area = false,
  showDots = false,
  yWidth = 34,
}: {
  data: Record<string, string | number>[]
  series: Series[]
  xKey?: string
  height?: number
  area?: boolean
  showDots?: boolean
  yWidth?: number
}) {
  const Chart = area ? AreaChart : LineChart

  return (
    <ResponsiveContainer width="100%" height={height}>
      <Chart data={data} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
        <defs>
          {series.map((s) => (
            <linearGradient key={s.key} id={`area-${s.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={0.28} />
              <stop offset="100%" stopColor={s.color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke={CHART.grid} strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey={xKey} tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: CHART.axisLine }} minTickGap={24} />
        <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} width={yWidth} allowDecimals={false} />
        <Tooltip content={<ChartTooltipContent />} cursor={{ stroke: CHART.axisLine }} />
        {series.map((s) =>
          area ? (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.label}
              stroke={s.color}
              strokeWidth={1.75}
              fill={`url(#area-${s.key})`}
              dot={showDots ? { r: 2, fill: s.color, strokeWidth: 0 } : false}
              activeDot={{ r: 3 }}
              isAnimationActive={false}
            />
          ) : (
            <Line
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.label}
              stroke={s.color}
              strokeWidth={1.75}
              dot={showDots ? { r: 2, fill: s.color, strokeWidth: 0 } : false}
              activeDot={{ r: 3 }}
              isAnimationActive={false}
            />
          ),
        )}
      </Chart>
    </ResponsiveContainer>
  )
}

/** Horizontal bars for ranked categories (tactic activity, top rules). */
export function RankedBars({
  data,
  color,
  height,
}: {
  data: { label: string; value: number }[]
  color: string
  height?: number
}) {
  return (
    <ResponsiveContainer width="100%" height={height ?? Math.max(160, data.length * 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
        <CartesianGrid stroke={CHART.grid} strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="label" tick={AXIS_TICK} tickLine={false} axisLine={false} width={116} />
        <Tooltip content={<ChartTooltipContent />} cursor={{ fill: CHART.cursor }} />
        <Bar dataKey="value" name="Count" fill={color} radius={[0, 4, 4, 0]} barSize={12} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Chart legend that matches the mockups: a row of coloured dashes with
 *  labels, centred under the plot. */
export function ChartLegend({ series, className }: { series: Series[]; className?: string }) {
  return (
    <ul className={clsx('flex flex-wrap items-center justify-center gap-x-4 gap-y-1', className)}>
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5 text-micro text-text-muted">
          <span className="h-0.5 w-3 rounded-full" style={{ background: s.color }} />
          {s.label}
        </li>
      ))}
    </ul>
  )
}

/** Wrapper so a chart panel can show a caption without the page repeating
 *  the same markup on every card. */
export function ChartFrame({ children, caption }: { children: ReactNode; caption?: ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      {children}
      {caption && <p className="text-micro text-text-faint">{caption}</p>}
    </div>
  )
}

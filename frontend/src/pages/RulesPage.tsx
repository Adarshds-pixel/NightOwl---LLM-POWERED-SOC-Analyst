import { CircleSlash, FileCode2, Layers, SlidersHorizontal, Target, Zap } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { RuleInfo, Severity } from '../api'
import {
  Badge,
  Card,
  DataTable,
  Donut,
  EmptyState,
  FilterBar,
  KeyValue,
  PageHeader,
  SearchInput,
  Select,
  SeverityBadge,
  StatCard,
  Toggle,
  Tooltip,
  type Column,
  type SortState,
} from '../components/ui'
import { useRules } from '../hooks/useRules'
import { formatRelativeTime } from '../lib/format'
import { CATEGORICAL, CATEGORICAL_OTHER } from '../lib/tokens'
import { topBy } from '../lib/aggregations'

import { SEVERITY_RANK } from '../lib/severity'

const SEVERITY_LEVELS: Severity[] = ['critical', 'high', 'medium', 'low']

/**
 * The Rules Engine view.
 *
 * Rules are YAML files under backend/app/detection/rules, loaded at startup
 * and served read-only by GET /rules. The enable toggle therefore reports
 * state rather than offering to change it: a rule is enabled precisely when
 * it loaded successfully, and changing that means editing the file and
 * restarting -- so the control is disabled with an explanation instead of
 * being a switch that silently does nothing.
 */
function RulesPage() {
  const [searchParams] = useSearchParams()
  const { rules, loading, error, refresh } = useRules()
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('all')
  const [category, setCategory] = useState('all')
  const [sort, setSort] = useState<SortState | null>(null)
  const ruleParam = searchParams.get('rule')
  const [selectedId, setSelectedId] = useState<string | null>(ruleParam)
  const [seenRuleParam, setSeenRuleParam] = useState(ruleParam)
  if (ruleParam !== seenRuleParam) {
    setSeenRuleParam(ruleParam)
    if (ruleParam) setSelectedId(ruleParam)
  }

  const categories = [...new Set(rules.map((rule) => rule.category).filter(Boolean))] as string[]
  const filtered = rules.filter((rule) => {
    const term = search.trim().toLowerCase()
    if (level !== 'all' && rule.level !== level) return false
    if (category !== 'all' && rule.category !== category) return false
    if (term && !`${rule.title} ${rule.description} ${rule.technique_id ?? ''}`.toLowerCase().includes(term)) return false
    return true
  })

  const selected = rules.find((rule) => rule.rule_id === selectedId) ?? filtered[0] ?? null
  // ML anomaly records are advisory and left out, as on every other alert total.
  const triggeredToday = rules.filter((rule) => rule.kind !== 'ml').reduce((sum, rule) => sum + rule.matches_24h, 0)
  // Top 6 + a folded "Other" slice, same convention as
  // attackVectorBreakdown()/MitrePage.tsx/ReportsPage.tsx -- a bare
  // topBy(..., 6) here previously dropped every category past the 6th
  // with no indication anything was cut. The rule set has 21 distinct
  // categories (as of this fix), so a "Rules" donut with no fold was
  // silently hiding ~15 of them. topBy() itself is intentionally left
  // unmodified: its other 2 call sites (AlertsPage's "most active rules",
  // LogsPage's "Top hosts") are genuine top-N ranking lists, not
  // total-implying donuts, and adding an unconditional "Other" bucket
  // there would inject an unwanted row into a plain ranked list.
  const allCategoryCounts = topBy(rules, (rule) => rule.category, Infinity)
  const topCategoryCounts = allCategoryCounts.slice(0, 6)
  const otherCategoryCount = allCategoryCounts.slice(6).reduce((sum, entry) => sum + entry.count, 0)
  const categoryCounts = [
    ...topCategoryCounts.map((entry, index) => ({
      name: entry.label.replace(/_/g, ' '),
      value: entry.count,
      color: CATEGORICAL[index % CATEGORICAL.length],
    })),
    ...(otherCategoryCount > 0 ? [{ name: 'Other', value: otherCategoryCount, color: CATEGORICAL_OTHER }] : []),
  ]

  const columns: Column<RuleInfo>[] = [
    {
      key: 'title',
      header: 'Rule',
      sortValue: (rule) => rule.title,
      className: 'max-w-[300px]',
      cell: (rule) => (
        <div className="min-w-0">
          <p className="flex items-center gap-1.5 truncate text-text">
            {rule.kind === 'sequence' && <Badge accent="violet">Sequence</Badge>}
            {rule.kind === 'ml' && <Badge accent="neutral">ML model · experimental</Badge>}
            <span className="truncate">{rule.title}</span>
          </p>
          <p className="truncate text-micro text-text-faint">{rule.description || rule.filename}</p>
        </div>
      ),
    },
    {
      key: 'category',
      header: 'Category',
      hideBelow: 'md',
      sortValue: (rule) => rule.category ?? '',
      cell: (rule) => (
        <Badge accent="primary">
          {rule.kind === 'sigma'
            ? (rule.category ?? 'event-id scoped').replace(/_/g, ' ')
            : rule.kind === 'ml'
              ? 'anomaly model'
              : 'correlation'}
        </Badge>
      ),
    },
    {
      key: 'technique',
      header: 'Technique',
      hideBelow: 'sm',
      sortValue: (rule) => rule.technique_id ?? '',
      cell: (rule) => <span className="font-mono text-meta text-accent-magenta">{rule.technique_id ?? '--'}</span>,
    },
    {
      key: 'level',
      header: 'Severity',
      sortValue: (rule) => (rule.level in SEVERITY_RANK ? SEVERITY_RANK[rule.level as Severity] : 0),
      cell: (rule) =>
        SEVERITY_LEVELS.includes(rule.level as Severity) ? (
          <SeverityBadge severity={rule.level as Severity} />
        ) : (
          <Badge accent="neutral">{rule.level}</Badge>
        ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (rule) => (
        <Tooltip
          label={
            rule.kind === 'ml'
              ? rule.enabled
                ? 'A trained model is loaded.'
                : 'No usable model is loaded -- see System status in Settings.'
              : 'Rules are version-controlled files; enabling or disabling one means editing the rule set, not flipping a switch here.'
          }
        >
          <span className="flex items-center gap-2">
            <Toggle checked={rule.enabled} label={`${rule.title} enabled`} disabled />
          </span>
        </Tooltip>
      ),
    },
    {
      key: 'matches24h',
      header: 'Matches 24h',
      align: 'right',
      sortValue: (rule) => rule.matches_24h,
      cell: (rule) => <span className="font-mono text-meta text-text tabular-nums">{rule.matches_24h}</span>,
    },
    {
      key: 'matches',
      header: 'Total',
      align: 'right',
      hideBelow: 'lg',
      sortValue: (rule) => rule.match_count,
      cell: (rule) => <span className="font-mono text-meta text-text-muted tabular-nums">{rule.match_count}</span>,
    },
    {
      key: 'last',
      header: 'Last triggered',
      hideBelow: 'md',
      sortValue: (rule) => rule.last_triggered ?? '',
      cell: (rule) => (
        <span className="text-meta whitespace-nowrap text-text-muted">
          {rule.last_triggered ? formatRelativeTime(rule.last_triggered) : 'never'}
        </span>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Rules Engine"
        subtitle="Detection rules currently loaded, and what each has caught"
        icon={<SlidersHorizontal className="h-5 w-5 text-accent-violet" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Rules Engine' }]}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard
          label="Rules loaded"
          value={rules.filter((rule) => rule.kind === 'sigma').length}
          icon={<FileCode2 className="h-4 w-4" />}
          accent="violet"
          note={`Sigma-style YAML rules + ${rules.filter((rule) => rule.kind === 'sequence').length} sequence detectors`}
        />
        <StatCard
          label="Enabled"
          value={rules.filter((rule) => rule.kind !== 'ml' && rule.enabled).length}
          icon={<Zap className="h-4 w-4" />}
          accent="magenta"
          note={`of ${rules.filter((rule) => rule.kind !== 'ml').length} rules and sequence detectors${
            rules.some((rule) => rule.kind === 'ml')
              ? rules.some((rule) => rule.kind === 'ml' && rule.enabled)
                ? ' -- plus the ML model (advisory)'
                : ' -- ML model not loaded'
              : ''
          }`}
        />
        <StatCard label="Triggered 24h" value={triggeredToday} icon={<Target className="h-4 w-4" />} accent="amber" note="Matches in the 24 h before the latest alert" />
        <StatCard label="Never fired" value={rules.filter((rule) => rule.kind !== 'ml' && rule.match_count === 0).length} icon={<CircleSlash className="h-4 w-4" />} accent="neutral" note={`of ${rules.filter((rule) => rule.kind !== 'ml').length} -- no match in the ingested data`} />
        <StatCard label="Categories" value={categories.length} icon={<Layers className="h-4 w-4" />} accent="primary" note="Log source categories covered" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-8">
          <FilterBar
            search={<SearchInput value={search} onChange={setSearch} placeholder="Search rules by name, description or technique..." />}
            filters={
              <>
                <Select
                  label="Severity"
                  value={level}
                  onChange={setLevel}
                  options={[{ label: 'All severities', value: 'all' }, ...SEVERITY_LEVELS.map((value) => ({ label: value, value }))]}
                  className="w-40"
                />
                <Select
                  label="Category"
                  value={category}
                  onChange={setCategory}
                  options={[
                    { label: 'All categories', value: 'all' },
                    ...categories.map((value) => ({ label: value.replace(/_/g, ' '), value })),
                  ]}
                  className="w-48"
                />
              </>
            }
          />

          <Card flush divided title={`${filtered.length} rules`}>
            <DataTable
              columns={columns}
              rows={filtered}
              rowKey={(rule) => rule.rule_id}
              onRowClick={(rule) => setSelectedId(rule.rule_id)}
              isRowActive={(rule) => rule.rule_id === selected?.rule_id}
              sort={sort}
              onSortChange={setSort}
              loading={loading}
              error={error}
              onRetry={refresh}
              emptyMessage="No rules match these filters"
            />
          </Card>
        </div>

        <div className="flex flex-col gap-4 xl:col-span-4">
          <Card
            title="Rule details"
            accent="violet"
            action={selected && <Badge accent={selected.enabled ? 'green' : 'neutral'}>{selected.enabled ? 'Enabled' : 'Disabled'}</Badge>}
          >
            {selected ? (
              <div className="flex flex-col gap-3">
                <div>
                  <p className="text-title font-semibold text-text">{selected.title}</p>
                  <p className="mt-0.5 text-meta text-text-muted">{selected.description || 'No description in the rule file.'}</p>
                </div>
                <dl className="grid grid-cols-2 gap-3">
                  <KeyValue label="Category" value={(selected.category ?? '--').replace(/_/g, ' ')} />
                  <KeyValue label="Technique" value={selected.technique_id ?? '--'} mono />
                  <KeyValue label="Severity" value={selected.level} />
                  <KeyValue label="Author" value={selected.author || '--'} />
                  <KeyValue label="Rule file" value={selected.filename} mono />
                  <KeyValue label="Authored" value={selected.date || '--'} mono />
                  <KeyValue label="Matches 24h" value={selected.matches_24h} mono />
                  <KeyValue label="Matches total" value={selected.match_count} mono />
                </dl>

                {selected.kind === 'sigma' ? (
                  <div>
                    <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">Detection logic</p>
                    <pre className="mt-1 overflow-x-auto rounded-control border border-line bg-bg-deep/60 px-3 py-2 font-mono text-micro text-text-dim">
                      {`selections: ${selected.selections.join(', ')}\ncondition: ${selected.condition}`}
                    </pre>
                  </div>
                ) : (
                  <p className="text-meta text-text-dim">
                    {selected.kind === 'ml'
                      ? 'Not a rule: a statistical model with no YAML logic. Its records are supporting evidence, never detections.'
                      : 'A multi-event correlation implemented in code (detection/sequences.py), not a YAML rule.'}
                  </p>
                )}

                {selected.tactics.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {selected.tactics.map((tactic) => (
                      <Badge key={tactic} accent="violet">
                        {tactic.replace(/_/g, ' ')}
                      </Badge>
                    ))}
                  </div>
                )}

                {selected.references.length > 0 && (
                  <div>
                    <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">References</p>
                    <ul className="mt-1 flex flex-col gap-1">
                      {selected.references.map((reference) => (
                        <li key={reference} className="truncate text-micro text-accent-magenta">
                          {reference}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <EmptyState message="Select a rule to inspect it" />
            )}
          </Card>

          <Card title="Rules by category" accent="primary">
            {categoryCounts.length > 0 ? (
              <Donut slices={categoryCounts} totalLabel="Rules" height={168} />
            ) : (
              <EmptyState message="No rules loaded" />
            )}
          </Card>

          <Card title="Most active rules" subtitle="By total matches" accent="amber">
            <ul className="flex flex-col gap-2">
              {[...rules]
                .sort((a, b) => b.match_count - a.match_count)
                .slice(0, 6)
                .map((rule) => (
                  <li key={rule.rule_id} className="flex items-center justify-between gap-3 text-meta">
                    <span className="truncate text-text-dim">{rule.title}</span>
                    <span className="font-mono text-text tabular-nums">{rule.match_count}</span>
                  </li>
                ))}
              {rules.length === 0 && <li className="text-meta text-text-muted">No rules loaded.</li>}
            </ul>
          </Card>
        </div>
      </div>

      <p className="text-micro text-text-faint">
        Rules live in backend/app/detection/rules as Sigma-style YAML and are reviewed like code; sequence detectors
        live in backend/app/detection/sequences.py and the ML model in backend/app/ml. This page is read-only by design:
        there is no endpoint that edits or disables a detector at runtime.
      </p>
    </div>
  )
}

export default RulesPage

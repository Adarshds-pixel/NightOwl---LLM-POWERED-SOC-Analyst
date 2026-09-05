import { Crosshair, Grid3x3, Layers, Radar, Target } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { HeatmapGrid } from '../components/mitre/HeatmapGrid'
import {
  Badge,
  Card,
  DataTable,
  Donut,
  EmptyState,
  ListRow,
  MeterBar,
  PageHeader,
  SearchInput,
  StatCard,
  Tabs,
  type Column,
} from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'
import { useRules } from '../hooks/useRules'
import { distinctTechniqueCount, tacticActivityCounts, tacticTechniqueMatrix } from '../lib/aggregations'
import { incidentRef } from '../lib/format'
import { TACTIC_LABELS, TACTIC_ORDER, isTactic, type Tactic } from '../lib/tactics'
import { CATEGORICAL, CATEGORICAL_OTHER, ACCENT } from '../lib/tokens'

interface TechniqueRow {
  id: string
  name: string
  tactics: string[]
  detections: number
  ruleCount: number
}

/**
 * MITRE ATT&CK coverage.
 *
 * Two very different numbers live on this page and the labels keep them
 * apart: the catalog holds hundreds of techniques (what exists), while
 * NightOwl has a few dozen detection rules and has observed a handful of
 * techniques (what this deployment can actually see). Coverage is stated
 * against the rule set, never against the whole catalog, because a rule
 * count over 800 would be a meaningless denominator for a student SOC.
 */
function MitrePage() {
  const [searchParams] = useSearchParams()
  const { incidents } = useIncidentsSnapshot()
  const { techniques, byId, loading } = useMitreCatalog()
  const { rules } = useRules()
  const [tab, setTab] = useState<'tactics' | 'techniques' | 'matrix'>('tactics')
  const [search, setSearch] = useState(searchParams.get('technique') ?? '')
  const [selectedTactic, setSelectedTactic] = useState<Tactic | null>(null)

  const matrix = tacticTechniqueMatrix(incidents, byId)
  const activity = tacticActivityCounts(incidents, byId)
  const observedCount = distinctTechniqueCount(incidents)
  const ruleTechniques = new Set(rules.map((rule) => rule.technique_id).filter(Boolean) as string[])

  const observedRows = useMemo<TechniqueRow[]>(() => {
    const counts = new Map<string, number>()
    for (const incident of incidents) {
      for (const techniqueId of incident.mitre_technique_ids) {
        counts.set(techniqueId, (counts.get(techniqueId) ?? 0) + 1)
      }
    }
    return [...counts.entries()]
      .map(([id, detections]) => ({
        id,
        name: byId.get(id)?.name ?? 'Unknown technique',
        tactics: byId.get(id)?.tactics ?? [],
        detections,
        ruleCount: rules.filter((rule) => rule.technique_id === id).length,
      }))
      .sort((a, b) => b.detections - a.detections)
  }, [incidents, byId, rules])

  const filteredRows = observedRows.filter((row) => {
    const term = search.trim().toLowerCase()
    if (!term) return true
    return row.id.toLowerCase().includes(term) || row.name.toLowerCase().includes(term)
  })

  // Top 6 + a folded "Other" slice, same convention as
  // attackVectorBreakdown() -- a bare `.slice(0, 6)` here previously
  // dropped every tactic past the 6th with no indication anything was
  // cut, so "Total technique hits" silently undercounted the moment a
  // corpus produced a 7th active tactic (found during the 39-file visual
  // QA pass, 2026-09-05).
  const topTacticActivity = activity.slice(0, 6)
  const otherTacticHits = activity.slice(6).reduce((sum, entry) => sum + entry.count, 0)
  const tacticSlices = [
    ...topTacticActivity.map((entry, index) => ({
      name: entry.label,
      value: entry.count,
      color: CATEGORICAL[index % CATEGORICAL.length],
    })),
    ...(otherTacticHits > 0 ? [{ name: 'Other', value: otherTacticHits, color: CATEGORICAL_OTHER }] : []),
  ]

  const selectedTechniques = selectedTactic
    ? observedRows.filter((row) => row.tactics.includes(selectedTactic))
    : []

  const columns: Column<TechniqueRow>[] = [
    {
      key: 'id',
      header: 'Technique',
      sortValue: (row) => row.id,
      cell: (row) => <span className="font-mono text-meta text-accent-magenta">{row.id}</span>,
    },
    {
      key: 'name',
      header: 'Name',
      sortValue: (row) => row.name,
      cell: (row) => <span className="text-text">{row.name}</span>,
    },
    {
      key: 'tactics',
      header: 'Tactics',
      hideBelow: 'md',
      cell: (row) => (
        <span className="flex flex-wrap gap-1">
          {row.tactics.filter(isTactic).map((tactic) => (
            <Badge key={tactic} accent="violet">
              {TACTIC_LABELS[tactic]}
            </Badge>
          ))}
        </span>
      ),
    },
    {
      key: 'rules',
      header: 'Rules',
      align: 'right',
      sortValue: (row) => row.ruleCount,
      cell: (row) => <span className="font-mono text-meta text-text-muted tabular-nums">{row.ruleCount}</span>,
    },
    {
      key: 'detections',
      header: 'Detections',
      align: 'right',
      sortValue: (row) => row.detections,
      cell: (row) => <span className="font-mono text-meta text-text tabular-nums">{row.detections}</span>,
    },
  ]

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="MITRE ATT&CK"
        icon={<Crosshair className="h-5 w-5 text-accent-magenta" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'MITRE ATT&CK' }]}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Techniques in catalog"
          value={techniques.length}
          icon={<Layers className="h-4 w-4" />}
          accent="primary"
          note="Enterprise ATT&CK, loaded from the official bundle"
        />
        <StatCard
          label="Techniques observed"
          value={observedCount}
          icon={<Target className="h-4 w-4" />}
          accent="red"
          note="Seen in real ingested telemetry"
        />
        <StatCard
          label="Techniques with a rule"
          value={ruleTechniques.size}
          icon={<Radar className="h-4 w-4" />}
          accent="violet"
          note={`${rules.length} detection rules loaded`}
        />
        <StatCard
          label="Tactics active"
          value={matrix.tacticsPresent.length}
          icon={<Grid3x3 className="h-4 w-4" />}
          accent="primary"
          note={`Of ${TACTIC_ORDER.length} tracked tactics`}
        />
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { value: 'tactics', label: 'Tactics view' },
          { value: 'techniques', label: 'Techniques', count: observedRows.length },
          { value: 'matrix', label: 'Attack matrix' },
        ]}
      />

      {tab === 'tactics' && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Card
            title="MITRE ATT&CK heatmap"
            subtitle="Observed techniques by tactic - click a tactic to inspect it"
            accent="magenta"
            className="xl:col-span-8"
          >
            <HeatmapGrid
              incidents={incidents}
              techniqueById={byId}
              showAllTactics
              selectedTactic={selectedTactic}
              onSelectTactic={(tactic) => setSelectedTactic(tactic === selectedTactic ? null : tactic)}
            />
          </Card>

          <div className="flex flex-col gap-4 xl:col-span-4">
            <Card title="Selected tactic" accent="violet">
              {selectedTactic ? (
                <div className="flex flex-col gap-3">
                  <div>
                    <p className="text-title font-semibold text-text">{TACTIC_LABELS[selectedTactic]}</p>
                    <p className="text-micro text-text-faint">
                      {selectedTechniques.length} technique(s) observed in this deployment
                    </p>
                  </div>
                  {selectedTechniques.map((row) => (
                    <div key={row.id} className="rounded-control border border-line bg-surface-2/40 px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-meta text-accent-magenta">{row.id}</span>
                        <span className="font-mono text-micro text-text-muted tabular-nums">
                          {row.detections} detections
                        </span>
                      </div>
                      <p className="mt-0.5 truncate text-meta text-text-dim">{row.name}</p>
                      <MeterBar
                        className="mt-1.5"
                        value={row.detections}
                        max={observedRows[0]?.detections ?? 1}
                        color={ACCENT.magenta}
                      />
                    </div>
                  ))}
                  {selectedTechniques.length === 0 && (
                    <p className="text-meta text-text-muted">No observed techniques for this tactic.</p>
                  )}
                </div>
              ) : (
                <EmptyState message="Select a tactic in the matrix" hint="Its observed techniques appear here." />
              )}
            </Card>

            <Card title="Tactic activity" subtitle="Total technique hits" accent="primary">
              {tacticSlices.length > 0 ? (
                <Donut slices={tacticSlices} totalLabel="Hits" height={168} />
              ) : (
                <EmptyState message="No tactic activity yet" />
              )}
            </Card>
          </div>
        </div>
      )}

      {tab === 'techniques' && (
        <div className="flex flex-col gap-4">
          <SearchInput value={search} onChange={setSearch} placeholder="Search observed techniques by id or name..." className="max-w-md" />
          <Card flush divided title={`${filteredRows.length} observed techniques`}>
            <DataTable
              columns={columns}
              rows={filteredRows}
              rowKey={(row) => row.id}
              loading={loading}
              emptyMessage="No techniques observed yet"
              emptyHint="Only techniques with at least one real detection are listed here."
            />
          </Card>
        </div>
      )}

      {tab === 'matrix' && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Card title="Full attack matrix" subtitle="All 14 tactics - dimmed columns have no detections" accent="magenta" className="xl:col-span-9">
            <HeatmapGrid incidents={incidents} techniqueById={byId} showAllTactics />
          </Card>
          <Card title="Recently detected" accent="amber" className="xl:col-span-3" bodyClassName="px-2 pb-3">
            <div className="flex flex-col">
              {incidents.slice(0, 8).map((incident) => (
                <ListRow
                  key={incident.id}
                  to={`/incidents/${incident.id}`}
                  title={incident.mitre_technique_ids[0] ?? 'No technique'}
                  meta={`${incidentRef(incident.id)} - ${incident.host}`}
                  trailing={<span className="font-mono text-micro text-text-faint">{incident.mitre_technique_ids.length}</span>}
                />
              ))}
              {incidents.length === 0 && <EmptyState message="Nothing detected yet" />}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

export default MitrePage

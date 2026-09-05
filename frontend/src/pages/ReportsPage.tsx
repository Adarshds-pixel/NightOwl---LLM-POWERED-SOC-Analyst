import { FileBarChart, FileJson, Printer, RefreshCw, Sheet } from 'lucide-react'
import { useMemo, useState } from 'react'
import {
  Badge,
  Button,
  Card,
  DataTable,
  Donut,
  EmptyState,
  KeyValue,
  MeterBar,
  PageHeader,
  SegmentedControl,
  SeverityBadge,
  StatCard,
  StatusBadge,
  type Column,
} from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'
import { useToast } from '../context/toast/useToast'
import { useRules } from '../hooks/useRules'
import { distinctTechniqueCount } from '../lib/aggregations'
import { formatDateTime, incidentRef } from '../lib/format'
import { buildReport, downloadText, reportToCsv, REPORT_WINDOWS, type ReportWindow } from '../lib/report'
import { SEVERITY_HEX, severityLabel } from '../lib/severity'
import { ACCENT, CATEGORICAL, CATEGORICAL_OTHER } from '../lib/tokens'
import type { IncidentSummary } from '../api'

const SEVERITY_ROWS = ['critical', 'high', 'medium', 'low'] as const

/**
 * Reports.
 *
 * NightOwl has no reports table and no report endpoint, so this does not
 * pretend to list documents somebody filed. It generates the report live
 * from the same API data the rest of the console is showing, and lets you
 * take it away as print/PDF, CSV or JSON. What you see is the posture at
 * the moment you pressed the button, and the page says exactly that.
 */
function ReportsPage() {
  const { incidents, meta, loading } = useIncidentsSnapshot()
  const { byId } = useMitreCatalog()
  const { rules } = useRules()
  const { push } = useToast()
  // Defaults to 'all', not a recent-days window: this project's real
  // workload is batch-ingesting historical/public EVTX captures (the
  // benchmark corpus is dated 2019-2021), so a wall-clock-relative default
  // would show "0 incidents" out of the box for the project's actual
  // primary use case -- every real incident's own event time is years
  // before whatever "now" the browser thinks it is.
  const [window_, setWindow] = useState<ReportWindow>('all')
  const [generatedAt, setGeneratedAt] = useState(() => new Date().toISOString())

  const report = useMemo(
    () => buildReport(incidents, byId, rules, window_),
    // generatedAt is in the dependency list on purpose: pressing Regenerate
    // re-runs the snapshot against whatever the API holds right now.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [incidents, byId, rules, window_, generatedAt],
  )

  const severitySlices = SEVERITY_ROWS.filter((severity) => report.severity[severity] > 0).map((severity) => ({
    name: severityLabel(severity),
    value: report.severity[severity],
    color: SEVERITY_HEX[severity],
  }))

  // Top 6 + a folded "Other" slice, same convention as
  // attackVectorBreakdown() -- a bare `.slice(0, 6)` here previously
  // dropped every tactic past the 6th with no indication anything was
  // cut, so the "Hits" total silently undercounted the moment a corpus
  // produced a 7th active tactic (found during the 39-file visual QA
  // pass, 2026-09-05; the MITRE page had the identical bug).
  const topReportTactics = report.tactics.slice(0, 6)
  const otherReportTacticHits = report.tactics.slice(6).reduce((sum, entry) => sum + entry.count, 0)
  const tacticSlices = [
    ...topReportTactics.map((entry, index) => ({
      name: entry.label,
      value: entry.count,
      color: CATEGORICAL[index % CATEGORICAL.length],
    })),
    ...(otherReportTacticHits > 0 ? [{ name: 'Other', value: otherReportTacticHits, color: CATEGORICAL_OTHER }] : []),
  ]

  const columns: Column<IncidentSummary>[] = [
    {
      key: 'ref',
      header: 'Reference',
      cell: (incident) => <span className="font-mono text-meta text-text-muted">{incidentRef(incident.id)}</span>,
    },
    { key: 'title', header: 'Title', cell: (incident) => <span className="text-text">{incident.title}</span> },
    { key: 'severity', header: 'Severity', cell: (incident) => <SeverityBadge severity={incident.severity} /> },
    { key: 'status', header: 'Status', cell: (incident) => <StatusBadge status={incident.status} /> },
    {
      key: 'host',
      header: 'Host',
      hideBelow: 'sm',
      cell: (incident) => <span className="font-mono text-meta text-text-muted">{incident.host}</span>,
    },
    {
      key: 'detected',
      header: 'Detected',
      hideBelow: 'md',
      cell: (incident) => (
        <span className="font-mono text-meta whitespace-nowrap text-text-muted">
          {formatDateTime(incident.created_at)}
        </span>
      ),
    },
  ]

  function regenerate() {
    setGeneratedAt(new Date().toISOString())
    push({ tone: 'success', title: 'Report regenerated', description: 'Rebuilt from the current API data.' })
  }

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Reports"
        subtitle="A live posture summary, generated from the current API data"
        icon={<FileBarChart className="h-5 w-5 text-accent-primary" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Reports' }]}
        className="print-hide"
        actions={
          <>
            <SegmentedControl value={window_} onChange={setWindow} options={REPORT_WINDOWS} />
            <Button variant="ghost" onClick={regenerate} icon={<RefreshCw className="h-3.5 w-3.5" />}>
              Regenerate
            </Button>
            <Button
              variant="secondary"
              onClick={() => downloadText(`${report.id}.csv`, reportToCsv(report), 'text/csv')}
              icon={<Sheet className="h-3.5 w-3.5" />}
            >
              CSV
            </Button>
            <Button
              variant="secondary"
              onClick={() => downloadText(`${report.id}.json`, JSON.stringify(report, null, 2), 'application/json')}
              icon={<FileJson className="h-3.5 w-3.5" />}
            >
              JSON
            </Button>
            <Button variant="primary" onClick={() => window.print()} icon={<Printer className="h-3.5 w-3.5" />}>
              Print / PDF
            </Button>
          </>
        }
      />

      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-title font-semibold text-text">NightOwl security posture report</p>
            <p className="mt-0.5 text-meta text-text-muted">
              {report.windowLabel} - generated {formatDateTime(report.generatedAt)}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge accent="primary">{report.id}</Badge>
            <Badge accent="neutral">Generated in-browser</Badge>
          </div>
        </div>
        <p className="mt-3 text-meta text-text-faint">
          Every figure below is read from the live API at generation time. NightOwl does not store reports
          server-side, so this document exists only here and in whatever you export.
        </p>
      </Card>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Incidents in window"
          value={report.incidentCount}
          icon={<FileBarChart className="h-4 w-4" />}
          accent="primary"
          note={`${meta.totalAll.toLocaleString()} total ingested`}
        />
        <StatCard
          label="Critical"
          value={report.severity.critical ?? 0}
          icon={<FileBarChart className="h-4 w-4" />}
          accent="red"
          note="Highest severity band"
        />
        <StatCard
          label="Hosts involved"
          value={report.hosts.length}
          icon={<FileBarChart className="h-4 w-4" />}
          accent="primary"
          note="Distinct hosts in this window"
        />
        <StatCard
          label="Techniques seen"
          value={distinctTechniqueCount(report.incidents)}
          icon={<FileBarChart className="h-4 w-4" />}
          accent="violet"
          note={`${distinctTechniqueCount(incidents)} across all data`}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Card title="Severity breakdown" accent="red" className="xl:col-span-4">
          {severitySlices.length > 0 ? (
            <Donut slices={severitySlices} total={report.incidentCount} totalLabel="Incidents" height={180} />
          ) : (
            <EmptyState
              message="No incidents in this window"
              hint={
                window_ !== 'all' && meta.totalAll > 0
                  ? `${meta.totalAll.toLocaleString()} incident(s) exist outside this window -- try "All ingested data"`
                  : undefined
              }
            />
          )}
        </Card>

        <Card title="Tactic activity" accent="violet" className="xl:col-span-4">
          {tacticSlices.length > 0 ? (
            <Donut slices={tacticSlices} totalLabel="Hits" height={180} />
          ) : (
            <EmptyState message="No tactics attributed in this window" />
          )}
        </Card>

        <Card title="Status of these incidents" accent="primary" className="xl:col-span-4">
          <dl className="grid grid-cols-2 gap-3">
            <KeyValue label="Open" value={report.status.open ?? 0} mono />
            <KeyValue label="Investigating" value={report.status.investigating ?? 0} mono />
            <KeyValue label="Resolved" value={report.status.resolved ?? 0} mono />
            <KeyValue label="Closed" value={report.status.closed ?? 0} mono />
          </dl>
          <p className="mt-3 text-micro text-text-faint">
            Status is analyst-set through the incident view and recorded in the backend audit log.
          </p>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Card title="Most detected techniques" accent="magenta" className="xl:col-span-6">
          {report.techniques.length === 0 ? (
            <EmptyState message="No techniques detected in this window" />
          ) : (
            <ul className="flex flex-col gap-2.5">
              {report.techniques.map((technique) => (
                <li key={technique.id}>
                  <div className="flex items-center justify-between gap-3 text-meta">
                    <span className="truncate">
                      <span className="font-mono text-accent-magenta">{technique.id}</span>
                      <span className="ml-2 text-text-dim">{technique.name}</span>
                    </span>
                    <span className="font-mono text-text tabular-nums">{technique.detections}</span>
                  </div>
                  <MeterBar
                    className="mt-1"
                    value={technique.detections}
                    max={report.techniques[0].detections}
                    color={ACCENT.magenta}
                  />
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Rules that fired most" accent="amber" className="xl:col-span-6">
          {report.rules.length === 0 ? (
            <EmptyState message="No rule has matched yet" />
          ) : (
            <ul className="flex flex-col gap-2.5">
              {report.rules.map((rule) => (
                <li key={rule.title}>
                  <div className="flex items-center justify-between gap-3 text-meta">
                    <span className="truncate text-text-dim">{rule.title}</span>
                    <span className="font-mono text-text tabular-nums">{rule.matches}</span>
                  </div>
                  <MeterBar className="mt-1" value={rule.matches} max={report.rules[0].matches} color={ACCENT.amber} />
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-micro text-text-faint">
            Match counts are lifetime totals from the alerts table, not limited to the report window.
          </p>
        </Card>
      </div>

      <Card flush divided title={`Incidents in this report (${report.incidentCount})`}>
        <DataTable
          columns={columns}
          rows={report.incidents.slice(0, 100)}
          rowKey={(incident) => incident.id}
          loading={loading}
          emptyMessage="No incidents in this window"
          emptyHint="Widen the reporting window, or ingest more telemetry."
        />
      </Card>

      {report.incidentCount > 100 && (
        <p className="text-micro text-text-faint">
          The table lists the first 100 incidents; CSV and JSON exports contain all {report.incidentCount}.
        </p>
      )}
    </div>
  )
}

export default ReportsPage

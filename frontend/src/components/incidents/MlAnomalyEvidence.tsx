import type { MlAnomalyDetails } from '../../api'
import { formatDateTime } from '../../lib/format'
import { Badge, KeyValue } from '../ui'

/** Human wording for the ML layer's feature names (backend app/ml/features.py). */
export function mlFeatureLabel(name: string): string {
  if (name.startsWith('eid_') && name !== 'eid_other') return `Event ${name.slice(4)} count`
  const labels: Record<string, string> = {
    eid_other: 'Events of uncommon types',
    total_events: 'Total events',
    distinct_event_ids: 'Distinct event types',
    failed_logons: 'Failed logons',
    distinct_logon_accounts: 'Distinct logon accounts',
    distinct_logon_sources: 'Distinct logon source addresses',
    remote_logons: 'Network / RDP logons',
    explicit_credential_logons: 'Explicit-credential logons',
    account_changes: 'Account / group changes',
    distinct_new_processes: 'Distinct new processes',
    process_creations: 'Process creations',
    distinct_processes: 'Distinct processes',
    distinct_parent_child: 'Distinct parent→child pairs',
    network_connections: 'Network connections',
    distinct_destinations: 'Distinct destinations',
    distinct_destination_ports: 'Distinct destination ports',
    distinct_access_targets: 'Distinct processes accessed',
    script_blocks: 'Script blocks',
    script_chars: 'Script characters',
    max_script_chars: 'Largest script block',
    service_installs: 'Service installs',
    service_state_changes: 'Service state changes',
  }
  return labels[name] ?? name
}

/**
 * Evidence for one ML anomaly record: why the window was flagged, against
 * what baseline, and the explicit caveat that an anomaly is not a detection.
 */
export function MlAnomalyEvidence({ details }: { details: MlAnomalyDetails }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-control border border-line bg-bg-deep/60 px-3 py-2 text-meta text-text-dim">
        <Badge accent="neutral">Experimental · ML anomaly</Badge>{' '}
        This {details.family} window's mix and volume of events is unusual compared with the benign baseline the
        model was trained on. It is supporting evidence, not a detection: the model was trained on two hosts and
        flags a few ordinary windows per host-day, and it cannot name an ATT&amp;CK technique.
        {details.mode === 'advisory' && ' It never opens or changes an incident.'}
      </div>
      <dl className="grid grid-cols-2 gap-3">
        <KeyValue label="Log family" value={details.family} />
        <KeyValue label="Anomaly band" value={details.band === 'high' ? 'High (beyond 99.9th pct)' : 'Medium (beyond 99.5th pct)'} />
        <KeyValue
          label="Distance / thresholds"
          value={`${details.distance.toFixed(1)} vs ${details.threshold_medium.toFixed(1)} / ${details.threshold_high.toFixed(1)}`}
          mono
        />
        <KeyValue label="Events in window" value={details.window_events} mono />
        <KeyValue label="Window start" value={formatDateTime(details.window_start)} mono />
        <KeyValue label="Window end" value={formatDateTime(details.window_end)} mono />
      </dl>
      {details.top_features.length > 0 && (
        <div>
          <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">What drove the score</p>
          <table className="mt-1 w-full text-meta">
            <thead>
              <tr className="text-left text-text-faint">
                <th className="py-1 font-normal">Feature</th>
                <th className="py-1 text-right font-normal">This window</th>
                <th className="py-1 text-right font-normal">Baseline median</th>
                <th className="py-1 text-right font-normal">Share</th>
              </tr>
            </thead>
            <tbody>
              {details.top_features.map((feature) => (
                <tr key={feature.feature} className="border-t border-line">
                  <td className="py-1 text-text-dim">{mlFeatureLabel(feature.feature)}</td>
                  <td className="py-1 text-right font-mono tabular-nums text-text">{feature.value}</td>
                  <td className="py-1 text-right font-mono tabular-nums text-text-muted">{feature.baseline_median}</td>
                  <td className="py-1 text-right font-mono tabular-nums text-text-muted">
                    {Math.round(feature.share * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {details.novel_event_ids.length > 0 && (
        <p className="text-meta text-text-dim">
          Event types never seen in the baseline:{' '}
          <span className="font-mono text-text">{details.novel_event_ids.join(', ')}</span>
        </p>
      )}
    </div>
  )
}

// Standard MITRE ATT&CK Enterprise tactic vocabulary, hyphenated to match
// the real shortnames /mitre/techniques actually returns in each
// MitreTechnique.tactics entry (verified live 2026-08-25). NOT the same
// convention as backend/app/services/severity_service.py's _TACTIC_WEIGHT --
// that dict is keyed by underscore, deliberately, because it parses a
// *different* source (this project's own Sigma rule `tags:`, e.g.
// "attack.command_and_control"), not the MITRE catalog. An earlier version
// of this file mirrored that dict's underscore keys for this list too,
// which silently broke every multi-word tactic here (isTactic() rejected
// "credential-access", "lateral-movement", "command-and-control", etc. --
// only single-word tactics like "execution"/"persistence" ever matched) --
// found while wiring in a multi-technique demo incident on 2026-08-25 and
// fixed here; single-word tactics were unaffected either way.
//
// This is NOT the classic 14-tactic Enterprise list verbatim: querying the
// live /mitre/techniques endpoint over every tactic the bundled dataset
// actually uses (found during the 39-file visual QA pass, 2026-09-05) shows
// "defense-evasion" does not exist in this dataset at all -- it has been
// replaced by two different tactics, `stealth` (the general case) and
// `defense-impairment` (tool/log tampering specifically, e.g. the T1685.x
// family -- "Clear Windows Event Logs", "Disable or Modify Tools", etc.).
// Real techniques observed in this project's own corpus confirm both:
// T1014/T1070.006/T1218.005 -> ['stealth'], T1685.005 -> ['defense-impairment'].
// Before this was caught, every technique whose only tactic was one of
// these two was silently invisible in the Incidents Tactic column,
// Dashboard's "Top Attack Vectors", and the MITRE heatmap/tactic totals --
// isTactic() only recognized the classic 14, so a real non-null tactic
// string rendered as if the incident had none. `stealth` gets the classic
// "Defense Evasion" label/id (TA0005) since analysts expect that name and
// it's this dataset's real replacement for it; `defense-impairment` is not
// an official ATT&CK tactic, so it gets its own honest label and no
// fabricated TA-id.
export const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'stealth',
  'defense-impairment',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
] as const

export type Tactic = (typeof TACTIC_ORDER)[number]

export const TACTIC_LABELS: Record<Tactic, string> = {
  reconnaissance: 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  stealth: 'Defense Evasion',
  'defense-impairment': 'Defense Impairment',
  'credential-access': 'Credential Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  'command-and-control': 'Command and Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}

export function isTactic(value: string): value is Tactic {
  return (TACTIC_ORDER as readonly string[]).includes(value)
}

// Official ATT&CK tactic identifiers, shown under each column in the MITRE
// heatmap. Fixed public constants (attack.mitre.org/tactics/<id>), not derived
// from the STIX bundle: /mitre/techniques returns per-technique data only and
// never carries the tactic objects these ids belong to. `defense-impairment`
// has no official id -- it isn't a real Enterprise ATT&CK tactic, just this
// bundled dataset's own subdivision of Defense Evasion -- so it's left blank
// rather than inventing a TA-looking id that would misrepresent it as
// official.
export const TACTIC_IDS: Record<Tactic, string> = {
  reconnaissance: 'TA0043',
  'resource-development': 'TA0042',
  'initial-access': 'TA0001',
  execution: 'TA0002',
  persistence: 'TA0003',
  'privilege-escalation': 'TA0004',
  stealth: 'TA0005',
  'defense-impairment': '',
  'credential-access': 'TA0006',
  discovery: 'TA0007',
  'lateral-movement': 'TA0008',
  collection: 'TA0009',
  'command-and-control': 'TA0011',
  exfiltration: 'TA0010',
  impact: 'TA0040',
}

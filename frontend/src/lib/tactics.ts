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
export const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
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
  'defense-evasion': 'Defense Evasion',
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
// never carries the tactic objects these ids belong to.
export const TACTIC_IDS: Record<Tactic, string> = {
  reconnaissance: 'TA0043',
  'resource-development': 'TA0042',
  'initial-access': 'TA0001',
  execution: 'TA0002',
  persistence: 'TA0003',
  'privilege-escalation': 'TA0004',
  'defense-evasion': 'TA0005',
  'credential-access': 'TA0006',
  discovery: 'TA0007',
  'lateral-movement': 'TA0008',
  collection: 'TA0009',
  'command-and-control': 'TA0011',
  exfiltration: 'TA0010',
  impact: 'TA0040',
}

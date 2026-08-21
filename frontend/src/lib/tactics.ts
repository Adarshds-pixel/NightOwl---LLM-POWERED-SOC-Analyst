// Mirrors backend/app/services/severity_service.py's _TACTIC_WEIGHT key order
// verbatim (standard MITRE ATT&CK Enterprise tactic vocabulary). There is no
// endpoint that returns this list directly -- MitreTechnique.tactics is just
// a list of these strings attached to each of the 858 technique objects.
export const TACTIC_ORDER = [
  'reconnaissance',
  'resource_development',
  'initial_access',
  'execution',
  'persistence',
  'privilege_escalation',
  'defense_evasion',
  'credential_access',
  'discovery',
  'lateral_movement',
  'collection',
  'command_and_control',
  'exfiltration',
  'impact',
] as const

export type Tactic = (typeof TACTIC_ORDER)[number]

export const TACTIC_LABELS: Record<Tactic, string> = {
  reconnaissance: 'Reconnaissance',
  resource_development: 'Resource Development',
  initial_access: 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  privilege_escalation: 'Privilege Escalation',
  defense_evasion: 'Defense Evasion',
  credential_access: 'Credential Access',
  discovery: 'Discovery',
  lateral_movement: 'Lateral Movement',
  collection: 'Collection',
  command_and_control: 'Command and Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}

export function isTactic(value: string): value is Tactic {
  return (TACTIC_ORDER as readonly string[]).includes(value)
}

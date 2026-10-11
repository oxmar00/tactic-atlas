/**
 * Tiny hand-built STIX bundle that mirrors the structure of the official Enterprise ATT&CK
 * bundle (collection, matrix, tactics, techniques, sub-techniques, detection strategies,
 * analytics, data components, revoked/deprecated objects). Names/IDs mirror real ATT&CK
 * objects but descriptions are shortened.
 */
const ref = (id: string, kind: string) => ({ source_name: 'mitre-attack', external_id: id, url: `https://attack.mitre.org/${kind}/${id.replace('.', '/')}` });
const ENT = ['enterprise-attack'];

export function miniBundle(): { type: string; id: string; objects: Record<string, unknown>[] } {
  return {
    type: 'bundle',
    id: 'bundle--test',
    objects: [
      { type: 'x-mitre-collection', id: 'x-mitre-collection--1', name: 'Enterprise ATT&CK', x_mitre_version: '19.2', modified: '2026-08-05T21:33:58.496Z', x_mitre_attack_spec_version: '3.3.0' },
      {
        type: 'x-mitre-matrix',
        id: 'x-mitre-matrix--1',
        name: 'Enterprise ATT&CK',
        x_mitre_domains: ENT,
        tactic_refs: ['x-mitre-tactic--exec', 'x-mitre-tactic--cred', 'x-mitre-tactic--missing'],
      },
      { type: 'x-mitre-tactic', id: 'x-mitre-tactic--cred', name: 'Credential Access', x_mitre_shortname: 'credential-access', description: 'Steal credentials.', external_references: [ref('TA0006', 'tactics')], x_mitre_domains: ENT },
      { type: 'x-mitre-tactic', id: 'x-mitre-tactic--exec', name: 'Execution', x_mitre_shortname: 'execution', description: 'Run code.', external_references: [ref('TA0002', 'tactics')], x_mitre_domains: ENT },
      {
        type: 'attack-pattern',
        id: 'attack-pattern--t1059',
        name: 'Command and Scripting Interpreter',
        description: 'Adversaries may abuse interpreters.(Citation: Example 2020) See [PowerShell](https://attack.mitre.org/techniques/T1059/001).',
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
        x_mitre_platforms: ['Windows', 'Linux'],
        x_mitre_is_subtechnique: false,
        x_mitre_domains: ENT,
        x_mitre_version: '2.6',
        external_references: [ref('T1059', 'techniques'), { source_name: 'Example 2020', url: 'https://example.com' }],
      },
      {
        type: 'attack-pattern',
        id: 'attack-pattern--t1059-001',
        name: 'PowerShell',
        description: 'Adversaries may abuse PowerShell. Example: <code>powershell -enc ...</code>',
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
        x_mitre_platforms: ['Windows'],
        x_mitre_is_subtechnique: true,
        x_mitre_domains: ENT,
        external_references: [ref('T1059.001', 'techniques')],
      },
      {
        type: 'attack-pattern',
        id: 'attack-pattern--t1003',
        name: 'OS Credential Dumping',
        description: 'Adversaries may dump credentials.',
        kill_chain_phases: [
          { kill_chain_name: 'mitre-attack', phase_name: 'credential-access' },
          { kill_chain_name: 'mitre-attack', phase_name: 'execution' },
        ],
        x_mitre_platforms: ['Windows'],
        x_mitre_domains: ENT,
        external_references: [ref('T1003', 'techniques')],
      },
      {
        type: 'attack-pattern',
        id: 'attack-pattern--t1562',
        name: 'Impair Defenses',
        revoked: true,
        description: 'Old.',
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
        x_mitre_domains: ENT,
        external_references: [ref('T1562', 'techniques')],
      },
      {
        type: 'attack-pattern',
        id: 'attack-pattern--t1999',
        name: 'Deprecated Thing',
        x_mitre_deprecated: true,
        description: 'Old.',
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
        x_mitre_domains: ENT,
        external_references: [ref('T1999', 'techniques')],
      },
      {
        type: 'attack-pattern',
        id: 'attack-pattern--mobile',
        name: 'Mobile only',
        x_mitre_domains: ['mobile-attack'],
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
        external_references: [ref('T1400', 'techniques')],
      },
      { type: 'relationship', id: 'relationship--1', relationship_type: 'subtechnique-of', source_ref: 'attack-pattern--t1059-001', target_ref: 'attack-pattern--t1059' },
      { type: 'relationship', id: 'relationship--2', relationship_type: 'revoked-by', source_ref: 'attack-pattern--t1562', target_ref: 'attack-pattern--t1003' },
      { type: 'relationship', id: 'relationship--3', relationship_type: 'detects', source_ref: 'x-mitre-detection-strategy--1', target_ref: 'attack-pattern--t1059-001' },
      {
        type: 'x-mitre-detection-strategy',
        id: 'x-mitre-detection-strategy--1',
        name: 'Detect PowerShell abuse',
        x_mitre_domains: ENT,
        x_mitre_analytic_refs: ['x-mitre-analytic--1'],
        external_references: [ref('DET0001', 'detectionstrategies')],
      },
      {
        type: 'x-mitre-analytic',
        id: 'x-mitre-analytic--1',
        name: 'Analytic 0001',
        description: 'Correlate script block logging with process creation.',
        x_mitre_platforms: ['Windows'],
        x_mitre_domains: ENT,
        x_mitre_log_source_references: [
          { x_mitre_data_component_ref: 'x-mitre-data-component--script', name: 'WinEventLog:Microsoft-Windows-PowerShell/Operational', channel: 'EventCode=4104' },
          { x_mitre_data_component_ref: 'x-mitre-data-component--proc', name: 'WinEventLog:Security', channel: 'EventCode=4688' },
        ],
        external_references: [{ source_name: 'mitre-attack', external_id: 'AN0001', url: 'https://attack.mitre.org/detectionstrategies/DET0001#AN0001' }],
      },
      { type: 'x-mitre-data-component', id: 'x-mitre-data-component--script', name: 'Script Execution', description: 'Scripts.', x_mitre_domains: ENT, external_references: [ref('DC0029', 'datacomponents')] },
      { type: 'x-mitre-data-component', id: 'x-mitre-data-component--proc', name: 'Process Creation', description: 'Processes.', x_mitre_domains: ENT, external_references: [ref('DC0032', 'datacomponents')] },
    ],
  };
}

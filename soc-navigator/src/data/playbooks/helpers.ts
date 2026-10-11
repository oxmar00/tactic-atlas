import type { EvidenceField, Playbook, QueryPlaceholder } from '../../lib/playbooks/schema';

/**
 * Shared building blocks for the starter playbook library. Every starter playbook is
 * AI-assisted content and therefore ships as Draft until an authorized reviewer approves it.
 */

const COMMON_EVIDENCE: Record<string, Omit<EvidenceField, 'id' | 'required'>> = {
  alert_id: { label: 'Alert ID', hint: 'SIEM/EDR alert or incident number exactly as shown in the console.', multiline: false },
  detection_name: { label: 'Detection / rule name', hint: 'Name and, if shown, version of the rule that fired.', multiline: false },
  event_time: {
    label: 'Event timestamps and timezone',
    hint: 'First and last observed time. Write the timezone explicitly (UTC recommended), e.g. 2026-10-10T14:03:11Z.',
    multiline: false,
  },
  hostname: { label: 'Hostname / asset ID', hint: 'Device name plus EDR device ID or CMDB asset tag if available.', multiline: false },
  username: {
    label: 'Username / account ID',
    hint: 'UPN or DOMAIN\\user plus a stable identifier (SID, Entra ObjectId) when available.',
    multiline: false,
  },
  process: { label: 'Process name and PID', hint: 'e.g. powershell.exe (PID 4312). Include full path.', multiline: false },
  parent_process: { label: 'Parent process', hint: 'Parent image path and PID; grandparent if relevant.', multiline: false },
  command_line: { label: 'Command line', hint: 'Copy exactly. Treat as untrusted text - never run it.', multiline: true },
  file_hash: { label: 'File name, path and SHA-256', hint: 'One file per line.', multiline: true },
  src_ip: { label: 'Source IP address', hint: 'Include whether it is internal, VPN, or public.', multiline: false },
  destination: { label: 'Destination IP / domain / port', hint: 'One destination per line, e.g. 203.0.113.10:443 (cdn.example.net).', multiline: true },
  auth_outcome: { label: 'Authentication outcome and logon type', hint: 'e.g. 4624 LogonType 10 success; Entra ResultType 50126.', multiline: false },
  event_ids: {
    label: 'Relevant event IDs and raw event references',
    hint: 'Event IDs, EDR ReportIds, SIEM search links, or saved-search names you used.',
    multiline: true,
  },
  related_alerts: { label: 'Related alerts', hint: 'Other alerts for the same user, host, IP or hash in the window.', multiline: true },
  affected_assets: { label: 'Additional affected users / systems', hint: 'Anything beyond the original host and account.', multiline: true },
};

export type CommonEvidenceId = keyof typeof COMMON_EVIDENCE;

/** Reference a shared evidence definition, optionally overriding its hint. */
export function ev(id: CommonEvidenceId, required: boolean, hint?: string): EvidenceField {
  const base = COMMON_EVIDENCE[id];
  return { id, required, ...base, hint: hint ?? base.hint };
}

/** Define a playbook-specific evidence field. */
export function evCustom(id: string, label: string, hint: string, required = false, multiline = false): EvidenceField {
  return { id, label, hint, required, multiline };
}

/** Commonly re-used query placeholders. */
export const PH = {
  hostname: (example = 'WS-DEMO-0142'): QueryPlaceholder => ({
    name: 'hostname',
    kind: 'string',
    description: 'Device name from the alert (as it appears in this data source).',
    example,
    evidenceField: 'hostname',
  }),
  username: (example = 'jdoe'): QueryPlaceholder => ({
    name: 'username',
    kind: 'string',
    description: 'Account name from the alert. Check whether this table stores sAMAccountName, UPN, or DOMAIN\\user.',
    example,
    evidenceField: 'username',
  }),
  upn: (example = 'jdoe@example.com'): QueryPlaceholder => ({
    name: 'upn',
    kind: 'string',
    description: 'User principal name (sign-in name) from the alert.',
    example,
    evidenceField: 'username',
  }),
  alertTime: (example = '2026-10-10T14:03:11Z'): QueryPlaceholder => ({
    name: 'alert_time',
    kind: 'datetime',
    description: 'Alert time in ISO 8601 UTC. The query searches a window around it.',
    example,
  }),
  lookback: (example = '7d'): QueryPlaceholder => ({
    name: 'lookback',
    kind: 'timespan',
    description: 'How far back to search, e.g. 24h, 7d, 30d. Longer windows cost more.',
    example,
  }),
  srcIp: (example = '203.0.113.25'): QueryPlaceholder => ({
    name: 'src_ip',
    kind: 'string',
    description: 'Source IP address from the alert.',
    example,
    evidenceField: 'src_ip',
  }),
};

export const STARTER_AUTHOR = 'SOC Navigator starter library (AI-assisted draft)';
export const STARTER_DATE = '2026-10-11';

export function starterReview(): Playbook['review'] {
  return {
    author: STARTER_AUTHOR,
    reviewer: null,
    reviewedAt: null,
    notes:
      'AI-assisted starter content. Must be reviewed by an authorized detection engineer or IR lead, adapted to local telemetry, escalation policy, and tooling, then promoted to Reviewed/Approved.',
    history: [{ version: '1.0.0', status: 'Draft', by: STARTER_AUTHOR, at: STARTER_DATE, note: 'Initial starter library release.' }],
  };
}

/** Standard references every starter playbook carries in addition to technique pages. */
export function attackRef(id: string, title: string): { title: string; url: string } {
  return { title: `MITRE ATT&CK ${id} - ${title}`, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` };
}

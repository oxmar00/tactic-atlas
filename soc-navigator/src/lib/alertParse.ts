import type { Playbook } from './playbooks/schema';

/**
 * Turns pasted alert text or JSON (Defender, Sentinel, Splunk, or generic) into suggested
 * evidence values and a ranked playbook suggestion. Everything is treated as untrusted data:
 * it is only read, never executed or followed, and the analyst confirms what is used.
 */

export const MAX_ALERT_BYTES = 200_000;

export interface ParsedAlert {
  /** Suggested evidence values keyed by common evidence field ID. */
  evidence: Record<string, string>;
  title: string;
  alertRef: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical' | null;
  source: string;
  /** ATT&CK technique IDs mentioned in the alert. */
  techniques: string[];
  suggestions: { playbookId: string; score: number; reasons: string[] }[];
  warnings: string[];
}

/** Lowercased key aliases per evidence field, most specific first. */
const KEY_MAP: Record<string, string[]> = {
  alert_id: ['alertid', 'incidentid', 'systemalertid', 'providerincidentid', 'event_id', 'notable_id', 'sid', 'id'],
  detection_name: ['alertdisplayname', 'alertname', 'rulename', 'rule_name', 'search_name', 'detectionname', 'title', 'signature', 'name'],
  event_time: ['timegenerated', 'timestamp', 'eventtime', 'firstactivity', 'starttime', 'creationtime', '_time', 'time'],
  hostname: ['devicename', 'computerdnsname', 'computer', 'hostname', 'host', 'dest', 'dvc', 'machinename'],
  username: ['userprincipalname', 'accountupn', 'accountname', 'targetusername', 'username', 'user', 'src_user', 'account'],
  process: ['filename', 'processname', 'process_name', 'image', 'newprocessname', 'process'],
  parent_process: ['initiatingprocessfilename', 'parentimage', 'parentprocessname', 'parent_process_name', 'parent_process'],
  command_line: ['processcommandline', 'commandline', 'command_line', 'cmdline'],
  file_hash: ['sha256', 'filehash', 'file_hash', 'hash'],
  src_ip: ['sourceip', 'src_ip', 'ipaddress', 'clientip', 'callerip', 'srcipaddr', 'src', 'remoteip'],
  destination: ['destinationip', 'dest_ip', 'remoteurl', 'destinationhostname', 'dstipaddr', 'url', 'domain'],
};

const SEVERITY: Record<string, ParsedAlert['severity']> = { informational: 'Low', info: 'Low', low: 'Low', medium: 'Medium', moderate: 'Medium', high: 'High', critical: 'Critical' };

function flatten(value: unknown, out: Map<string, string>, depth = 0): void {
  if (depth > 6 || out.size > 2000 || value === null || typeof value !== 'object') return;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const key = k.toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (typeof v === 'string' || typeof v === 'number') {
      const s = String(v).trim();
      if (s && !out.has(key)) out.set(key, s.slice(0, 4000));
    } else if (Array.isArray(v)) {
      v.slice(0, 20).forEach((item) => (typeof item === 'object' ? flatten(item, out, depth + 1) : !out.has(key) && item != null && out.set(key, String(item).slice(0, 4000))));
    } else flatten(v, out, depth + 1);
  }
}

/** Parses "key: value" / "key=value" lines from plain-text alerts. */
function fromText(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split(/\r?\n/).slice(0, 2000)) {
    const m = /^\s*"?([A-Za-z_][\w .-]{0,60}?)"?\s*[:=]\s*"?(.*?)"?,?\s*$/.exec(line);
    if (!m || !m[2]) continue;
    const key = m[1].toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (!out.has(key)) out.set(key, m[2].slice(0, 4000));
  }
  return out;
}

const KEYWORDS: Record<string, string[]> = {
  'PB-PHISH-001': ['phish', 'email', 'spoof', 'malicious url', 'attachment'],
  'PB-USEREXEC-001': ['winword', 'excel.exe', 'outlook.exe', 'user execution', 'mshta', 'macro', 'lnk'],
  'PB-PWSH-001': ['powershell', 'pwsh', 'encodedcommand', '-enc', 'script block', 'amsi'],
  'PB-SCHTASK-001': ['schtasks', 'scheduled task', '4698'],
  'PB-WMI-001': ['wmiprvse', 'wmic', 'wmi '],
  'PB-CREDDUMP-001': ['lsass', 'mimikatz', 'credential dump', 'ntds', 'dcsync', 'procdump', 'comsvcs'],
  'PB-BRUTE-001': ['brute', 'password spray', 'failed logon', 'failed sign-in', '4625', 'lockout'],
  'PB-VALIDACCT-001': ['impossible travel', 'atypical travel', 'unfamiliar sign-in', 'anonymous ip', 'risky sign-in'],
  'PB-RUNKEY-001': ['currentversion\\run', 'run key', 'startup folder', 'autostart'],
  'PB-LATMOVE-001': ['psexec', 'lateral movement', 'admin$', 'remote desktop', 'rdp', 'winrm', '7045'],
  'PB-INGRESS-001': ['certutil', 'bitsadmin', 'urlcache', 'download'],
  'PB-INJECT-001': ['injection', 'createremotethread', 'hollow', 'reflective'],
  'PB-C2-001': ['command and control', 'c2', 'beacon', 'dns tunnel', 'cobalt strike'],
  'PB-EXFIL-001': ['exfiltration', 'rclone', 'mega.nz', 'upload', 'dlp'],
  'PB-RANSOM-001': ['ransom', 'vssadmin', 'shadow cop', 'encrypt', 'recoveryenabled'],
  'PB-MFAFATIGUE-001': ['mfa', 'push', '500121', 'multi-factor', 'multifactor'],
  'PB-INBOXRULE-001': ['inbox rule', 'inboxrule', 'forwarding', 'forwardto', 'redirectto'],
  'PB-DEFTAMPER-001': ['set-mppreference', 'tamper', 'disable defender', 'real-time protection', '1102', 'log cleared', 'wevtutil'],
  'PB-KERBEROAST-001': ['kerberoast', '4769', 'service ticket', 'spn'],
  'PB-ACCTCHANGE-001': ['4720', '4732', '4728', 'user created', 'added to group', 'net user', 'localgroup'],
  'PB-WEBSHELL-001': ['web shell', 'webshell', 'w3wp', 'exploit', '.aspx', 'public-facing'],
  'PB-CLOUDKEY-001': ['cloudtrail', 'createaccesskey', 'putbucketpolicy', 'iam', 's3 bucket', 'aws'],
  'PB-CRON-001': ['cron', 'crontab'],
};

export function parseAlert(raw: string, playbooks: readonly Playbook[]): ParsedAlert {
  const warnings: string[] = [];
  let text = raw;
  if (text.length > MAX_ALERT_BYTES) {
    text = text.slice(0, MAX_ALERT_BYTES);
    warnings.push('Alert text was longer than 200 KB and was truncated.');
  }
  const fields = new Map<string, string>();
  const trimmed = text.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      flatten(JSON.parse(trimmed), fields);
    } catch {
      warnings.push('Could not parse as JSON; read as plain text instead.');
    }
  }
  if (fields.size === 0) for (const [k, v] of fromText(text)) fields.set(k, v);

  const evidence: Record<string, string> = {};
  for (const [field, aliases] of Object.entries(KEY_MAP)) {
    const hit = aliases.find((a) => fields.has(a));
    if (hit) evidence[field] = fields.get(hit)!;
  }
  if (evidence.process && evidence.parent_process === evidence.process) delete evidence.parent_process;

  const techniques = [...new Set(text.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? [])].slice(0, 20);
  const lower = text.toLowerCase();
  const suggestions = playbooks
    .map((pb) => {
      const reasons: string[] = [];
      let score = 0;
      const direct = techniques.filter((t) => pb.techniques.includes(t));
      const parent = techniques.filter((t) => !direct.includes(t) && pb.techniques.includes(t.split('.')[0]));
      if (direct.length) {
        score += 10 * direct.length;
        reasons.push(`alert names ${direct.join(', ')}`);
      }
      if (parent.length) {
        score += 4 * parent.length;
        reasons.push(`alert names sub-technique(s) of ${[...new Set(parent.map((t) => t.split('.')[0]))].join(', ')}`);
      }
      const words = (KEYWORDS[pb.id] ?? []).filter((w) => lower.includes(w));
      if (words.length) {
        score += 2 * words.length;
        reasons.push(`keywords: ${words.slice(0, 4).join(', ')}`);
      }
      return { playbookId: pb.id, score, reasons };
    })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

  const sev = SEVERITY[(fields.get('severity') ?? fields.get('alertseverity') ?? fields.get('urgency') ?? '').toLowerCase()] ?? null;
  if (Object.keys(evidence).length === 0 && suggestions.length === 0) warnings.push('No recognizable fields were found. You can still start the investigation and enter details by hand.');
  return {
    evidence,
    title: (evidence.detection_name ?? '').slice(0, 200),
    alertRef: (evidence.alert_id ?? '').slice(0, 200),
    severity: sev,
    source: (fields.get('productname') ?? fields.get('vendor_product') ?? fields.get('detectionsource') ?? fields.get('sourcetype') ?? '').slice(0, 200),
    techniques,
    suggestions,
    warnings,
  };
}

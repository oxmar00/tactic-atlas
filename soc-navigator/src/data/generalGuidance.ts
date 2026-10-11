/**
 * Tactic-level general investigation guidance shown when a technique has no specific playbook.
 * It is deliberately generic and always labeled as such in the UI - it is not a reviewed,
 * technique-specific playbook.
 */
export interface TacticGuidance {
  question: string;
  checks: string[];
  logs: string[];
  escalateIf: string;
  relatedPlaybooks: string[];
}

export const GENERAL_STEPS = [
  'Validate the alert: confirm timestamp (with timezone), host, user, process, and the rule that fired.',
  'Establish a baseline: is this normal for the user, host, process, or business role? Check change records and approved software.',
  'Review surrounding telemetry 30-60 minutes before and after the alert and build a short timeline.',
  'Search for related activity: other alerts, the same indicators on other hosts/users, unusual authentication or network connections.',
  'Record supporting and contradicting evidence and the questions you could not answer.',
  'Recommend closure, further investigation, or escalation based on evidence and your procedures. Do not force a benign verdict when evidence is insufficient.',
];

export const TACTIC_GUIDANCE: Record<string, TacticGuidance> = {
  reconnaissance: {
    question: 'Is someone gathering information to target the organization?',
    checks: ['Volume and source of scanning or enumeration against external assets', 'Whether the activity targets specific people or systems (spearphishing preparation)'],
    logs: ['Firewall / WAF logs', 'Web server logs', 'Email security logs'],
    escalateIf: 'Targeted reconnaissance of specific employees or critical systems, or reconnaissance followed by exploitation attempts.',
    relatedPlaybooks: ['PB-PHISH-001'],
  },
  'resource-development': {
    question: 'Is there evidence of attacker infrastructure or capabilities aimed at the organization?',
    checks: ['Lookalike domains, newly registered domains, or impersonating accounts', 'Threat-intelligence reports naming the organization'],
    logs: ['Threat intelligence', 'DNS / proxy logs for lookalike domains', 'Brand monitoring'],
    escalateIf: 'Infrastructure clearly impersonating the organization or prepared for an active campaign.',
    relatedPlaybooks: ['PB-PHISH-001'],
  },
  'initial-access': {
    question: 'Did an attacker gain a first foothold?',
    checks: ['Entry vector (email, exposed service, valid account, supply chain)', 'First suspicious process, sign-in, or connection after the entry point'],
    logs: ['Email security', 'Identity provider sign-ins', 'VPN / remote access', 'Web server and WAF logs', 'EDR'],
    escalateIf: 'Any evidence that code ran or an account was used by an unauthorized party.',
    relatedPlaybooks: ['PB-PHISH-001', 'PB-VALIDACCT-001'],
  },
  execution: {
    question: 'Did attacker-controlled code run?',
    checks: ['Process lineage and command lines', 'Signer, path, prevalence of executed files', 'Network and file activity after execution'],
    logs: ['EDR / Sysmon process events', 'Security 4688 with command lines', 'PowerShell 4104'],
    escalateIf: 'Unapproved code executed, or execution chains through interpreters/LOLBins without explanation.',
    relatedPlaybooks: ['PB-PWSH-001', 'PB-USEREXEC-001', 'PB-WMI-001'],
  },
  persistence: {
    question: 'Did something set itself up to survive reboot or logoff?',
    checks: ['New autostart entries, tasks, services, accounts, or cloud credentials', 'What process created them and what they launch'],
    logs: ['EDR registry/task/service events', 'Security 4698, 4697, 4720', 'Cloud audit logs'],
    escalateIf: 'Unexplained persistence mechanism pointing to unapproved code or created by an unknown process.',
    relatedPlaybooks: ['PB-RUNKEY-001', 'PB-SCHTASK-001'],
  },
  'privilege-escalation': {
    question: 'Did an actor gain higher permissions than they should have?',
    checks: ['Privilege changes (group membership, role assignment, SYSTEM processes from user context)', 'Exploit or token manipulation indicators'],
    logs: ['Security 4672, 4728/4732/4756', 'Entra ID audit logs', 'EDR'],
    escalateIf: 'Any unauthorized gain of administrative or SYSTEM-level rights.',
    relatedPlaybooks: ['PB-VALIDACCT-001', 'PB-INJECT-001'],
  },
  stealth: {
    question: 'Is someone hiding activity from defenders?',
    checks: ['Masquerading names/paths, obfuscation, hidden artifacts, injection', 'Whether the hiding technique wraps another malicious action'],
    logs: ['EDR', 'Sysmon', 'File and registry telemetry'],
    escalateIf: 'Deliberate concealment is confirmed - it implies intent and usually other malicious activity.',
    relatedPlaybooks: ['PB-INJECT-001', 'PB-PWSH-001'],
  },
  'defense-impairment': {
    question: 'Were security controls disabled, modified, or blinded?',
    checks: ['Security tool status changes, exclusions, logging changes, cleared logs', 'Who made the change and whether a change ticket exists'],
    logs: ['EDR / AV health events', 'Security 1102, 4719', 'Defender 5001/5007', 'Cloud audit logs'],
    escalateIf: 'Any unauthorized change that reduces visibility or protection - treat as high priority.',
    relatedPlaybooks: ['PB-RANSOM-001'],
  },
  'credential-access': {
    question: 'Are credentials being stolen or guessed?',
    checks: ['Access to credential stores (LSASS, SAM, NTDS, browsers, keychains)', 'Failed-then-successful authentication patterns'],
    logs: ['EDR process access', 'Domain controller logs', 'Identity provider sign-ins'],
    escalateIf: 'Any credential store accessed by an unexpected process, or credentials used after guessing.',
    relatedPlaybooks: ['PB-CREDDUMP-001', 'PB-BRUTE-001'],
  },
  discovery: {
    question: 'Is someone mapping the environment?',
    checks: ['Bursts of enumeration commands (whoami, net group, nltest, AD queries)', 'Whether the account and host normally run such commands'],
    logs: ['EDR process events', 'Domain controller LDAP/4662 logs', 'Cloud API enumeration logs'],
    escalateIf: 'Enumeration from a user workstation or account with no administrative role, especially after other alerts.',
    relatedPlaybooks: ['PB-PWSH-001'],
  },
  'lateral-movement': {
    question: 'Is activity spreading between systems?',
    checks: ['Remote logons, remote execution, and tool transfer between hosts', 'Source host health and account legitimacy'],
    logs: ['Security 4624/4648/7045', 'EDR network and process events', 'Firewall east-west logs'],
    escalateIf: 'Unexplained remote execution or workstation-to-workstation administrative access.',
    relatedPlaybooks: ['PB-LATMOVE-001', 'PB-WMI-001'],
  },
  collection: {
    question: 'Is data being gathered for theft?',
    checks: ['Mass access to files, mailboxes, or repositories', 'Archive creation and staging folders'],
    logs: ['File server auditing', 'Microsoft 365 audit logs', 'EDR file events'],
    escalateIf: 'Bulk collection of sensitive data without a business reason.',
    relatedPlaybooks: ['PB-EXFIL-001'],
  },
  'command-and-control': {
    question: 'Is a system communicating with attacker infrastructure?',
    checks: ['Process responsible for the traffic', 'Beaconing, rare destinations, tunneling patterns'],
    logs: ['EDR network events', 'Proxy / DNS / firewall logs'],
    escalateIf: 'Non-browser or unknown process communicating with unverified external infrastructure.',
    relatedPlaybooks: ['PB-C2-001', 'PB-INGRESS-001'],
  },
  exfiltration: {
    question: 'Is data leaving the organization without authorization?',
    checks: ['Outbound volume, destinations, and transfer tools', 'Staging before the transfer'],
    logs: ['Firewall / proxy byte counts', 'DLP', 'Cloud audit logs'],
    escalateIf: 'Meaningful transfer to an unsanctioned destination.',
    relatedPlaybooks: ['PB-EXFIL-001'],
  },
  impact: {
    question: 'Is availability or integrity being damaged?',
    checks: ['Encryption, deletion, service stops, recovery inhibition, defacement', 'Number of affected systems'],
    logs: ['EDR file and process events', 'System/Security logs', 'Backup platform logs'],
    escalateIf: 'Immediately, for any confirmed destructive activity.',
    relatedPlaybooks: ['PB-RANSOM-001'],
  },
};

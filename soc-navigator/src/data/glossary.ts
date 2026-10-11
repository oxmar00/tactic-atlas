/** Plain-language definitions used by tooltips, the reference page, and the local assistant. */
export const GLOSSARY: Record<string, string> = {
  'ATT&CK': 'MITRE ATT&CK is a public knowledge base of attacker behaviors (tactics and techniques). It describes what attackers do - it is not a list of your detections.',
  Tactic: 'The attacker\'s goal at a stage of an intrusion, such as Initial Access or Credential Access. Shown as matrix columns.',
  Technique: 'A specific way an attacker achieves a tactic, e.g. T1059 Command and Scripting Interpreter.',
  'Sub-technique': 'A more specific variant of a technique, e.g. T1059.001 PowerShell.',
  Playbook: 'Step-by-step investigation guidance written by your organization. It is separate from MITRE content.',
  EDR: 'Endpoint Detection and Response: an agent on each host that records process, file, registry, and network activity and raises alerts.',
  SIEM: 'Security Information and Event Management: the platform that collects and searches logs (e.g. Microsoft Sentinel, Splunk, Elastic).',
  KQL: 'Kusto Query Language, used by Microsoft Sentinel and Defender XDR advanced hunting.',
  SPL: 'Search Processing Language, used by Splunk.',
  CIM: 'Splunk Common Information Model: normalized field names (e.g. Authentication.user) so one search works across data sources.',
  ASIM: 'Advanced Security Information Model: Microsoft Sentinel\'s normalization layer (e.g. _Im_Dns, imProcessCreate).',
  Sysmon: 'Free Microsoft Sysinternals tool that logs detailed process, network, file, and registry events on Windows.',
  LSASS: 'Local Security Authority Subsystem Service (lsass.exe). It holds credential material in memory, which is why attackers try to dump it.',
  LOLBin: '"Living off the land" binary: a legitimate built-in tool (certutil, rundll32, mshta) abused by attackers to avoid dropping new files.',
  'Parent process': 'The process that started another process. Parent-child relationships show how activity began.',
  'Command line': 'The full text used to start a process, including arguments. Treat it as untrusted text - never run it.',
  'Logon type': 'Windows code describing how a logon happened: 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 9 new credentials, 10 remote interactive (RDP), 11 cached.',
  MFA: 'Multi-factor authentication: a second proof of identity beyond a password.',
  'Password spraying': 'Trying a few common passwords against many accounts to avoid lockouts.',
  'Lateral movement': 'Moving from one compromised system to another inside the network.',
  Persistence: 'A mechanism that lets attacker code survive reboots or logoffs (Run keys, scheduled tasks, services).',
  'C2': 'Command and control: the communication channel attackers use to send commands to malware or tools.',
  Beaconing: 'Malware checking in with its C2 server at regular intervals.',
  IOC: 'Indicator of compromise: an observable such as a hash, IP, domain, or file path linked to malicious activity.',
  'Mark-of-the-Web': 'A Zone.Identifier tag Windows adds to downloaded files, recording that they came from the internet (and sometimes the URL).',
  'Process injection': 'Running code inside another process\'s memory to hide or gain that process\'s privileges.',
  DCSync: 'Abusing directory replication rights to request password hashes from a domain controller.',
  Exfiltration: 'Moving data out of the organization without authorization.',
  'Defang': 'Rewriting an indicator so it cannot be clicked, e.g. hxxps://bad[.]example.',
  'True positive': 'The detection fired on the activity it was designed to catch. It may still be authorized (benign true positive).',
  'False positive': 'The detection fired on activity that does not match what it was designed to catch.',
  Disposition: 'The analyst\'s recommended outcome for the alert: close, continue, or escalate.',
};

export function lookupTerm(term: string): string | undefined {
  const key = Object.keys(GLOSSARY).find((k) => k.toLowerCase() === term.trim().toLowerCase());
  return key ? GLOSSARY[key] : undefined;
}

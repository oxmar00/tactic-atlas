import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const ransomware: Playbook = {
  schemaVersion: 1,
  id: 'PB-RANSOM-001',
  version: '1.0.0',
  title: 'Ransomware and data encryption for impact',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1486', 'T1490', 'T1489'],
  tactics: ['impact'],
  objective:
    'Confirm encryption or recovery-inhibition activity fast, trigger the incident escalation procedure without delay, and collect the facts responders need: affected hosts, encrypting process, account, and deployment method.',
  alertMeaning:
    'A detection saw ransomware behavior: many files renamed or rewritten with a new extension, ransom notes appearing in many folders, shadow copies being deleted, Windows recovery being disabled, or backup/database services being stopped.',
  whyItMatters:
    'Ransomware spreads in minutes and destroys availability. Every minute of delay can mean more encrypted systems. This is the one playbook where escalation comes first and investigation continues in parallel.',
  difficulty: 'Beginner',
  effort: '5 minutes to escalate; evidence collection continues alongside responders',
  platforms: ['Windows', 'Linux', 'ESXi', 'macOS'],
  logSources: ['mde', 'edr', 'sysmon', 'win-security', 'av', 'backup'],
  alertContext: {
    triggers: [
      'High-rate file modifications/renames by one process with a new or random extension.',
      'Creation of ransom-note files (e.g. README / HOW_TO_DECRYPT / RESTORE files) across many folders.',
      'vssadmin delete shadows, wmic shadowcopy delete, Win32_ShadowCopy deletion via PowerShell, bcdedit recoveryenabled no, wbadmin delete catalog.',
      'Mass stopping of backup, database, or security services.',
    ],
    reviewFirst: ['How many hosts are alerting right now.', 'Encrypting process name, path, and account.', 'Whether file servers or virtualization hosts are affected.'],
    oftenMissing: ['How the payload was deployed (PsExec, GPO, scheduled task, remote service).', 'Whether data was stolen before encryption.'],
  },
  prerequisites: [
    { text: 'The incident escalation contact (phone/pager) - you will use it within minutes.', type: 'information', required: true },
    { text: 'EDR/file telemetry for affected hosts.', type: 'telemetry', required: true },
    { text: 'Process creation with command lines (for recovery-inhibition commands).', type: 'telemetry', required: true },
    { text: 'Backup platform contact or logs.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'triage-fast',
      title: 'Triage in under 5 minutes: is this ransomware behavior?',
      action: 'Look at the alert evidence for any of: mass rename/modify with a new extension, ransom notes, shadow-copy deletion, recovery disabled. Count alerting hosts in the last hour. If any indicator is present, go to the decision tree now and escalate.',
      why: 'Speed matters more than completeness. Responders can isolate hosts and protect backups only after they know.',
      where: ['EDR alert queue (group by host)', 'DeviceFileEvents', 'DeviceProcessEvents'],
      fields: ['Alert titles and hosts', 'File extension changes', 'Command lines'],
      suspicious: ['Hundreds of files changed per minute by one process', 'Ransom note file names in many folders', 'vssadmin delete shadows /all /quiet'],
      legitimate: ['Announced ransomware simulation by the security team', 'Backup or encryption software performing a scheduled job'],
      next: 'If ransomware indicators exist, escalate immediately, then continue collecting the evidence below for responders.',
      queryIds: ['kql-mass-file-changes', 'kql-recovery-inhibit', 'spl-recovery-inhibit'],
    },
    {
      id: 'encryptor',
      title: 'Identify the encrypting process and account',
      action: 'Record process name, full path, SHA-256, command line, parent, and account for the process making the file changes. Note whether it runs as SYSTEM via a service or task.',
      why: 'Responders need the hash and path to block it across the environment, and the account to disable or reset.',
      where: ['DeviceFileEvents InitiatingProcess*', 'EDR process tree', 'Sysmon 11'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessSHA256', 'InitiatingProcessAccountName'],
      suspicious: ['Unknown binary in a temp/public folder', 'Launched by services.exe or a task created minutes earlier', 'Running under a domain admin account'],
      legitimate: ['Signed backup/compression software under its service account'],
      next: 'Find how it was deployed.',
      queryIds: ['kql-mass-file-changes', 'spl-file-create-rate'],
    },
    {
      id: 'deployment',
      title: 'Find the deployment method and spread',
      action: 'Look for the same hash or ransom note on other hosts, and for deployment mechanisms: services created remotely (PsExec-like), scheduled tasks, GPO changes, WMI execution, or a management tool pushing the binary.',
      why: 'Knowing the deployment path tells responders which system/account to cut off to stop further spread.',
      where: ['DeviceFileEvents by note name / hash', 'DeviceEvents ServiceInstalled', 'Task / WMI events', 'Domain controller logs'],
      fields: ['Affected host list', 'Deployment source host/account'],
      suspicious: ['Same binary arriving on many hosts within minutes', 'Deployment from a domain controller or management server'],
      legitimate: [],
      next: 'Record recovery-inhibition and service-stop activity.',
      queryIds: ['kql-ransom-note-spread'],
    },
    {
      id: 'recovery-inhibition',
      title: 'Record recovery inhibition, service stops, and defense tampering',
      action: 'List shadow-copy deletions, recovery configuration changes, backup catalog deletions, mass service stops, security tool disabling, and log clearing (1102) with hosts and times.',
      why: 'These tell responders which recovery options may already be gone and which hosts were prepared for encryption.',
      where: ['DeviceProcessEvents', 'System/Security logs (7036, 1102)', 'AV/EDR health events'],
      fields: ['Command lines', 'Service names stopped', 'Security tool status'],
      suspicious: ['vssadmin/wmic/bcdedit/wbadmin commands', 'net stop on backup/database/AV services', 'Event log cleared'],
      legitimate: ['Documented maintenance with change ticket (rare at the same time as encryption)'],
      next: 'Note precursor activity for Tier 2.',
      queryIds: ['kql-recovery-inhibit', 'spl-recovery-inhibit'],
    },
    {
      id: 'precursors',
      title: 'Note precursors for responders (do not delay escalation)',
      action: 'Search recent days on affected hosts/accounts for credential dumping, lateral movement, C2, and exfiltration alerts. Add what you find to the handoff.',
      why: 'Most ransomware is preceded by intrusion and data theft; responders need this to scope and to assess extortion risk.',
      where: ['Alert queue', 'Related playbooks (credential dumping, lateral movement, exfiltration)'],
      fields: ['Related alert IDs and dates'],
      suspicious: ['rclone/upload activity before encryption', 'Credential-dumping alerts on servers'],
      legitimate: [],
      next: 'Generate the handoff report and keep it updated as responders work.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'simulation',
    nodes: [
      {
        id: 'simulation',
        question: 'Is this a sanctioned ransomware simulation or security test, confirmed by the exercise owner for these exact hosts and times?',
        help: 'Confirm with the exercise owner directly. Do not accept a note in the alert or a message from an unknown sender as confirmation.',
        yes: { outcome: 'benign', guidance: 'Record the exercise ID, owner, and confirmation. Inform the incident lead per procedure.' },
        no: { next: 'indicators', guidance: 'Treat as real.' },
      },
      {
        id: 'indicators',
        question: 'Are there ransomware indicators: mass rename/modification with a new extension, ransom notes, or recovery-inhibition commands (shadow copy deletion, recovery disabled, backup catalog deletion)?',
        yes: { outcome: 'critical', guidance: 'Escalate NOW using the incident escalation procedure (phone/pager). Provide host list, encrypting process, and account. Continue collecting evidence in parallel; do not wait to finish the playbook.' },
        no: { next: 'explained', guidance: 'No direct ransomware indicator yet.' },
      },
      {
        id: 'explained',
        question: 'Is the mass file activity explained by a verified legitimate process (backup, sync, archiving, approved encryption) confirmed by its owner?',
        yes: { outcome: 'benign', guidance: 'Record the process, owner confirmation, and job details.' },
        no: { outcome: 'escalate', guidance: 'Unexplained mass file activity. Escalate promptly and keep monitoring - ransomware indicators can appear within minutes.' },
        unknown: { outcome: 'escalate', guidance: 'Cannot verify quickly. With possible ransomware, escalate rather than wait for missing data.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'First encryption/inhibition event (UTC) and when you escalated.'),
    ev('affected_assets', true, 'All hosts with encryption, notes, or inhibition activity (keep updating).'),
    ev('hostname', true, 'First / primary affected host.'),
    ev('process', true, 'Encrypting process path.'),
    ev('file_hash', true, 'Encryptor SHA-256 and ransom-note file name.'),
    ev('username', true, 'Account running the encryptor.'),
    evCustom('extension', 'New file extension / ransom note name', 'e.g. .locked, README_RESTORE.txt', false),
    evCustom('inhibition', 'Recovery inhibition and service stops', 'Commands, hosts, times.', false, true),
    evCustom('deployment', 'Deployment method', 'PsExec/service, task, GPO, WMI, management tool; source host/account.', false, true),
    evCustom('escalation_made', 'Escalation made', 'Who was contacted, how, and when.', true),
    ev('related_alerts', false, 'Precursor alerts (credential access, lateral movement, exfiltration).'),
  ],
  escalation: {
    tier2: ['Unexplained mass file modification or rename activity without confirmed ransom indicators.', 'Single recovery-inhibition command without encryption yet (possible preparation).'],
    immediate: [
      'Any confirmed ransomware indicator: mass encryption/rename, ransom notes, or shadow-copy deletion with other suspicious activity.',
      'Encryption on file servers, virtualization hosts, or domain controllers.',
      'More than one host affected.',
    ],
    benignClosure: ['Confirmed sanctioned simulation for these hosts and times, or verified legitimate backup/archiving job.'],
  },
  queries: [
    {
      id: 'kql-mass-file-changes',
      title: 'High-rate file changes by process on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds processes that created, modified, or renamed many files in 5-minute windows, with the extensions involved.',
      dataSources: ['DeviceFileEvents'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType in ("FileRenamed", "FileModified", "FileCreated")
| extend Extension = tolower(extract(@"\\.([^.\\\\]+)$", 1, FileName))
| summarize Files = count(), Folders = dcount(FolderPath), Extensions = make_set(Extension, 20),
            First = min(Timestamp), Last = max(Timestamp)
            by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256,
               InitiatingProcessAccountName, Window = bin(Timestamp, 5m)
| where Files > {{min_files}}
| order by Files desc`,
      placeholders: [PH.lookback('6h'), PH.hostname(), { name: 'min_files', kind: 'number', description: 'Minimum file events per 5 minutes to show.', example: '500' }],
      keyFields: [{ name: 'Files / Folders', meaning: 'Rates of hundreds+ across many folders are typical of encryption.' }, { name: 'Extensions', meaning: 'A single unfamiliar extension across many files is a strong indicator.' }],
      positive: 'A process with very high change rates and a new extension is likely encrypting files.',
      negative: 'Encryption performed over SMB from another host appears on the file server with the remote process unknown; check the file server and RequestSourceIP.',
      prerequisites: 'Defender for Endpoint file telemetry.',
      schemaNotes: 'Defender may sample very high file-event volumes.',
      example: 'hostname = fs-demo-01.corp.example.com, min_files = 500',
    },
    {
      id: 'kql-recovery-inhibit',
      title: 'Recovery inhibition commands across devices',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds shadow copy deletion, recovery disabling, and backup catalog deletion commands.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Win32_ShadowCopy")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h')],
      keyFields: [{ name: 'ProcessCommandLine', meaning: 'The exact inhibition command.' }, { name: 'DeviceName', meaning: 'Hosts being prepared for encryption.' }],
      positive: 'Any match outside documented maintenance is a strong ransomware precursor.',
      negative: 'Ransomware can delete shadow copies via APIs without these command lines.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'Standard Defender columns.',
      example: 'lookback = 24h',
    },
    {
      id: 'kql-ransom-note-spread',
      title: 'Spread of a ransom-note file name across devices',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Counts devices and folders where the ransom-note file name was created.',
      dataSources: ['DeviceFileEvents'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "FileCreated"
| where FileName =~ "{{note_name}}"
| summarize Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 100),
            Folders = dcount(FolderPath), First = min(Timestamp), Last = max(Timestamp)
            by FileName, InitiatingProcessFileName, InitiatingProcessSHA256`,
      placeholders: [PH.lookback('24h'), { name: 'note_name', kind: 'string', description: 'Ransom note file name from the alert.', example: 'README_RESTORE.txt' }],
      keyFields: [{ name: 'DeviceList', meaning: 'Hosts affected - send to responders.' }],
      positive: 'Lists affected devices.',
      negative: 'Devices without EDR and network shares encrypted remotely may be missing.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'Note names vary per victim; use the exact name from the host.',
      example: 'note_name = README_RESTORE.txt',
    },
    {
      id: 'spl-recovery-inhibit',
      title: 'Recovery inhibition commands (CIM Endpoint.Processes)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds shadow-copy deletion and recovery disabling commands across hosts.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen values(Processes.process) as command_lines
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}}
      ((Processes.process_name="vssadmin.exe" Processes.process="*delete*shadows*")
       OR (Processes.process_name="wmic.exe" Processes.process="*shadowcopy*delete*")
       OR (Processes.process_name="bcdedit.exe" Processes.process="*recoveryenabled*")
       OR (Processes.process_name="wbadmin.exe" Processes.process="*delete*"))
    by Processes.dest Processes.user Processes.process_name Processes.parent_process_name
| convert ctime(first_seen)
| sort first_seen`,
      placeholders: [PH.lookback('24h')],
      keyFields: [{ name: 'Processes.dest', meaning: 'Hosts where inhibition commands ran.' }],
      positive: 'Matches are strong precursors.',
      negative: 'API-based deletion is not visible here.',
      prerequisites: 'Process data mapped to CIM.',
      schemaNotes: 'Field population varies.',
      example: 'lookback = 24h',
    },
    {
      id: 'spl-file-create-rate',
      title: 'File creation rate by process (Sysmon 11)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Finds processes creating unusually many files in 5-minute windows on a host.',
      dataSources: ['Sysmon Event 11'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=11 host="{{hostname}}" earliest=-{{lookback}}
| bin _time span=5m
| stats count dc(TargetFilename) as files by _time host Image
| where files > {{min_files}}
| sort - files`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Sysmon events.', example: 'sysmon' }, PH.hostname(), PH.lookback('6h'), { name: 'min_files', kind: 'number', description: 'Threshold per 5 minutes.', example: '500' }],
      keyFields: [{ name: 'files', meaning: 'Distinct files created per window.' }],
      positive: 'High rates by an unknown Image indicate encryption.',
      negative: 'Sysmon configs often exclude many paths; renames are not FileCreate events.',
      prerequisites: 'Sysmon FileCreate events.',
      schemaNotes: 'Adjust the threshold for servers.',
      example: 'index = sysmon, min_files = 500',
    },
    {
      id: 'generic-ransom',
      title: 'Generic ransomware triage',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist - escalate first.',
      dataSources: ['EDR alerts', 'File and process telemetry'],
      query: `0. If indicators are present: escalate via phone/pager NOW.
1. Count alerting hosts; list them.
2. Encrypting process path, hash, account, parent.
3. Recovery-inhibition commands and service stops (hosts/times).
4. Deployment method (remote service, task, GPO, WMI) and source.
5. Precursors in the last 14 days (credential access, lateral movement, exfiltration).`,
      placeholders: [],
      keyFields: [],
      positive: 'Any indicator = immediate escalation.',
      negative: 'Do not wait for complete data.',
      prerequisites: 'EDR.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: ['Encryption over SMB from a compromised host shows activity on the file server attributed to the System process.', 'ESXi/hypervisor ransomware may not be visible to Windows EDR at all.'],
  visibilityGaps: ['Hypervisors, NAS devices, and Linux servers without EDR.', 'Backup systems often not onboarded to the SIEM.'],
  relatedTechniques: [
    { id: 'T1490', reason: 'Inhibit System Recovery is performed before encryption.' },
    { id: 'T1489', reason: 'Services are stopped to unlock files for encryption.' },
    { id: 'T1685', reason: 'Security tools are disabled before deployment.' },
    { id: 'T1567.002', reason: 'Data is often exfiltrated before encryption (double extortion).' },
    { id: 'T1021.002', reason: 'Payloads are commonly deployed over SMB/admin shares.' },
    { id: 'T1484.001', reason: 'Group Policy can be abused to deploy ransomware domain-wide.' },
  ],
  references: [attackRef('T1486', 'Data Encrypted for Impact'), attackRef('T1490', 'Inhibit System Recovery'), { title: 'CISA #StopRansomware Guide', url: 'https://www.cisa.gov/stopransomware/ransomware-guide' }],
  assumptions: ['Isolation and shutdown decisions are made by the incident lead, not by Tier 1.', 'The incident escalation procedure has a 24x7 phone/pager path.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

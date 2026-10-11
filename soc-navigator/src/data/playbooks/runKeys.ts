import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const runKeys: Playbook = {
  schemaVersion: 1,
  id: 'PB-RUNKEY-001',
  version: '1.0.0',
  title: 'Registry Run key or Startup folder persistence',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1547', 'T1547.001'],
  tactics: ['persistence', 'privilege-escalation'],
  objective:
    'Identify what program the new autostart entry launches, which process created it, and whether it belongs to legitimate software or to malware establishing persistence.',
  alertMeaning:
    'A value was added or changed under a Run/RunOnce registry key, or a file was placed in a Startup folder. Whatever it points to will start automatically when the user logs on (HKCU / user Startup) or when any user logs on (HKLM / All Users Startup).',
  whyItMatters:
    'Run keys and Startup folders are among the simplest and most common persistence methods for commodity malware and remote-access tools. Persistence means the attacker returns after reboots.',
  difficulty: 'Beginner',
  effort: '20-40 minutes',
  platforms: ['Windows'],
  logSources: ['mde', 'sysmon', 'edr', 'win-security'],
  alertContext: {
    triggers: [
      'Registry value set under ...\\CurrentVersion\\Run, RunOnce, RunOnceEx, or ...\\Policies\\Explorer\\Run (HKCU or HKLM, including Wow6432Node).',
      'File created in %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup or C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp.',
      'Autostart entry referencing a script host, LOLBin, or user-writable path.',
    ],
    reviewFirst: ['Registry key path, value name, and value data (the command).', 'Process and account that wrote it.', 'Host and time.'],
    oftenMissing: ['Hash, signer, and prevalence of the referenced file.', 'Whether the entry has already executed at a logon.'],
  },
  prerequisites: [
    { text: 'Registry change telemetry (EDR registry events or Sysmon 12/13). Native 4657 only exists where SACLs are configured.', type: 'telemetry', required: true },
    { text: 'File creation telemetry for Startup folders.', type: 'telemetry', required: true },
    { text: 'Software inventory to recognize common autostart entries.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'entry',
      title: 'Record the autostart entry exactly',
      action:
        'Record the full key path (HKCU vs HKLM, which user SID), value name, value data, previous data (if modified), and timestamp. For Startup folders, record the file name, type (.lnk, .bat, .vbs, .exe), and for shortcuts the target and arguments.',
      why: 'The value data is the command that will run - it is the core evidence.',
      where: ['DeviceRegistryEvents', 'Sysmon 13 (TargetObject, Details)', 'DeviceFileEvents (Startup folder)'],
      fields: ['RegistryKey', 'RegistryValueName', 'RegistryValueData', 'PreviousRegistryValueData', 'FolderPath', 'FileName'],
      suspicious: [
        'Data points to AppData, Temp, ProgramData, Users\\Public, or a random-named folder',
        'Data launches powershell/cmd/wscript/mshta/rundll32/regsvr32 with arguments',
        'Value name imitates legitimate software (e.g. "OneDriveUpdate" with a non-Microsoft path)',
        '.vbs/.js/.bat/.lnk dropped in a Startup folder',
      ],
      legitimate: ['Well-known software (collaboration clients, cloud storage sync, hardware utilities) with data pointing to its signed binary in Program Files or the expected per-user install path'],
      next: 'Identify the process that wrote the entry.',
      queryIds: ['kql-run-key-changes', 'spl-run-key-sysmon'],
    },
    {
      id: 'writer',
      title: 'Identify the process that created the entry',
      action:
        'Find the initiating process, its command line, parent chain, and account. Determine if it is an installer/updater or something else (script host, unknown binary, reg.exe from a script).',
      why: 'Legitimate entries are written by the software\'s installer or the app itself. Malware writes its own persistence, often right after initial execution.',
      where: ['DeviceRegistryEvents InitiatingProcess*', 'Sysmon 13 Image', 'EDR process tree'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'InitiatingProcessParentFileName', 'InitiatingProcessAccountName'],
      suspicious: ['reg.exe add ... \\Run launched by powershell/cmd/wscript', 'Unknown binary in AppData writing its own path', 'Writer process created minutes after a user opened an attachment'],
      legitimate: ['msiexec.exe or the vendor\'s installer during a known install'],
      next: 'Investigate the referenced file.',
      queryIds: [],
    },
    {
      id: 'target-file',
      title: 'Assess the referenced file',
      action:
        'Record the path, SHA-256, signer, creation time, creating process, and organizational prevalence of the file the entry launches. Check reputation.',
      why: 'An unsigned, newly created, single-device file referenced from a Run key is a classic persistence pattern.',
      where: ['DeviceFileEvents', 'EDR file page', 'Reputation / sandbox'],
      fields: ['SHA256', 'Signer', 'File creation time', 'Device count'],
      suspicious: ['Unsigned and first seen recently', 'File created by the same process that wrote the Run key'],
      legitimate: ['Signed by the expected vendor, present on many devices'],
      next: 'Check whether it has executed.',
      queryIds: ['kql-run-key-prevalence'],
    },
    {
      id: 'executed',
      title: 'Check whether the entry has executed',
      action:
        'Look for the command from the value data being launched at logon (parent typically explorer.exe shortly after a logon, or the RunOnce handler). Review network connections and children of those executions.',
      why: 'If it already ran, the payload is active and may have contacted command-and-control.',
      where: ['DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceLogonEvents (logon times)'],
      fields: ['ProcessCommandLine', 'InitiatingProcessFileName', 'RemoteIP / RemoteUrl'],
      suspicious: ['Outbound connections to unknown hosts immediately after logon from the autostart process'],
      legitimate: ['Vendor application connecting to its update service'],
      next: 'Record executions and destinations.',
      queryIds: [],
    },
    {
      id: 'baseline',
      title: 'Compare across the fleet',
      action: 'Count devices with the same value name and data. Check software inventory and change records.',
      why: 'Common software creates the same entry on many devices. A unique entry is suspicious.',
      where: ['DeviceRegistryEvents summarized by value', 'Software inventory'],
      fields: ['Device count', 'First seen'],
      suspicious: ['Only on this device', 'On a small set of devices that share other alerts'],
      legitimate: ['Consistent across many devices with a known software deployment'],
      next: 'Use the decision tree.',
      queryIds: ['kql-run-key-prevalence', 'spl-run-key-cim'],
    },
  ],
  decisionTree: {
    start: 'known',
    nodes: [
      {
        id: 'known',
        question: 'Does the entry belong to known, legitimate software - written by its installer, pointing to a signed binary in its expected path, and common across the fleet?',
        yes: { outcome: 'benign', guidance: 'Document software name, signer, path, and prevalence.' },
        no: { next: 'risky', guidance: 'Not verified as known software.' },
      },
      {
        id: 'risky',
        question: 'Does the entry launch a script host/LOLBin, an encoded command, or an unsigned/rare file in a user-writable path - or was it written by a script host or unknown process?',
        yes: { next: 'active', guidance: 'Likely malicious persistence.' },
        no: { next: 'owner', guidance: 'Ambiguous entry.' },
      },
      {
        id: 'owner',
        question: 'Can you confirm the owner and purpose (user/IT confirmation, ticket, vendor documentation)?',
        yes: { outcome: 'benign', guidance: 'Document the confirmation source.' },
        no: { outcome: 'investigate', guidance: 'Unverified autostart entry. Continue investigating the file and writer; escalate if it cannot be verified.' },
      },
      {
        id: 'active',
        question: 'Does the same malicious entry exist on multiple hosts, or is the affected host a server or privileged administrator workstation with the payload already communicating externally?',
        yes: { outcome: 'critical', guidance: 'Spreading or high-value persistence. Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Malicious persistence on a single host. Escalate with key, data, file details, executions, and destinations - before the next logon triggers it again.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('hostname', true),
    ev('username', true, 'Account that wrote the entry and the hive owner (user SID for HKCU).'),
    evCustom('registry_entry', 'Registry key / value / data (or Startup file)', 'Full key, value name, value data; or Startup file path and shortcut target.', true, true),
    ev('parent_process', true, 'Process that wrote the entry.'),
    ev('file_hash', true, 'Referenced file: path, SHA-256, signer.'),
    evCustom('prevalence', 'Fleet prevalence', 'Number of devices with the same entry/file.', false),
    evCustom('executions', 'Executions and connections', 'Did the entry run? When? Network destinations?', false, true),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Entry launches a script interpreter/LOLBin, encoded command, or unsigned rare file from a user-writable location.',
      'Entry was written by a script host, unknown binary, or shortly after a suspicious execution.',
      'Value name or path imitates legitimate software.',
      'Owner cannot be verified.',
    ],
    immediate: [
      'Same malicious entry on multiple hosts.',
      'Payload has executed and is communicating with external hosts on a server or privileged workstation.',
    ],
    benignClosure: ['Entry traced to known software: installer writer, signed binary, expected path, common prevalence.', 'Or owner confirmed with documentation.'],
  },
  queries: [
    {
      id: 'kql-run-key-changes',
      title: 'Run/RunOnce registry changes and Startup folder files on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists autostart registry values set on the host, plus files created in Startup folders.',
      dataSources: ['DeviceRegistryEvents', 'DeviceFileEvents'],
      query: `let host = "{{hostname}}";
let lookbackWindow = {{lookback}};
let runKeys = DeviceRegistryEvents
    | where Timestamp > ago(lookbackWindow) and DeviceName =~ host
    | where ActionType == "RegistryValueSet"
    | where RegistryKey contains @"\\CurrentVersion\\Run"
         or RegistryKey contains @"\\Policies\\Explorer\\Run"
    | project Timestamp, Kind = "Registry", Location = RegistryKey,
              Name = RegistryValueName, Data = RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
let startupFiles = DeviceFileEvents
    | where Timestamp > ago(lookbackWindow) and DeviceName =~ host
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath contains @"\\Start Menu\\Programs\\Startup"
    | project Timestamp, Kind = "StartupFolder", Location = FolderPath,
              Name = FileName, Data = SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
union runKeys, startupFiles
| order by Timestamp asc`,
      placeholders: [PH.hostname(), PH.lookback('7d')],
      keyFields: [
        { name: 'Data', meaning: 'Registry value data (command) or Startup file SHA-256.' },
        { name: 'InitiatingProcessFileName', meaning: 'Process that created the entry.' },
      ],
      positive: 'Each row is an autostart change to attribute to software or an attacker.',
      negative: 'Other autostart locations (services, Winlogon, scheduled tasks, COM hijacks) are not covered - see related techniques.',
      prerequisites: 'Defender for Endpoint registry and file telemetry.',
      schemaNotes: 'RegistryKey in Defender uses HKEY_CURRENT_USER\\<SID>\\... or HKEY_LOCAL_MACHINE\\... formats; contains matches RunOnce/RunOnceEx too.',
      example: 'hostname = ws-demo-0142.corp.example.com, lookback = 7d',
    },
    {
      id: 'kql-run-key-prevalence',
      title: 'Prevalence of an autostart value across devices',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Counts devices where the same Run value name was set, to judge whether it is common software.',
      dataSources: ['DeviceRegistryEvents'],
      query: `DeviceRegistryEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\\CurrentVersion\\Run"
| where RegistryValueName =~ "{{value_name}}"
| summarize Devices = dcount(DeviceName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleData = make_set(RegistryValueData, 5), Writers = make_set(InitiatingProcessFileName, 5)
            by RegistryValueName`,
      placeholders: [PH.lookback('30d'), { name: 'value_name', kind: 'string', description: 'Registry value name from the alert.', example: 'UpdaterSvc' }],
      keyFields: [{ name: 'Devices', meaning: 'Number of devices with the value.' }, { name: 'SampleData', meaning: 'Differing data for the same name can reveal impersonation.' }],
      positive: 'High device counts with consistent data and writers suggest legitimate software.',
      negative: 'Entries created before the lookback window are not counted.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'Standard Defender columns.',
      example: 'value_name = UpdaterSvc, lookback = 30d',
    },
    {
      id: 'spl-run-key-sysmon',
      title: 'Run key value sets (Sysmon 13)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Lists autostart registry values set on the host with the writing process.',
      dataSources: ['Sysmon Event 13 (RegistryEvent value set)'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=13 host="{{hostname}}" earliest=-{{lookback}}
    (TargetObject="*CurrentVersion*Run*" OR TargetObject="*Policies*Explorer*Run*")
| table _time host User Image TargetObject Details
| sort _time`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Sysmon events.', example: 'sysmon' }, PH.hostname(), PH.lookback('7d')],
      keyFields: [{ name: 'Details', meaning: 'Value data written (the command).' }, { name: 'Image', meaning: 'Writing process.' }],
      positive: 'Autostart values to attribute.',
      negative: 'Sysmon configs sometimes exclude registry events from common installers; absence may be a config gap.',
      prerequisites: 'Sysmon registry monitoring for Run keys.',
      schemaNotes: 'Wildcards avoid backslash escaping; tighten if results are noisy.',
      example: 'index = sysmon, hostname = WS-DEMO-0142',
    },
    {
      id: 'spl-run-key-cim',
      title: 'Run key changes across hosts (CIM Endpoint.Registry)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Baseline of Run key value names across the fleet.',
      dataSources: ['CIM Endpoint.Registry'],
      query: `| tstats summariesonly=false count dc(Registry.dest) as hosts min(_time) as first_seen
    values(Registry.registry_value_data) as data
    from datamodel=Endpoint.Registry
    where earliest=-{{lookback}} Registry.registry_path="*CurrentVersion*Run*"
    by Registry.registry_value_name
| convert ctime(first_seen)
| sort hosts`,
      placeholders: [PH.lookback('30d')],
      keyFields: [{ name: 'hosts', meaning: 'Rare value names (low host counts) sort first.' }],
      positive: 'Rare entries deserve review.',
      negative: 'Requires registry data mapped to CIM.',
      prerequisites: 'Registry telemetry mapped to CIM Endpoint.Registry.',
      schemaNotes: 'CIM field population varies by source.',
      example: 'lookback = 30d',
    },
    {
      id: 'generic-runkey',
      title: 'Generic autostart procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Registry events', 'File events', 'Process events'],
      query: `1. Record key, value name, value data (or Startup file + shortcut target).
2. Identify the writing process, its parent, and account.
3. Hash, signer, creation time, and prevalence of the referenced file.
4. Look for executions at logon and their network activity.
5. Count devices with the same entry; check software inventory.`,
      placeholders: [],
      keyFields: [],
      positive: 'Findings feed the decision tree.',
      negative: 'Registry telemetry gaps should be recorded.',
      prerequisites: 'Registry and file telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'High volume of benign entries from legitimate software; allow-list by signer + path, not value name.',
    'RunOnce entries delete themselves after running - a missing entry later is not proof it never existed.',
  ],
  visibilityGaps: ['Native Windows logging (4657) requires SACLs on Run keys, rarely configured.', 'Offline registry edits are not captured by live telemetry.'],
  relatedTechniques: [
    { id: 'T1112', reason: 'Creating Run entries is a registry modification.' },
    { id: 'T1053.005', reason: 'Scheduled tasks are an alternative persistence mechanism.' },
    { id: 'T1543.003', reason: 'Windows services are an alternative persistence mechanism.' },
    { id: 'T1547.009', reason: 'Shortcut modification in Startup folders.' },
    { id: 'T1036.005', reason: 'Names and paths imitate legitimate software.' },
  ],
  references: [
    attackRef('T1547.001', 'Registry Run Keys / Startup Folder'),
    { title: 'Microsoft Learn - Run and RunOnce registry keys', url: 'https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys' },
    { title: 'Microsoft Learn - DeviceRegistryEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table' },
  ],
  assumptions: ['Removing autostart entries is a containment action performed after escalation.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

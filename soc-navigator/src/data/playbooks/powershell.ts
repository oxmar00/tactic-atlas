import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const powershell: Playbook = {
  schemaVersion: 1,
  id: 'PB-PWSH-001',
  version: '1.0.0',
  title: 'Suspicious PowerShell or command interpreter activity',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1059', 'T1059.001', 'T1059.003'],
  tactics: ['execution'],
  objective:
    'Decode and interpret the PowerShell (or cmd.exe) activity, identify who and what launched it, and determine whether it is approved automation or attacker activity.',
  alertMeaning:
    'A detection matched a risky PowerShell or command-shell pattern: an encoded command, a download-and-execute "cradle", a hidden window, execution-policy bypass, AMSI tampering, or an interpreter launched by an unusual parent process.',
  whyItMatters:
    'PowerShell is built into Windows and is used both by administrators and by attackers to download tools, run code in memory, and avoid writing files to disk. The same flags appear in legitimate scripts, so context decides the verdict.',
  difficulty: 'Intermediate',
  effort: '30-60 minutes',
  platforms: ['Windows'],
  logSources: ['mde', 'powershell', 'sysmon', 'win-security', 'edr', 'proxy'],
  alertContext: {
    triggers: [
      'powershell.exe / pwsh.exe with -EncodedCommand (or -enc, -e, -ec), -WindowStyle Hidden, or -ExecutionPolicy Bypass.',
      'Command line or script block containing DownloadString, Invoke-WebRequest, Net.WebClient, Invoke-Expression/IEX, or FromBase64String.',
      'AMSI or script-logging tampering strings in a script block (event 4104).',
      'cmd.exe or PowerShell launched by Office, a browser, mshta.exe, or wmiprvse.exe.',
    ],
    reviewFirst: [
      'Full command line (not the truncated alert title).',
      'Parent and grandparent process, user account, and integrity level.',
      'Any script block (4104) text near the same time.',
    ],
    oftenMissing: [
      'Decoded content of -EncodedCommand.',
      'Network destinations contacted by the PowerShell process.',
      'Whether the same command runs routinely across the fleet.',
    ],
  },
  prerequisites: [
    { text: 'Process creation with full command lines (EDR, Sysmon 1, or 4688 with command-line auditing).', type: 'telemetry', required: true },
    { text: 'PowerShell script block logging (4104) - strongly recommended; reveals de-obfuscated content.', type: 'telemetry', required: false },
    { text: 'An offline decoding tool approved by your SOC (e.g. a local CyberChef instance). Never paste suspicious commands into a PowerShell prompt to "see what they do".', type: 'tool', required: true },
    { text: 'Inventory of approved admin scripts and management agents (SCCM, Intune, RMM).', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'capture-command',
      title: 'Capture the full command line and execution context',
      action:
        'Copy the complete command line, process ID, user, host, integrity level, and timestamps from the EDR or SIEM event. Note the PowerShell version (powershell.exe = Windows PowerShell 5.1, pwsh.exe = PowerShell 7).',
      why: 'Alert titles truncate commands. The full text is the primary evidence and must be preserved exactly.',
      where: ['EDR process event', 'DeviceProcessEvents', 'Sysmon Event 1', 'Security 4688'],
      fields: ['ProcessCommandLine / CommandLine', 'AccountName / User', 'ProcessId', 'IntegrityLevel', 'DeviceName'],
      suspicious: ['Command line longer than ~1,000 characters of base64', 'Running as SYSTEM from a user-facing parent', 'Use of -NoProfile -NonInteractive -WindowStyle Hidden together'],
      legitimate: ['Short, readable command from an admin tool with a known script path (e.g. C:\\Program Files\\<vendor>\\scripts\\...)'],
      next: 'Store the command in the evidence checklist as text only, then decode it.',
      queryIds: ['kql-pwsh-cmdline', 'spl-pwsh-endpoint'],
    },
    {
      id: 'decode',
      title: 'Decode and read what the command does',
      action:
        'If -EncodedCommand (or an abbreviation) is used, decode the base64 as UTF-16LE in an offline tool. Look for nested encoding (FromBase64String, GZip/Deflate streams, -join of characters, string format tricks). Summarize the intent in plain language: download, execute in memory, discovery, credential access, persistence, or tampering.',
      why: 'Encoding hides intent from simple detection rules - it is not proof of malice, but you cannot judge the activity until you can read it.',
      where: ['Offline decoder (e.g. local CyberChef)', 'Script block logs (4104) for already de-obfuscated text'],
      fields: ['Decoded script text', 'URLs / IPs / domains in the script', 'Function and cmdlet names'],
      suspicious: [
        'IEX / Invoke-Expression of downloaded content (download cradle)',
        'Reflection to access System.Management.Automation.AmsiUtils (AMSI bypass)',
        'Names of offensive tooling or functions that dump credentials',
        'Disabling Defender (Set-MpPreference -DisableRealtimeMonitoring) or adding exclusions',
      ],
      legitimate: ['Encoded command produced by a known management tool that always uses encoding for transport', 'Script performs inventory or configuration matching a documented job'],
      next: 'Record the plain-language summary. If you cannot decode it, record that as an unresolved question and continue.',
      queryIds: ['kql-scriptblock', 'spl-scriptblock'],
    },
    {
      id: 'lineage',
      title: 'Identify who and what launched it',
      action:
        'Review parent and grandparent processes. Classify the launcher: user (explorer.exe), Office/browser, remote management (wmiprvse.exe, wsmprovhost.exe), service/task (services.exe, svchost.exe with Schedule), or management agent (e.g. CcmExec.exe, IntuneManagementExtension.exe).',
      why: 'The parent explains how the command started. Office or a browser launching PowerShell is rarely legitimate; a management agent usually is.',
      where: ['EDR process tree', 'DeviceProcessEvents (InitiatingProcess*)', 'Sysmon 1 ParentImage / ParentCommandLine'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'InitiatingProcessParentFileName', 'ParentImage'],
      suspicious: ['winword.exe / excel.exe / outlook.exe / mshta.exe parent', 'wmiprvse.exe or wsmprovhost.exe parent with no matching admin activity (possible remote execution)', 'Scheduled task created minutes earlier'],
      legitimate: ['Known management agent parent on a managed device', 'Administrator\'s interactive session during a change window'],
      next: 'If launched remotely (WMI/WinRM), also run the WMI or Remote Services playbook for the source host.',
      queryIds: ['kql-pwsh-cmdline'],
    },
    {
      id: 'network-files',
      title: 'Check network connections and files created by the process',
      action:
        'Find outbound connections and file writes by the PowerShell process ID during and after execution. Note destinations, ports, file paths, and whether downloaded files were executed.',
      why: 'Download-and-execute is the most common malicious PowerShell pattern. A completed download plus execution means a payload is now on the host.',
      where: ['DeviceNetworkEvents / DeviceFileEvents filtered by InitiatingProcessId', 'Sysmon 3 and 11', 'Proxy logs at the same timestamp'],
      fields: ['RemoteIP', 'RemoteUrl', 'RemotePort', 'FolderPath', 'FileName', 'SHA256'],
      suspicious: ['Connections to raw IP addresses, paste sites, or newly registered domains', 'Executable or DLL written to AppData/Temp/ProgramData and then run'],
      legitimate: ['Connections to the vendor\'s update service or internal repositories'],
      next: 'Add destinations and file hashes to evidence; check them in the Ingress Tool Transfer playbook if a file was downloaded.',
      queryIds: [],
    },
    {
      id: 'baseline',
      title: 'Compare against the organization baseline',
      action:
        'Search for the same command line (or a distinctive part of it) across all devices for 30 days. Check whether it runs on a schedule, under a service account, and on many hosts.',
      why: 'Legitimate automation is repetitive and widespread. A command seen once, on one host, by one user is much more suspicious.',
      where: ['DeviceProcessEvents summarized by command line', 'CIM Endpoint.Processes', 'Admin script inventory'],
      fields: ['Device count', 'Account names', 'First seen / last seen'],
      suspicious: ['First seen today on a single host', 'Run by a regular user account that never used PowerShell before'],
      legitimate: ['Runs daily on hundreds of hosts under a known service account', 'Matches a script in the approved inventory'],
      next: 'Record the baseline result and use the decision tree.',
      queryIds: ['spl-pwsh-endpoint'],
    },
    {
      id: 'related',
      title: 'Look for related activity on the host and account',
      action:
        'Review other alerts and notable events for the same host and user from 24 hours before to now: new logons, other interpreters, scheduled tasks, services, credential-access alerts.',
      why: 'PowerShell is often one step in a chain. Related events show how the attacker got in and what they did next.',
      where: ['Alert queue', 'EDR timeline', 'Identity logs'],
      fields: ['Related alert IDs', 'Logon events', 'Persistence artifacts'],
      suspicious: ['Credential dumping, lateral movement, or persistence alerts on the same host', 'Same command on other hosts'],
      legitimate: ['No other unusual activity and a matching change ticket'],
      next: 'Proceed to the decision tree and record your recommendation.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'clearly-malicious',
    nodes: [
      {
        id: 'clearly-malicious',
        question: 'Does the decoded content show clearly malicious behavior: download-and-execute from an untrusted source, AMSI/logging/AV tampering, credential-theft tooling, or connections to a known-bad destination?',
        yes: { next: 'impact', guidance: 'Treat as malicious execution.' },
        no: { next: 'approved', guidance: 'Check whether this is approved automation.' },
      },
      {
        id: 'approved',
        question: 'Is the command verified approved automation - known script or management-agent parent, expected service/admin account, consistent fleet-wide baseline, or a matching change ticket?',
        yes: { outcome: 'benign', guidance: 'Document the script owner, parent process, baseline result, and ticket. Suggest tuning to the detection owner if appropriate.' },
        no: { next: 'unusual', guidance: 'Not verified - assess how unusual it is.' },
      },
      {
        id: 'unusual',
        question: 'Is the command obfuscated or hidden, launched by an unusual parent (Office, browser, mshta, unexpected WMI/WinRM), or run by an account that does not normally use PowerShell?',
        yes: { outcome: 'escalate', guidance: 'Unexplained obfuscated or oddly launched interpreter activity meets the Tier 2 threshold. Include the decoded text and lineage.' },
        no: { outcome: 'investigate', guidance: 'Readable, low-risk command that is not yet verified. Confirm with the owner; escalate if verification is not possible within your SLA.' },
      },
      {
        id: 'impact',
        question: 'Is there evidence of credential access, lateral movement, or the same malicious command on more than one host?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now. List all affected hosts and accounts.' },
        no: { outcome: 'escalate', guidance: 'Malicious execution on a single host. Escalate with the decoded command, lineage, network destinations, and files.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('hostname', true),
    ev('username', true, 'Account that ran the interpreter; note if SYSTEM or a service account.'),
    ev('process', true, 'powershell.exe / pwsh.exe / cmd.exe with PID.'),
    ev('parent_process', true),
    ev('command_line', true, 'Exact original command line.'),
    evCustom('decoded_command', 'Decoded command / script block summary', 'Plain-language summary first, then key decoded lines. Never execute.', true, true),
    ev('destination', false, 'URLs, domains, IPs contacted by the process.'),
    ev('file_hash', false, 'Files written or downloaded by the process.'),
    evCustom('baseline', 'Baseline result', 'Device count, accounts, first/last seen for the same command.', false),
    ev('event_ids', false, 'e.g. 4104 ScriptBlockId values, EDR ReportIds.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Decoded content downloads and executes code from an external or untrusted source.',
      'AMSI, script logging, Defender, or other security control tampering is present.',
      'Obfuscated/encoded command that you cannot fully decode or attribute to approved automation.',
      'PowerShell/cmd launched by Office, a browser, mshta.exe, or an unexplained remote-management parent.',
      'Command ran under a privileged account outside a documented change.',
    ],
    immediate: [
      'Credential-theft tooling or LSASS access associated with the script.',
      'The same malicious command observed on multiple hosts (possible scripted deployment by an attacker).',
      'Execution on a domain controller or other tier-0 system without a change record.',
    ],
    benignClosure: [
      'Script or command traced to an approved owner, inventory entry, or change ticket.',
      'Launched by the expected management agent or administrator account, with a consistent fleet-wide baseline.',
      'No suspicious network, file, or persistence activity from the process.',
    ],
  },
  queries: [
    {
      id: 'kql-pwsh-cmdline',
      title: 'Risky PowerShell command-line patterns on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Flags PowerShell executions on the host with encoded commands, download cradles, in-memory execution, or hidden windows, and shows the parent process.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| extend Encoded = ProcessCommandLine matches regex @"(?i)\\s[-/]e(c|n[a-z]*)?\\s"
| extend Download = ProcessCommandLine has_any ("DownloadString", "DownloadFile",
        "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "Start-BitsTransfer")
| extend InMemory = ProcessCommandLine has_any ("Invoke-Expression", "IEX")
| extend Hidden = ProcessCommandLine matches regex @"(?i)[-/]w[a-z]*\\s+h"
| where Encoded or Download or InMemory or Hidden
| project Timestamp, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine, ProcessId,
          Encoded, Download, InMemory, Hidden
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [
        { name: 'Encoded / Download / InMemory / Hidden', meaning: 'Which risky pattern matched (computed columns).' },
        { name: 'InitiatingProcessFileName', meaning: 'Parent process that launched PowerShell.' },
      ],
      positive: 'Each row is a PowerShell execution worth decoding and reviewing. Flags are common in admin tooling; a match is not a verdict.',
      negative: 'No rows does not mean PowerShell was not abused: the engine can be hosted inside other processes (System.Management.Automation.dll loaded by a non-PowerShell binary), and obfuscation can evade these strings.',
      prerequisites: 'Defender for Endpoint process telemetry; advanced hunting or Sentinel read access.',
      schemaNotes: 'Regex flags are approximations of PowerShell parameter abbreviations. In Sentinel, Timestamp exists for Defender tables; TimeGenerated can also be used.',
      example: 'hostname = ws-demo-0142.corp.example.com, lookback = 24h',
    },
    {
      id: 'kql-scriptblock',
      title: 'PowerShell script block logs (4104) for a host',
      language: 'kql',
      platform: 'Microsoft Sentinel (Windows events via Azure Monitor Agent)',
      purpose: 'Retrieves de-obfuscated script block text logged by PowerShell on the host.',
      dataSources: ['WindowsEvent (Microsoft-Windows-PowerShell/Operational)'],
      query: `WindowsEvent
| where TimeGenerated > ago({{lookback}})
| where Provider == "Microsoft-Windows-PowerShell" and EventID == 4104
| where Computer =~ "{{hostname}}"
| extend ScriptBlockText = tostring(EventData.ScriptBlockText),
         ScriptBlockId = tostring(EventData.ScriptBlockId),
         ScriptPath = tostring(EventData.Path)
| project TimeGenerated, Computer, ScriptBlockId, ScriptPath, ScriptBlockText
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [
        { name: 'ScriptBlockText', meaning: 'Script content as PowerShell compiled it - often already de-obfuscated.' },
        { name: 'ScriptBlockId', meaning: 'Long scripts are split into multiple events with the same ID; read them together.' },
      ],
      positive: 'Shows what the script actually contained. Use it to confirm intent.',
      negative: 'Empty results usually mean script block logging is not enabled or the channel is not collected - record this as a visibility gap.',
      prerequisites: 'Script block logging policy enabled; Data Collection Rule collecting Microsoft-Windows-PowerShell/Operational.',
      schemaNotes: 'If your workspace uses the legacy Log Analytics agent, events land in the Event table with EventData as XML; parse with extract(@\'<Data Name="ScriptBlockText">([\\s\\S]*?)</Data>\', 1, EventData). Computer may be FQDN.',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'spl-pwsh-endpoint',
      title: 'PowerShell with encoding, download, or hidden-window flags (CIM)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds PowerShell processes with risky flags across all hosts so you can compare against the baseline.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen
    values(Processes.process) as command_lines values(Processes.parent_process_name) as parents
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}}
      (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe")
      (Processes.process="* -enc*" OR Processes.process="* -e *" OR Processes.process="* -ec *"
       OR Processes.process="*-encodedcommand*" OR Processes.process="*downloadstring*"
       OR Processes.process="*frombase64string*" OR Processes.process="*-w hidden*"
       OR Processes.process="*-windowstyle hidden*" OR Processes.process="*invoke-webrequest*")
    by Processes.dest Processes.user
| convert ctime(first_seen) ctime(last_seen)
| sort - count`,
      placeholders: [PH.lookback('30d')],
      keyFields: [
        { name: 'count / first_seen', meaning: 'High counts across many hosts suggest automation; single recent rows deserve attention.' },
        { name: 'parents', meaning: 'Parent processes seen for this host/user.' },
      ],
      positive: 'Lists hosts/users with risky PowerShell usage. Use it as baseline context for the alerted host.',
      negative: 'Empty output can mean command lines are not collected or not mapped to Processes.process.',
      prerequisites: 'Process data in CIM Endpoint.Processes with command lines.',
      schemaNotes: 'String matching in tstats where-clauses is case-insensitive for most configurations; verify in your environment.',
      example: 'lookback = 30d',
    },
    {
      id: 'spl-scriptblock',
      title: 'Script block logging (4104) on a host',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Retrieves script block text for the host around the alert.',
      dataSources: ['Microsoft-Windows-PowerShell/Operational, EventCode 4104'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
    EventCode=4104 host="{{hostname}}" earliest=-{{lookback}}
| table _time host ScriptBlockId Path ScriptBlockText
| sort _time`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Index holding Windows event logs (ask your Splunk admin).', example: 'wineventlog' },
        PH.hostname(),
        PH.lookback('24h'),
      ],
      keyFields: [{ name: 'ScriptBlockText', meaning: 'Script content; reassemble multi-part blocks by ScriptBlockId.' }],
      positive: 'Readable script content to confirm intent.',
      negative: 'No events usually means logging is disabled or not forwarded.',
      prerequisites: 'Script block logging enabled and the PowerShell Operational channel forwarded.',
      schemaNotes: 'Source may be "WinEventLog:Microsoft-Windows-PowerShell/Operational" when events are collected in classic (non-XML) format.',
      example: 'index = wineventlog, hostname = WS-DEMO-0142',
    },
    {
      id: 'generic-pwsh',
      title: 'Generic interpreter investigation procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral steps for PowerShell and cmd.exe alerts.',
      dataSources: ['Process creation', 'PowerShell Operational log', 'Network connections'],
      query: `1. Pull the full command line, parent, grandparent, user, and integrity level.
2. Decode -EncodedCommand as base64 -> UTF-16LE in an offline tool; repeat for nested layers.
3. Search the PowerShell Operational log (4104) on the host +/- 15 minutes.
4. List network connections and file writes by the same process ID.
5. Count how many hosts ran the same command in the last 30 days.
6. Record sources searched and time ranges.`,
      placeholders: [],
      keyFields: [],
      positive: 'Findings are leads to evaluate in the decision tree.',
      negative: 'Absence of script block logs is a visibility gap, not proof of benign activity.',
      prerequisites: 'Process telemetry with command lines.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Many legitimate management tools use -EncodedCommand and -ExecutionPolicy Bypass - baseline before judging.',
    'PowerShell can run without powershell.exe (hosted runspaces in other binaries); watch for System.Management.Automation.dll loads by unusual processes.',
    'Script block logging captures de-obfuscated content and is the single most valuable source for this playbook.',
  ],
  visibilityGaps: [
    'PowerShell 2.0 engine (if still installed) bypasses script block logging.',
    'Command-line auditing for 4688 is off by default.',
    'Constrained Language Mode and AMSI events are not always forwarded.',
  ],
  relatedTechniques: [
    { id: 'T1027.010', reason: 'Command obfuscation is commonly used with PowerShell.' },
    { id: 'T1105', reason: 'Download cradles transfer tools onto the host.' },
    { id: 'T1047', reason: 'WMI is often used to launch PowerShell remotely.' },
    { id: 'T1021.006', reason: 'WinRM / PowerShell remoting enables remote execution.' },
    { id: 'T1685', reason: 'Scripts frequently disable or modify security tools.' },
    { id: 'T1140', reason: 'Scripts decode or decrypt payloads at runtime.' },
  ],
  references: [
    attackRef('T1059.001', 'PowerShell'),
    { title: 'Microsoft Learn - about_Logging_Windows (script block logging)', url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows' },
    { title: 'Microsoft Learn - about_PowerShell_exe (parameters)', url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe' },
    { title: 'Microsoft Learn - DeviceProcessEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table' },
  ],
  assumptions: [
    'An inventory of approved admin scripts exists or can be obtained from the platform team.',
    'Decoding is done offline with an approved tool; suspicious content is never executed.',
  ],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

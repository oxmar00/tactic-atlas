import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const lateralMovement: Playbook = {
  schemaVersion: 1,
  id: 'PB-LATMOVE-001',
  version: '1.0.0',
  title: 'Remote services and possible lateral movement (RDP, SMB/admin shares, WinRM)',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1021', 'T1021.001', 'T1021.002', 'T1021.006'],
  tactics: ['lateral-movement'],
  objective:
    'Map the source, destination, account, and protocol of the remote connection; find what was executed on the destination; and decide whether it is approved administration or an attacker moving between systems.',
  alertMeaning:
    'A detection flagged a remote logon or remote execution pattern: RDP from an unusual source, administrative share (ADMIN$/C$) access, a service installed remotely (PsExec-like), WinRM/PowerShell remoting, or one host connecting to many others.',
  whyItMatters:
    'Lateral movement means an intrusion is spreading beyond the first host. The earlier it is confirmed, the fewer systems need to be contained and rebuilt.',
  difficulty: 'Advanced',
  effort: '45-90 minutes',
  platforms: ['Windows'],
  logSources: ['mde', 'win-security', 'edr', 'firewall', 'sysmon', 'vpn'],
  alertContext: {
    triggers: [
      'Network logon (4624 LogonType 3) with admin rights from a workstation to another workstation.',
      'RDP logon (LogonType 10) from an unexpected source or account.',
      'Service installation (7045/4697) shortly after a network logon, e.g. PSEXESVC or a random service name.',
      'wsmprovhost.exe (WinRM) spawning processes; ADMIN$/C$ writes (5140/5145).',
      'One source connecting to many hosts over 445/3389/5985 in a short time.',
    ],
    reviewFirst: ['Source host/IP, destination host, account, protocol/port, and time.', 'Whether the account is an administrator on the destination.', 'Whether the source host has its own alerts.'],
    oftenMissing: ['What ran on the destination after the logon.', 'Which process on the source initiated the connection.', 'Whether this source-destination pair has ever been seen before.'],
  },
  prerequisites: [
    { text: 'Logon events on destination hosts (4624/4672 or EDR logon events).', type: 'telemetry', required: true },
    { text: 'EDR or Sysmon on both source and destination to see processes and connections.', type: 'telemetry', required: true },
    { text: 'System log 7045 / Security 4697 for service installs; 5140/5145 for share access.', type: 'telemetry', required: false },
    { text: 'List of approved jump hosts/PAWs, admin accounts, and management servers.', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'map',
      title: 'Map the connection: who, from where, to where, how',
      action:
        'Record source host and IP, destination host, account (and domain), protocol and port (RDP 3389, SMB 445, WinRM 5985/5986), logon type, authentication package (Kerberos/NTLM), and time.',
      why: 'Every later check depends on knowing both ends of the connection and the account used.',
      where: ['DeviceLogonEvents', 'Security 4624/4672 on destination', 'DeviceNetworkEvents on source', 'Firewall logs'],
      fields: ['AccountName', 'LogonType', 'RemoteIP', 'RemoteDeviceName', 'Protocol', 'IsLocalAdmin', 'AuthenticationPackageName'],
      suspicious: ['Workstation-to-workstation admin logon', 'NTLM network logon by an admin account where Kerberos is expected', 'Source IP is a VPN address assigned to a different user'],
      legitimate: ['Source is an approved jump host / PAW / management server'],
      next: 'Check what happened on the destination after the logon.',
      queryIds: ['kql-remote-logons', 'spl-remote-logons'],
    },
    {
      id: 'destination-activity',
      title: 'Find remote execution artifacts on the destination',
      action:
        'In the minutes after the logon, look for: services installed (7045/4697) - especially PSEXESVC or random names with binaries in ADMIN$/Windows; files written over SMB to ADMIN$/C$; processes started by services.exe, wsmprovhost.exe, or WmiPrvSE.exe; scheduled tasks created; RDP session activity (explorer, cmd, browsers).',
      why: 'A logon alone may be benign; remote execution right after it is the hallmark of lateral movement tools.',
      where: ['DeviceEvents ServiceInstalled', 'DeviceFileEvents with RequestSourceIP', 'System 7045 / Security 4697, 5140, 5145', 'DeviceProcessEvents'],
      fields: ['ServiceName', 'ImagePath / FolderPath', 'RequestSourceIP', 'RequestAccountName', 'ShareName', 'RelativeTargetName', 'Child processes'],
      suspicious: ['Service binary in C:\\Windows\\ with a random 8-character name', 'Executable written to ADMIN$ then run as a service', 'wsmprovhost.exe launching cmd/powershell with discovery commands'],
      legitimate: ['Software deployment service from the management server (documented service name)'],
      next: 'Record each artifact with timestamps.',
      queryIds: ['kql-destination-artifacts', 'spl-service-installs', 'spl-admin-shares'],
    },
    {
      id: 'source-review',
      title: 'Review the source host',
      action:
        'On the source, find the process that initiated the connection (mstsc.exe, psexec*.exe, powershell Enter-PSSession/Invoke-Command, wmic, sc.exe \\\\host, net use). Check the source host for alerts, recent suspicious logons, and credential-access indicators. Look for 4648 (explicit credentials) or LogonType 9 sessions.',
      why: 'If the source is compromised it is the attacker\'s current foothold, and the credentials used are likely stolen.',
      where: ['DeviceNetworkEvents InitiatingProcess*', 'DeviceProcessEvents on source', 'Security 4648', 'Alert queue'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'Account on source', 'Related alerts'],
      suspicious: ['psexec / remote-exec tooling not used by IT', 'Source has credential-dumping or malware alerts', 'Explicit-credential logons using a different admin account'],
      legitimate: ['IT admin on their PAW using mstsc.exe during a ticketed task'],
      next: 'If the source is unmanaged or not covered by EDR, record it as a visibility gap.',
      queryIds: ['kql-fanout'],
    },
    {
      id: 'legitimacy',
      title: 'Check against approved administration',
      action:
        'Compare the source, account, destination, and time with the approved jump host list, admin account inventory, change tickets, and the account\'s history (has this account connected from this source to this destination before?).',
      why: 'Administrators legitimately use the same protocols. First-time pairs and off-pattern accounts stand out.',
      where: ['Change management system', 'Admin account inventory', 'DeviceLogonEvents history (30 days)'],
      fields: ['Ticket', 'Prior occurrences of the source-destination-account combination'],
      suspicious: ['First time this account accessed the destination', 'Standard user or service account performing remote admin actions'],
      legitimate: ['Routine pattern with ticket coverage'],
      next: 'Proceed to scope.',
      queryIds: ['kql-remote-logons'],
    },
    {
      id: 'scope',
      title: 'Scope fan-out and account usage',
      action:
        'Determine whether the source connected to other hosts on the same ports, and whether the account logged on to other hosts in the same period.',
      why: 'Attackers commonly sweep many hosts. The number of destinations sets the urgency.',
      where: ['DeviceNetworkEvents by source', 'DeviceLogonEvents by account', 'Firewall logs'],
      fields: ['Destination count', 'Destination list', 'Time span'],
      suspicious: ['Connections to many hosts within minutes', 'Account active on servers it never used before'],
      legitimate: ['Management server connecting to its normal fleet'],
      next: 'Use the decision tree.',
      queryIds: ['kql-fanout'],
    },
  ],
  decisionTree: {
    start: 'approved',
    nodes: [
      {
        id: 'approved',
        question: 'Is the connection from an approved admin source (jump host/PAW/management server) with the expected admin account, matching a ticket or routine pattern, with nothing suspicious on the destination?',
        yes: { outcome: 'benign', guidance: 'Record source, account, ticket/pattern evidence.' },
        no: { next: 'execution', guidance: 'Not verified as approved administration.' },
      },
      {
        id: 'execution',
        question: 'Did the destination show remote execution artifacts after the logon (new service, files written to ADMIN$/C$, WinRM/WMI/service children, unexpected RDP session activity)?',
        yes: { next: 'scale', guidance: 'Remote execution occurred.' },
        no: { next: 'unusual', guidance: 'Logon without execution artifacts so far.' },
      },
      {
        id: 'unusual',
        question: 'Is it a first-time source-destination pair, a workstation-to-workstation admin logon, or an account that does not normally administer this host?',
        yes: { outcome: 'escalate', guidance: 'Unexplained remote admin access is a lateral-movement indicator even without visible execution. Escalate with the connection map.' },
        no: { outcome: 'investigate', guidance: 'Pattern is not obviously anomalous but not verified. Confirm with the account owner; escalate if unverified.' },
      },
      {
        id: 'scale',
        question: 'Does the source fan out to multiple hosts, use privileged/domain admin credentials, or show credential-theft indicators?',
        yes: { outcome: 'critical', guidance: 'Active lateral movement. Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Remote execution between two hosts. Escalate with source, destination, account, and artifacts.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    evCustom('source_host', 'Source host / IP', 'Hostname, IP, and whether EDR-covered.', true),
    ev('hostname', true, 'Destination host.'),
    ev('username', true),
    ev('auth_outcome', true, 'LogonType, authentication package (Kerberos/NTLM), admin rights.'),
    evCustom('protocol', 'Protocol / port', 'RDP 3389, SMB 445, WinRM 5985/5986, RPC 135.', true),
    evCustom('remote_artifacts', 'Destination artifacts', 'Services, ADMIN$ files, child processes, tasks (one per line).', false, true),
    ev('command_line', false, 'Initiating command on the source, if found.'),
    ev('affected_assets', false, 'Other destinations from the same source / account.'),
    ev('event_ids', false, 'e.g. 4624, 4672, 7045, 5145 records.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Remote execution artifacts (service install, ADMIN$ payload, WinRM/WMI execution) not attributable to approved administration.',
      'Workstation-to-workstation administrative logons.',
      'First-time use of an admin account from an unexpected source.',
      'Source host has related alerts or is not covered by EDR.',
    ],
    immediate: [
      'One source connecting to and executing on multiple hosts.',
      'Domain admin or other tier-0 credentials used from a non-PAW source.',
      'Lateral movement following credential-dumping indicators.',
    ],
    benignClosure: ['Approved source, expected admin account, documented ticket or routine pattern.', 'No unexpected artifacts on the destination.'],
  },
  queries: [
    {
      id: 'kql-remote-logons',
      title: 'Remote logons to a destination host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Summarizes network and RDP logons to the destination by account, source, and protocol.',
      dataSources: ['DeviceLogonEvents'],
      query: `DeviceLogonEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive")
| summarize Logons = count(), First = min(Timestamp), Last = max(Timestamp)
          by AccountDomain, AccountName, LogonType, RemoteIP, RemoteDeviceName, Protocol, IsLocalAdmin
| order by First asc`,
      placeholders: [PH.lookback('7d'), PH.hostname()],
      keyFields: [
        { name: 'IsLocalAdmin', meaning: 'Whether the account had local admin rights.' },
        { name: 'Protocol', meaning: 'Authentication protocol (e.g. NTLM, Kerberos).' },
        { name: 'First', meaning: 'Pairs first seen near the alert are new.' },
      ],
      positive: 'Shows who connected remotely and from where.',
      negative: 'Logons from unmanaged or non-Windows sources may lack RemoteDeviceName; some network logons are not recorded by the sensor.',
      prerequisites: 'Defender for Endpoint on the destination.',
      schemaNotes: 'LogonType values are strings in Defender (Network, RemoteInteractive, Interactive, ...).',
      example: 'hostname = srv-demo-app01.corp.example.com',
    },
    {
      id: 'kql-destination-artifacts',
      title: 'Services installed and files written remotely on a destination',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Combines service installations and files created over the network (SMB) on the destination into one timeline.',
      dataSources: ['DeviceEvents (ServiceInstalled)', 'DeviceFileEvents (RequestSourceIP)'],
      query: `let host = "{{hostname}}";
let since = ago({{lookback}});
let services = DeviceEvents
    | where Timestamp > since and DeviceName =~ host and ActionType == "ServiceInstalled"
    | extend Fields = parse_json(AdditionalFields)
    | project Timestamp, Kind = "ServiceInstalled", Item = tostring(Fields.ServiceName),
              Detail = FolderPath, Account = tostring(Fields.ServiceAccount), Source = "";
let remoteFiles = DeviceFileEvents
    | where Timestamp > since and DeviceName =~ host
    | where isnotempty(RequestSourceIP)
    | project Timestamp, Kind = strcat("RemoteFile:", ActionType), Item = FileName,
              Detail = FolderPath, Account = RequestAccountName, Source = RequestSourceIP;
union services, remoteFiles
| order by Timestamp asc`,
      placeholders: [PH.hostname(), PH.lookback('24h')],
      keyFields: [
        { name: 'Kind', meaning: 'ServiceInstalled or RemoteFile:<action>.' },
        { name: 'Source / Account', meaning: 'Remote IP and account that wrote the file over SMB.' },
      ],
      positive: 'A file written remotely followed by a service using it is strong evidence of remote execution.',
      negative: 'RequestSourceIP is only populated for some network file operations; absence does not prove no remote write.',
      prerequisites: 'Defender for Endpoint on the destination.',
      schemaNotes: 'AdditionalFields properties for ServiceInstalled (ServiceName, ServiceAccount, ...) should be verified in your tenant.',
      example: 'hostname = srv-demo-app01.corp.example.com, lookback = 24h',
    },
    {
      id: 'kql-fanout',
      title: 'Fan-out from a source host over admin protocols',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Counts distinct destinations the source connected to on SMB, RDP, WinRM, and RPC, by initiating process.',
      dataSources: ['DeviceNetworkEvents'],
      query: `DeviceNetworkEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{source_host}}"
| where ActionType == "ConnectionSuccess" and RemotePort in (135, 445, 3389, 5985, 5986)
| summarize Targets = dcount(RemoteIP), TargetList = make_set(RemoteIP, 50),
            Ports = make_set(RemotePort), First = min(Timestamp), Last = max(Timestamp)
            by InitiatingProcessFileName, InitiatingProcessAccountName
| order by Targets desc`,
      placeholders: [{ name: 'source_host', kind: 'string', description: 'Source device name.', example: 'ws-demo-0099.corp.example.com' }, PH.lookback('24h')],
      keyFields: [
        { name: 'Targets', meaning: 'Number of distinct destinations.' },
        { name: 'InitiatingProcessFileName', meaning: 'Process making the connections (mstsc.exe, powershell.exe, unknown tools).' },
      ],
      positive: 'Many targets from an unusual process/account is a strong lateral-movement indicator.',
      negative: 'Connections from an unmanaged source are not visible here; use firewall logs.',
      prerequisites: 'Defender for Endpoint on the source host.',
      schemaNotes: 'System processes (e.g. "System" for SMB) may appear as the initiator for kernel-mode connections.',
      example: 'source_host = ws-demo-0099.corp.example.com',
    },
    {
      id: 'spl-remote-logons',
      title: 'Network and RDP logons to a host (Windows Security)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Summarizes 4624 LogonType 3 and 10 logons to the destination, excluding computer accounts.',
      dataSources: ['Windows Security EventCode 4624'],
      query: `index="{{index}}" source="*:Security" EventCode=4624 host="{{hostname}}" earliest=-{{lookback}}
    (LogonType=3 OR LogonType=10)
| where NOT like(TargetUserName, "%$")
| stats count min(_time) as first_seen max(_time) as last_seen
    by TargetUserName IpAddress WorkstationName LogonType AuthenticationPackageName
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Windows Security events.', example: 'wineventlog' }, PH.hostname(), PH.lookback('7d')],
      keyFields: [{ name: 'IpAddress / WorkstationName', meaning: 'Source of the logon.' }, { name: 'AuthenticationPackageName', meaning: 'NTLM vs Kerberos.' }],
      positive: 'Remote logons to evaluate against approved admin sources.',
      negative: 'Requires the destination\'s Security log in Splunk; many workstation logs are not collected.',
      prerequisites: 'Logon auditing; Security log forwarded.',
      schemaNotes: 'Classic (non-XML) collection uses Logon_Type and Source_Network_Address; adjust field names.',
      example: 'index = wineventlog, hostname = SRV-DEMO-APP01',
    },
    {
      id: 'spl-service-installs',
      title: 'Services installed (System 7045)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Lists services installed on the host with their binary path.',
      dataSources: ['Windows System EventCode 7045'],
      query: `index="{{index}}" source="*:System" EventCode=7045 host="{{hostname}}" earliest=-{{lookback}}
| table _time host ServiceName ImagePath ServiceType StartType AccountName
| sort _time`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Windows System events.', example: 'wineventlog' }, PH.hostname(), PH.lookback('7d')],
      keyFields: [{ name: 'ImagePath', meaning: 'Service binary or command; look for ADMIN$-staged files, cmd /c, powershell.' }],
      positive: 'Services created right after a remote logon are a PsExec-style indicator.',
      negative: 'Service creation via other methods may only appear in 4697 (Security) or EDR.',
      prerequisites: 'System log forwarded.',
      schemaNotes: 'Field names follow XML rendering; classic rendering differs (Service_Name, Service_File_Name).',
      example: 'hostname = SRV-DEMO-APP01',
    },
    {
      id: 'spl-admin-shares',
      title: 'Administrative share access (5140/5145)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Shows access to ADMIN$ and C$ shares and the files touched.',
      dataSources: ['Windows Security EventCodes 5140, 5145'],
      query: `index="{{index}}" source="*:Security" (EventCode=5140 OR EventCode=5145) earliest=-{{lookback}}
    (ShareName="*ADMIN$" OR ShareName="*C$")
| stats count min(_time) as first_seen values(RelativeTargetName) as files
    by host SubjectUserName IpAddress ShareName
| convert ctime(first_seen)`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Windows Security events.', example: 'wineventlog' }, PH.lookback('24h')],
      keyFields: [{ name: 'files', meaning: 'Executables written to ADMIN$ are a strong indicator.' }],
      positive: 'Admin share use from workstations or unusual accounts needs explanation.',
      negative: 'Requires "Audit File Share" / "Audit Detailed File Share" - often disabled.',
      prerequisites: 'File share auditing enabled.',
      schemaNotes: 'ShareName values look like \\\\*\\ADMIN$.',
      example: 'index = wineventlog',
    },
    {
      id: 'generic-latmove',
      title: 'Generic lateral-movement procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Logon events', 'Service/file/process events', 'Network flows'],
      query: `1. Destination: 4624 type 3/10 for the account; source IP; admin rights; NTLM/Kerberos.
2. Destination +15 min: services installed, files written to ADMIN$/C$, processes under
   services.exe / wsmprovhost.exe / WmiPrvSE.exe, scheduled tasks.
3. Source: process that opened the connection; other alerts; explicit-credential logons.
4. Approved admin? Jump host list, admin inventory, tickets, 30-day history of the pair.
5. Fan-out: distinct destinations from the source on 445/3389/5985/135.`,
      placeholders: [],
      keyFields: [],
      positive: 'Execution artifacts plus unusual pairs indicate lateral movement.',
      negative: 'Missing workstation logs are a common gap - record it.',
      prerequisites: 'Logon and endpoint telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Admins use the same protocols; maintain an approved source/account list to reduce noise.',
    'Pass-the-hash shows as NTLM network logons; on the source, LogonType 9 with logon process seclogo is a known indicator.',
  ],
  visibilityGaps: ['Workstation Security logs are often not centralized.', 'Attacker-controlled or unmanaged sources have no EDR telemetry.'],
  relatedTechniques: [
    { id: 'T1570', reason: 'Tools are copied to the destination before execution.' },
    { id: 'T1569.002', reason: 'Service execution is how PsExec-like tools run payloads.' },
    { id: 'T1550.002', reason: 'Pass-the-hash enables remote logons with stolen NTLM hashes.' },
    { id: 'T1047', reason: 'WMI is another common remote execution channel.' },
    { id: 'T1003', reason: 'Credential theft usually precedes lateral movement.' },
  ],
  references: [
    attackRef('T1021', 'Remote Services'),
    attackRef('T1021.002', 'SMB/Windows Admin Shares'),
    { title: 'Microsoft Learn - DeviceLogonEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table' },
    { title: 'Microsoft Learn - 4624(S): An account was successfully logged on', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624' },
  ],
  assumptions: ['An approved list of admin sources and accounts is available from the infrastructure team.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

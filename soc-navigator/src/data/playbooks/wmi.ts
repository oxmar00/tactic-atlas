import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const wmi: Playbook = {
  schemaVersion: 1,
  id: 'PB-WMI-001',
  version: '1.0.0',
  title: 'Suspicious Windows Management Instrumentation (WMI) activity',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1047', 'T1546.003'],
  tactics: ['execution', 'persistence'],
  objective:
    'Classify the WMI activity (query, process creation, or event subscription), determine whether it came from another host, and decide whether it is legitimate management or attacker execution/persistence.',
  alertMeaning:
    'A detection saw WMI used to start a process (often on a remote host), a WMI provider host (WmiPrvSE.exe) spawning a shell, or a permanent WMI event subscription being registered.',
  whyItMatters:
    'WMI lets administrators - and attackers - run commands on remote machines without copying files, and permanent event subscriptions provide stealthy persistence that survives reboots.',
  difficulty: 'Intermediate',
  effort: '30-60 minutes',
  platforms: ['Windows'],
  logSources: ['mde', 'sysmon', 'wmi-activity', 'win-security', 'edr', 'firewall'],
  alertContext: {
    triggers: [
      'WmiPrvSE.exe launched cmd.exe, powershell.exe, or an unknown binary.',
      'wmic.exe with /node: or process call create; PowerShell Invoke-WmiMethod / Invoke-CimMethod against Win32_Process with -ComputerName.',
      'WMI permanent event subscription registered (WMI-Activity 5861, Sysmon 19/20/21, or EDR WmiBindEventFilterToConsumer).',
    ],
    reviewFirst: [
      'Which host is the target (where WmiPrvSE.exe ran the command) and which is the source (where the command was issued).',
      'Account used and the exact command executed.',
      'For subscriptions: filter query, consumer type, and consumer command/script.',
    ],
    oftenMissing: [
      'The source host - the target only shows a network logon and WmiPrvSE.exe.',
      'Command output (attackers often redirect it to a file on ADMIN$).',
    ],
  },
  prerequisites: [
    { text: 'Process creation telemetry on the target host (EDR or Sysmon 1).', type: 'telemetry', required: true },
    { text: 'Logon events (4624) on the target to identify the remote source.', type: 'telemetry', required: true },
    { text: 'WMI-Activity Operational or Sysmon 19-21 for event subscriptions.', type: 'telemetry', required: false },
    { text: 'List of management/monitoring servers that legitimately use WMI.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'classify',
      title: 'Classify the WMI activity',
      action:
        'Decide which of three patterns you are looking at: (1) querying information (inventory, monitoring), (2) creating a process through WMI (Win32_Process Create), or (3) a permanent event subscription (filter + consumer + binding). Record the pattern.',
      why: 'Querying is extremely common and usually benign. Process creation and subscriptions carry much more risk and need different checks.',
      where: ['EDR alert details', 'DeviceProcessEvents', 'DeviceEvents', 'Sysmon 1, 19-21'],
      fields: ['InitiatingProcessFileName', 'FileName', 'ProcessCommandLine', 'ActionType'],
      suspicious: ['WmiPrvSE.exe parent of cmd.exe/powershell.exe', 'Subscription consumer of type CommandLineEventConsumer or ActiveScriptEventConsumer'],
      legitimate: ['Monitoring agent querying Win32_Service or performance counters', 'SCCM/Intune inventory'],
      next: 'For process creation go to the remote-source step; for subscriptions go to the persistence step.',
      queryIds: ['kql-wmiprvse-children', 'spl-wmiprvse-children'],
    },
    {
      id: 'remote-source',
      title: 'Find where the WMI command came from',
      action:
        'On the target host, look for a successful network logon (4624 LogonType 3) for the same account just before WmiPrvSE.exe started the process. Record the source IP/host. On the source host, look for wmic.exe /node:, PowerShell WMI/CIM cmdlets with -ComputerName, or tools that use WMI for remote execution.',
      why: 'Remote WMI execution is a common lateral-movement method. The source host may be the attacker\'s current foothold and must be investigated too.',
      where: ['DeviceLogonEvents / Security 4624 on target', 'DeviceProcessEvents on source', 'Firewall logs (RPC 135 then high ports)'],
      fields: ['LogonType', 'RemoteIP', 'RemoteDeviceName', 'AccountName', 'Source ProcessCommandLine'],
      suspicious: ['Workstation-to-workstation WMI execution', 'Account is a regular user or a service account used outside its normal servers', 'Source host has other alerts'],
      legitimate: ['Source is a known management server and account is its documented service account'],
      next: 'Add the source host to affected assets. Review the command that ran next.',
      queryIds: ['kql-wmi-source'],
    },
    {
      id: 'command-review',
      title: 'Review the command executed through WMI',
      action:
        'Read the child process command line. Look for output redirection to an admin share (a pattern such as cmd.exe /Q /c <command> 1> \\\\127.0.0.1\\ADMIN$\\__<number> 2>&1 is typical of remote-execution tooling), encoded PowerShell, discovery commands, or downloads.',
      why: 'The command shows intent: discovery (whoami, net group), credential access, payload download, or service changes.',
      where: ['DeviceProcessEvents (children of WmiPrvSE.exe)', 'Sysmon 1', 'Security 4688'],
      fields: ['ProcessCommandLine', 'AccountName', 'FileName', 'SHA256'],
      suspicious: ['Output redirected to \\\\127.0.0.1\\ADMIN$', 'whoami, net user /domain, nltest, ipconfig run in sequence', 'powershell -enc or downloads from external hosts'],
      legitimate: ['Known software deployment command from the management server'],
      next: 'Record each command. If PowerShell was launched, also apply the PowerShell playbook.',
      queryIds: ['kql-wmiprvse-children'],
    },
    {
      id: 'persistence',
      title: 'Check for WMI event subscription persistence',
      action:
        'Search for new event filters, consumers, and bindings on the host. Record the filter query (what triggers it), consumer type, and the command or script the consumer runs. Check for scrcons.exe (script consumer host) executions.',
      why: 'A permanent subscription can re-launch attacker code at startup or on a timer and is easy to overlook.',
      where: ['DeviceEvents ActionType WmiBindEventFilterToConsumer', 'Sysmon 19/20/21', 'WMI-Activity 5861'],
      fields: ['Filter Name / Query', 'Consumer Name / Type / Destination', 'User'],
      suspicious: ['CommandLineEventConsumer running powershell, cmd, or a binary in a user-writable path', 'ActiveScriptEventConsumer with VBScript/JScript', 'Filter on __InstanceModificationEvent within Win32_PerfFormattedData (timer-like trigger)'],
      legitimate: ['Subscriptions created by known security or monitoring software (verify vendor documentation)'],
      next: 'Any unexplained subscription is an escalation criterion.',
      queryIds: ['kql-wmi-subscription', 'spl-wmi-sysmon'],
    },
    {
      id: 'scope',
      title: 'Scope the source and account across the environment',
      action:
        'Check whether the same source host or account executed WMI commands on other hosts, and whether the account logged on to unusual systems in the last 7 days.',
      why: 'Attackers often run the same WMI command against many hosts. Scope determines urgency.',
      where: ['DeviceProcessEvents (WmiPrvSE children) across devices', 'DeviceLogonEvents by account', 'Alert queue'],
      fields: ['Target host list', 'Account logon history'],
      suspicious: ['Same command on multiple hosts within minutes', 'Account authenticating to many hosts it never used before'],
      legitimate: ['Activity limited to the management server\'s normal target set'],
      next: 'Record every affected host, then use the decision tree.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'query-only',
    nodes: [
      {
        id: 'query-only',
        question: 'Is the activity only WMI querying/inventory by a known management or monitoring tool, with no process creation and no event subscription?',
        yes: { outcome: 'benign', guidance: 'Record the tool, server, and account. Suggest tuning if the alert recurs.' },
        no: { next: 'subscription', guidance: 'Execution or persistence is involved.' },
      },
      {
        id: 'subscription',
        question: 'Was a permanent WMI event subscription (filter/consumer/binding) created that is not from verified security or monitoring software?',
        yes: { next: 'spread', guidance: 'Unexplained WMI persistence.' },
        no: { next: 'shell', guidance: 'Check the process-creation path.' },
      },
      {
        id: 'shell',
        question: 'Did WMI create a shell, interpreter, or unknown binary - especially from a remote source or with output redirected to ADMIN$?',
        yes: { next: 'spread', guidance: 'Likely remote execution.' },
        no: { next: 'verified', guidance: 'Process creation without obvious malicious traits.' },
      },
      {
        id: 'verified',
        question: 'Can you verify the source host and account as approved administration (management server, documented service account, or change ticket)?',
        yes: { outcome: 'benign', guidance: 'Record the verification source.' },
        no: { outcome: 'investigate', guidance: 'Unverified WMI process creation. Continue checking source host activity; escalate if not verified within your SLA.' },
      },
      {
        id: 'spread',
        question: 'Is the activity hitting multiple hosts from one source, using a privileged/domain admin account, or followed by credential-access activity?',
        yes: { outcome: 'critical', guidance: 'Indicators of active lateral movement. Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Escalate with source host, account, command lines, and any subscription details.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('hostname', true, 'Target host where WmiPrvSE.exe ran the command.'),
    ev('src_ip', true, 'Source host/IP that issued the WMI request (from 4624 LogonType 3 or EDR).'),
    ev('username', true),
    ev('command_line', true, 'Command executed through WMI (child of WmiPrvSE.exe) or issued on the source.'),
    ev('auth_outcome', false, 'e.g. 4624 LogonType 3 success at 14:02:58Z'),
    evCustom('wmi_subscription', 'WMI subscription details', 'Filter name/query, consumer name/type, consumer command or script.', false, true),
    ev('affected_assets', false),
    ev('event_ids', false),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'WMI started a shell, interpreter, or unknown binary on a host and the source/account cannot be verified.',
      'Remote WMI execution between workstations.',
      'A permanent WMI event subscription not attributable to verified security/monitoring software.',
      'Command output redirected to ADMIN$ or other remote-execution tooling patterns.',
    ],
    immediate: [
      'The same source host or account executes WMI commands on multiple hosts.',
      'Privileged or domain administrator credentials used from an unexpected source.',
      'WMI execution followed by credential dumping or ransomware indicators.',
    ],
    benignClosure: [
      'Activity originates from a documented management/monitoring server and service account.',
      'Commands match known management operations or a change ticket.',
      'No subscription persistence and no suspicious child behavior.',
    ],
  },
  queries: [
    {
      id: 'kql-wmiprvse-children',
      title: 'Processes started by WmiPrvSE.exe on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists child processes of the WMI provider host, with a flag for output redirected to the local ADMIN$ share.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| extend OutputToAdminShare = ProcessCommandLine contains @"ADMIN$\\__"
| project Timestamp, AccountDomain, AccountName, FileName, ProcessCommandLine,
          SHA256, OutputToAdminShare
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [
        { name: 'AccountName', meaning: 'Account WMI executed as - usually the remote caller.' },
        { name: 'OutputToAdminShare', meaning: 'True when output is redirected to ADMIN$\\__..., a common remote-execution tool pattern.' },
      ],
      positive: 'Shows what WMI executed. Management tools also spawn processes via WMI; check the account and source.',
      negative: 'No rows does not exclude WMI abuse: a subscription consumer may run under scrcons.exe, and some tools use other execution paths.',
      prerequisites: 'Defender for Endpoint process telemetry.',
      schemaNotes: 'Standard Defender advanced hunting columns.',
      example: 'hostname = srv-demo-app01.corp.example.com, lookback = 24h',
    },
    {
      id: 'kql-wmi-source',
      title: 'Remote WMI commands issued from any host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds hosts that issued remote WMI process creation via wmic /node: or PowerShell WMI/CIM cmdlets with -ComputerName.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where (FileName =~ "wmic.exe" and ProcessCommandLine contains "/node:")
    or (FileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has_any ("Invoke-WmiMethod", "Invoke-CimMethod", "Win32_Process")
        and ProcessCommandLine has "ComputerName")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'DeviceName', meaning: 'Source host that issued the remote WMI request.' }],
      positive: 'Identifies candidate source hosts. Compare the target names in the command line with the alerted host.',
      negative: 'Remote WMI from unmanaged hosts, scripts that build the command dynamically, or attacker tooling on non-onboarded systems will not appear.',
      prerequisites: 'Defender for Endpoint on the source hosts.',
      schemaNotes: 'wmic.exe is deprecated and disabled by default on recent Windows 11 releases; PowerShell and third-party tooling are more common now.',
      example: 'lookback = 7d',
    },
    {
      id: 'kql-wmi-subscription',
      title: 'WMI event filter-to-consumer bindings',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists WMI permanent event subscription bindings recorded by Defender for Endpoint.',
      dataSources: ['DeviceEvents'],
      query: `DeviceEvents
| where Timestamp > ago({{lookback}})
| where ActionType == "WmiBindEventFilterToConsumer"
| extend Fields = parse_json(AdditionalFields)
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, Fields
| order by Timestamp asc`,
      placeholders: [PH.lookback('30d')],
      keyFields: [{ name: 'Fields', meaning: 'AdditionalFields JSON with filter and consumer details.' }],
      positive: 'Each binding needs an owner. Unexplained bindings are an escalation criterion.',
      negative: 'Subscriptions created before the lookback or on non-onboarded devices are not shown.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'AdditionalFields content varies; inspect a sample row to see the available properties.',
      example: 'lookback = 30d',
    },
    {
      id: 'spl-wmi-sysmon',
      title: 'WMI event subscription activity (Sysmon 19/20/21)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Shows WMI event filter, consumer, and binding registrations.',
      dataSources: ['Sysmon Events 19, 20, 21'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    (EventCode=19 OR EventCode=20 OR EventCode=21) earliest=-{{lookback}}
| table _time host EventCode Operation User Name Query Type Destination Consumer Filter
| sort _time`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Index holding Sysmon events.', example: 'sysmon' },
        PH.lookback('30d'),
      ],
      keyFields: [
        { name: 'Query (19)', meaning: 'WQL filter that triggers the subscription.' },
        { name: 'Type / Destination (20)', meaning: 'Consumer type and the command or script it runs.' },
        { name: 'Consumer / Filter (21)', meaning: 'The binding that activates the pair.' },
      ],
      positive: 'Registrations to attribute to an owner.',
      negative: 'Requires Sysmon config with WmiEvent enabled; no events may be a configuration gap.',
      prerequisites: 'Sysmon with WMI event logging; Sysmon channel indexed.',
      schemaNotes: 'Source naming depends on add-on version and collection format.',
      example: 'index = sysmon',
    },
    {
      id: 'spl-wmiprvse-children',
      title: 'WmiPrvSE.exe child processes (CIM)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Lists processes launched through WMI across hosts.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen values(Processes.process) as command_lines
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}} Processes.parent_process_name="wmiprvse.exe"
    by Processes.dest Processes.user Processes.process_name
| convert ctime(first_seen)
| sort - first_seen`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'Processes.user', meaning: 'Account WMI executed as.' }],
      positive: 'Shows WMI-launched processes for baseline and scoping.',
      negative: 'Empty output may mean parent process fields are not populated in your data model.',
      prerequisites: 'Process creation mapped to CIM.',
      schemaNotes: 'Parent process names may be full paths in some add-ons; adjust the filter.',
      example: 'lookback = 7d',
    },
    {
      id: 'generic-wmi',
      title: 'Generic WMI procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist for WMI alerts.',
      dataSources: ['Process creation', 'Logon events', 'WMI-Activity log'],
      query: `1. Target host: list children of WmiPrvSE.exe +/- 1 hour; record account and command lines.
2. Target host: find 4624 LogonType 3 for the same account seconds before; record source IP.
3. Source host: look for wmic /node:, Invoke-WmiMethod/Invoke-CimMethod -ComputerName, or
   other remote tooling at the same time.
4. Persistence: search WMI-Activity 5861 / Sysmon 19-21 for new filters, consumers, bindings.
5. Scope: same account or source to other hosts in the last 7 days.`,
      placeholders: [],
      keyFields: [],
      positive: 'Findings feed the decision tree.',
      negative: 'Missing WMI logs are a gap to record.',
      prerequisites: 'Process and logon telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Management platforms (SCCM, monitoring tools) generate large volumes of benign WMI activity; allow-list by server and account rather than by command.',
    'On the target host, remote WMI execution appears as a network logon followed by WmiPrvSE.exe children - correlate both.',
  ],
  visibilityGaps: [
    'WMI-Activity Operational and Sysmon WMI events are not collected in many environments.',
    'Source hosts outside EDR coverage (attacker-controlled or unmanaged) cannot be inspected.',
  ],
  relatedTechniques: [
    { id: 'T1021.006', reason: 'WinRM is an alternative remote management channel used similarly.' },
    { id: 'T1059.001', reason: 'WMI frequently launches PowerShell.' },
    { id: 'T1021.002', reason: 'Output and payloads are often staged via admin shares.' },
    { id: 'T1003', reason: 'Remote execution commonly precedes credential dumping.' },
  ],
  references: [
    attackRef('T1047', 'Windows Management Instrumentation'),
    attackRef('T1546.003', 'Windows Management Instrumentation Event Subscription'),
    { title: 'Sysinternals Sysmon (event IDs 19-21)', url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon' },
  ],
  assumptions: ['A list of legitimate WMI management servers and service accounts is maintained by the platform team.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

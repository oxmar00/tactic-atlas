import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const scheduledTask: Playbook = {
  schemaVersion: 1,
  id: 'PB-SCHTASK-001',
  version: '1.0.0',
  title: 'Suspicious scheduled task created or modified',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1053', 'T1053.005'],
  tactics: ['execution', 'persistence', 'privilege-escalation'],
  objective:
    'Extract what the scheduled task runs, when, and as whom; identify who created it and from where; and decide whether it is legitimate software or attacker persistence/execution.',
  alertMeaning:
    'A Windows scheduled task was created or changed in a way a detection considers risky - for example by an unusual process, from a remote host, with an action in a user-writable folder, or with a name imitating a Microsoft task.',
  whyItMatters:
    'Scheduled tasks let attackers re-run their code at logon, at boot, or every few minutes, often as SYSTEM. They are also used to execute commands on remote hosts during lateral movement.',
  difficulty: 'Intermediate',
  effort: '30-45 minutes',
  platforms: ['Windows'],
  logSources: ['mde', 'win-security', 'task-scheduler', 'sysmon', 'edr'],
  alertContext: {
    triggers: [
      'Security event 4698 (task created) or 4702 (task updated) matching a rule.',
      'EDR ScheduledTaskCreated / ScheduledTaskUpdated event with a suspicious action.',
      'schtasks.exe /create run by Office, a script host, or with /s (remote computer).',
      'Register-ScheduledTask / New-ScheduledTaskAction in PowerShell.',
    ],
    reviewFirst: [
      'Task name and folder path (e.g. \\Microsoft\\Windows\\...).',
      'Action: executable, arguments, and working directory.',
      'Trigger (logon, boot, time interval) and principal (user, SYSTEM, highest privileges).',
      'Creating process and account.',
    ],
    oftenMissing: [
      'The full task XML (only in 4698 TaskContent, EDR AdditionalFields, or on disk).',
      'Whether the task has already run.',
      'Whether it was created locally or from another host.',
    ],
  },
  prerequisites: [
    { text: 'Security 4698/4702 auditing ("Audit Other Object Access Events") or EDR task events.', type: 'telemetry', required: true },
    { text: 'Process creation telemetry to see the creating process and task executions.', type: 'telemetry', required: true },
    { text: 'TaskScheduler Operational log (106/140/200/201) if collected.', type: 'telemetry', required: false },
    { text: 'Software inventory / GPO list of expected scheduled tasks.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'task-definition',
      title: 'Extract the task definition',
      action:
        'Record the task name and folder, the action (Command, Arguments, WorkingDirectory), triggers, principal (UserId, RunLevel), author, and whether it is hidden. Take it from the 4698 TaskContent XML or the EDR event; on-disk XML is at C:\\Windows\\System32\\Tasks\\<name> (live response only if permitted).',
      why: 'The action and principal tell you exactly what will run and with which privileges - this is the core of the investigation.',
      where: ['Security 4698 / 4702 (TaskContent)', 'DeviceEvents ScheduledTaskCreated (AdditionalFields)', 'TaskScheduler Operational 106/140'],
      fields: ['TaskName', 'TaskContent: <Command>, <Arguments>, <Triggers>, <Principal>, <RunLevel>, <Hidden>', 'SubjectUserName'],
      suspicious: [
        'Action runs powershell/cmd/mshta/rundll32/regsvr32/wscript with encoded or URL arguments',
        'Executable in AppData, Temp, ProgramData, Users\\Public, or a random folder name',
        'Trigger every 1-15 minutes, or at logon/boot, running as SYSTEM with HighestAvailable',
        'Task name imitating Microsoft (e.g. under \\Microsoft\\Windows\\ with a typo) or a random GUID-like name',
      ],
      legitimate: ['Vendor updater tasks (browser, PDF reader, OneDrive) pointing to signed binaries in Program Files', 'Tasks deployed by GPO or the endpoint management platform'],
      next: 'Record the action and principal in the evidence checklist, then identify how the task was created.',
      queryIds: ['kql-task-events', 'kql-task-4698', 'spl-task-4698'],
    },
    {
      id: 'creator',
      title: 'Identify who created the task and from where',
      action:
        'Find the creating process (schtasks.exe, powershell.exe, an installer, mmc.exe, or the Task Scheduler service on behalf of a remote caller) and the account. If the creator is the service with a network logon (4624 LogonType 3) from another host just before, the task was likely created remotely.',
      why: 'A task created remotely from another workstation is a lateral-movement indicator; a task created by an Office macro or script host indicates an initial infection.',
      where: ['DeviceProcessEvents (schtasks.exe command lines)', 'Security 4624/4672 around the creation time', 'Sysmon 1'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'SubjectUserName / SubjectLogonId', 'Logon IpAddress / WorkstationName'],
      suspicious: ['schtasks.exe launched by winword.exe, wscript.exe, mshta.exe, or powershell -enc', 'schtasks /create /s <remote host> from a workstation', 'Creating account is a regular user or a service account not used for administration'],
      legitimate: ['Software installer (msiexec.exe) during a documented deployment', 'Endpoint management agent'],
      next: 'If created remotely, add the source host to the investigation and consider the Remote Services playbook.',
      queryIds: ['spl-schtasks-create'],
    },
    {
      id: 'action-target',
      title: 'Assess the file or script the task runs',
      action:
        'Look up the target file: path, signer, SHA-256, prevalence, and creation time. If it is a script, review its content through the EDR (do not run it). Check whether the file was created shortly before the task.',
      why: 'A legitimate task runs a stable, signed, widely deployed binary. A task pointing to a file written minutes earlier by an unknown process is classic persistence.',
      where: ['EDR file page', 'DeviceFileEvents for the target path', 'Reputation / sandbox service'],
      fields: ['FolderPath', 'SHA256', 'Signer', 'File creation time', 'Prevalence'],
      suspicious: ['Unsigned file first seen today', 'File created by the same process that created the task', 'Script that downloads or decodes content'],
      legitimate: ['Signed vendor binary present on many devices for months'],
      next: 'Record the target file details and check whether the task has already executed.',
      queryIds: [],
    },
    {
      id: 'executions',
      title: 'Check whether the task has run and what it did',
      action:
        'Look for executions: TaskScheduler 200/201 events, or processes whose parent is the Task Scheduler service host (svchost.exe -k netsvcs -p -s Schedule, or taskhostw.exe) running the task action. Review network connections and child processes of those executions.',
      why: 'If the task already ran, the payload is active and the impact must be assessed.',
      where: ['DeviceProcessEvents with InitiatingProcessCommandLine containing "Schedule"', 'TaskScheduler 200/201', 'DeviceNetworkEvents'],
      fields: ['Execution timestamps', 'Child processes', 'RemoteIP / RemoteUrl'],
      suspicious: ['Repeated executions making outbound connections to the same external host (beaconing)', 'Execution launching credential or discovery tools'],
      legitimate: ['Execution of an updater contacting the vendor\'s update domain'],
      next: 'Record execution count, first/last run, and destinations.',
      queryIds: [],
    },
    {
      id: 'baseline',
      title: 'Check the task against the fleet and change records',
      action:
        'Search for the same task name or action across all devices. Check GPOs, the endpoint management platform, and change tickets for a matching deployment.',
      why: 'A task present on 3,000 devices from the management platform is expected; the same task on one host is not.',
      where: ['DeviceEvents ScheduledTaskCreated across devices', 'Change management system', 'Software inventory'],
      fields: ['Device count with same task', 'Change ticket'],
      suspicious: ['Unique to this device', 'Present on several unrelated devices created within minutes of each other (scripted attacker deployment)'],
      legitimate: ['Matches a documented deployment'],
      next: 'Use the decision tree.',
      queryIds: ['kql-task-events'],
    },
  ],
  decisionTree: {
    start: 'known-software',
    nodes: [
      {
        id: 'known-software',
        question: 'Was the task created by a known installer, management tool, or GPO, with an action pointing to a signed binary in a protected path and a consistent presence across the fleet?',
        yes: { outcome: 'benign', guidance: 'Record the vendor/deployment, signer, and fleet count. Note any detection tuning suggestion.' },
        no: { next: 'risky-action', guidance: 'Assess the action and naming.' },
      },
      {
        id: 'risky-action',
        question: 'Does the action run a script interpreter or LOLBin, an encoded command, or a file in a user-writable path - or is the task name/folder disguised to look like a Microsoft task?',
        yes: { next: 'spread', guidance: 'Likely malicious persistence or execution.' },
        no: { next: 'owner', guidance: 'Not obviously malicious - verify the owner.' },
      },
      {
        id: 'owner',
        question: 'Can you confirm the task owner and purpose (ticket, application owner, or admin confirmation)?',
        yes: { outcome: 'benign', guidance: 'Document who confirmed it and how.' },
        no: { outcome: 'investigate', guidance: 'Unverified task with no obvious malicious behavior. Keep investigating; escalate if not verified within your SLA.' },
      },
      {
        id: 'spread',
        question: 'Is the same suspicious task present on multiple hosts, was it created remotely from another host, or is it linked to credential access or lateral movement?',
        yes: { outcome: 'critical', guidance: 'Possible hands-on-keyboard intrusion spreading across hosts. Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Suspicious persistence on a single host. Escalate with the task XML, creator, target file, and executions.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'Task creation/modification time and first execution (UTC).'),
    ev('hostname', true),
    ev('username', true, 'Account that created the task (SubjectUserName) and the task principal.'),
    evCustom('task_name', 'Task name and folder', 'e.g. \\Microsoft\\Windows\\UpdateOrchestrator\\Sync (copy exactly).', true),
    evCustom('task_action', 'Task action (command and arguments)', 'Exact <Command> and <Arguments>.', true, true),
    evCustom('task_trigger', 'Trigger and principal', 'e.g. TimeTrigger every 10 min; Principal SYSTEM, RunLevel HighestAvailable.', true),
    ev('parent_process', true, 'Process that created the task (schtasks.exe / powershell.exe / service).'),
    ev('command_line', false, 'Creating command line, e.g. schtasks /create ...'),
    ev('file_hash', false, 'Target file path, SHA-256, signer.'),
    ev('src_ip', false, 'Source host/IP if created remotely.'),
    evCustom('executions', 'Executions observed', 'Count, first/last run, notable child processes or connections.', false, true),
    ev('event_ids', false, 'e.g. 4698 record IDs, EDR ReportIds.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Task action runs a script interpreter, LOLBin, encoded command, or file from a user-writable path.',
      'Task name or folder imitates a legitimate Microsoft or vendor task.',
      'Task was created by an Office application, script host, or unknown binary.',
      'Task runs as SYSTEM/highest privileges and its owner cannot be verified.',
      'The task has executed and made outbound connections to unknown destinations.',
    ],
    immediate: [
      'Task created remotely from another workstation (possible lateral movement).',
      'Same suspicious task appears on multiple hosts.',
      'Task created on a domain controller or other tier-0 system without a change record.',
    ],
    benignClosure: [
      'Task traced to a known installer, management platform, or GPO.',
      'Action points to a signed binary in a protected path with normal fleet prevalence.',
      'Owner confirmed through a ticket or application owner.',
    ],
  },
  queries: [
    {
      id: 'kql-task-events',
      title: 'Scheduled task create/update/delete events on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists scheduled task changes recorded by Defender for Endpoint with the creating process and task XML.',
      dataSources: ['DeviceEvents'],
      query: `DeviceEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated", "ScheduledTaskDeleted")
| extend Fields = parse_json(AdditionalFields)
| extend TaskName = tostring(Fields.TaskName), TaskContent = tostring(Fields.TaskContent)
| project Timestamp, ActionType, TaskName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, TaskContent
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d'), PH.hostname()],
      keyFields: [
        { name: 'TaskName', meaning: 'Task path and name.' },
        { name: 'TaskContent', meaning: 'Task XML including <Exec><Command>, <Arguments>, triggers, and principal.' },
        { name: 'InitiatingProcess*', meaning: 'Process and account that created the task.' },
      ],
      positive: 'Shows the task definition and creator for review. Many legitimate installers create tasks.',
      negative: 'No rows may mean the device is not onboarded, the event was outside retention, or the task was created before the lookback window.',
      prerequisites: 'Defender for Endpoint; advanced hunting or Sentinel access.',
      schemaNotes: 'AdditionalFields contents are not formally versioned by Microsoft; verify the property names in your tenant (TaskName, TaskContent).',
      example: 'hostname = ws-demo-0142.corp.example.com, lookback = 7d',
    },
    {
      id: 'kql-task-4698',
      title: 'Security 4698/4702 task events with parsed action',
      language: 'kql',
      platform: 'Microsoft Sentinel (Windows Security Events connector)',
      purpose: 'Parses the task action from Security event 4698/4702 TaskContent.',
      dataSources: ['SecurityEvent'],
      query: `SecurityEvent
| where TimeGenerated > ago({{lookback}})
| where EventID in (4698, 4702)
| where Computer =~ "{{hostname}}"
| extend TaskName = extract(@'<Data Name="TaskName">([^<]*)</Data>', 1, EventData),
         RawContent = extract(@'<Data Name="TaskContent">([\\s\\S]*?)</Data>', 1, EventData)
| extend TaskContent = replace_string(replace_string(RawContent, "&lt;", "<"), "&gt;", ">")
| extend TaskCommand = extract(@'<Command>([^<]*)</Command>', 1, TaskContent),
         TaskArguments = extract(@'<Arguments>([^<]*)</Arguments>', 1, TaskContent),
         TaskUserId = extract(@'<UserId>([^<]*)</UserId>', 1, TaskContent)
| project TimeGenerated, Computer, EventID, SubjectUserName, SubjectLogonId,
          TaskName, TaskCommand, TaskArguments, TaskUserId
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d'), PH.hostname()],
      keyFields: [
        { name: 'SubjectUserName / SubjectLogonId', meaning: 'Who created the task; correlate SubjectLogonId with 4624 to find the logon source.' },
        { name: 'TaskCommand / TaskArguments', meaning: 'What the task executes.' },
      ],
      positive: 'Shows the task action and creator account for review.',
      negative: 'Empty results usually mean "Audit Other Object Access Events" is not enabled or workstation Security logs are not collected - a visibility gap, not proof.',
      prerequisites: 'Audit policy for 4698/4702 and Security events collected for this host.',
      schemaNotes: 'TaskContent is XML embedded inside the event XML, so angle brackets arrive escaped (&lt; &gt;); the query unescapes them before extracting. Arguments may still contain &amp; or &quot;.',
      example: 'hostname = WS-DEMO-0142.corp.example.com',
    },
    {
      id: 'spl-task-4698',
      title: 'Security 4698 scheduled task creation with parsed action',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Extracts the command and arguments from 4698 events on a host.',
      dataSources: ['Windows Security EventCode 4698'],
      query: `index="{{index}}" source="XmlWinEventLog:Security" EventCode=4698 host="{{hostname}}" earliest=-{{lookback}}
| rex field=TaskContent "<Command>(?<task_command>[^<]+)</Command>"
| rex field=TaskContent "<Arguments>(?<task_arguments>[^<]+)</Arguments>"
| rex field=TaskContent "<UserId>(?<task_principal>[^<]+)</UserId>"
| table _time host SubjectUserName TaskName task_command task_arguments task_principal
| sort _time`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Index holding Windows Security events.', example: 'wineventlog' },
        PH.hostname(),
        PH.lookback('7d'),
      ],
      keyFields: [
        { name: 'task_command / task_arguments', meaning: 'Parsed task action.' },
        { name: 'SubjectUserName', meaning: 'Creating account.' },
      ],
      positive: 'Task definitions on the host for review.',
      negative: 'No events may mean auditing is not enabled for this subcategory or the host log is not forwarded.',
      prerequisites: 'Audit Other Object Access Events enabled; Security log forwarded.',
      schemaNotes: 'If TaskContent is XML-escaped in your data, change the rex patterns to match &lt;Command&gt;. With classic (non-XML) collection the source is WinEventLog:Security and field names may be Task_Name/Task_Content.',
      example: 'index = wineventlog, hostname = WS-DEMO-0142',
    },
    {
      id: 'spl-schtasks-create',
      title: 'schtasks.exe /create executions with parent process (CIM)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds task creation through schtasks.exe, including remote creation with /s, and shows the launching parent.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen values(Processes.process) as command_lines
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}} Processes.process_name="schtasks.exe" Processes.process="*/create*"
    by Processes.dest Processes.user Processes.parent_process_name
| convert ctime(first_seen)
| sort - first_seen`,
      placeholders: [PH.lookback('7d')],
      keyFields: [
        { name: 'command_lines', meaning: 'Look for /s (remote), /ru SYSTEM, /tr with interpreters or user-writable paths.' },
        { name: 'Processes.parent_process_name', meaning: 'What launched schtasks.exe.' },
      ],
      positive: 'Command-line evidence of task creation and its parent.',
      negative: 'Does not cover tasks created through the COM API or PowerShell cmdlets (no schtasks.exe process).',
      prerequisites: 'Process creation data mapped to CIM with command lines.',
      schemaNotes: 'Field population depends on the add-on.',
      example: 'lookback = 7d',
    },
    {
      id: 'generic-schtask',
      title: 'Generic scheduled task procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist for scheduled task alerts.',
      dataSources: ['Task creation events', 'Process creation', 'Logon events'],
      query: `1. Get the task XML: name, Command, Arguments, Triggers, Principal/RunLevel, Author.
2. Find the creating process and account; check for a network logon from another host
   within a few minutes before creation (remote creation).
3. Assess the action target: path, signer, hash, first seen, prevalence.
4. Look for executions (processes started by the Task Scheduler service) and their
   network activity.
5. Search the fleet for the same task name/action and check change records.`,
      placeholders: [],
      keyFields: [],
      positive: 'Findings feed the decision tree.',
      negative: 'Missing task auditing is a gap to record.',
      prerequisites: 'Task auditing or EDR.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Tasks created through the COM API or PowerShell do not spawn schtasks.exe - rely on 4698 or EDR events.',
    'Attackers sometimes modify an existing legitimate task (4702) instead of creating a new one.',
    'Tasks can be hidden from the Task Scheduler UI; on-disk XML and registry (TaskCache) still exist.',
  ],
  visibilityGaps: [
    '4698/4702 require an audit policy that is often disabled on workstations.',
    'TaskScheduler Operational log is disabled by default on many builds.',
  ],
  relatedTechniques: [
    { id: 'T1059.001', reason: 'Task actions frequently launch PowerShell.' },
    { id: 'T1021.002', reason: 'Remote task creation usually follows SMB/admin-share access.' },
    { id: 'T1036.005', reason: 'Task names and paths are chosen to look like legitimate Microsoft resources.' },
    { id: 'T1547.001', reason: 'Run keys are an alternative persistence mechanism checked alongside tasks.' },
    { id: 'T1543.003', reason: 'Windows services are another common persistence/execution method.' },
  ],
  references: [
    attackRef('T1053.005', 'Scheduled Task'),
    { title: 'Microsoft Learn - 4698(S): A scheduled task was created', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698' },
    { title: 'Microsoft Learn - DeviceEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table' },
  ],
  assumptions: ['Tier 1 does not delete or disable tasks; removal is a containment action requested through escalation.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

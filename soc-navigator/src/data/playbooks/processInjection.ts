import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const processInjection: Playbook = {
  schemaVersion: 1,
  id: 'PB-INJECT-001',
  version: '1.0.0',
  title: 'Suspicious process injection',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1055', 'T1055.001', 'T1055.002', 'T1055.012'],
  tactics: ['stealth', 'privilege-escalation'],
  objective:
    'Identify the injecting (source) and injected (target) processes, decide whether the source is a legitimate product, and check whether the target started behaving like malware.',
  alertMeaning:
    'The EDR observed one process writing code into, or redirecting execution of, another process - e.g. remote thread creation, APC queuing, process hollowing (a process started suspended and replaced), or reflective DLL loading.',
  whyItMatters:
    'Injection lets malware run inside a trusted process (explorer.exe, svchost.exe, a browser) to hide from defenders and inherit that process\'s access. Many security and accessibility products also inject legitimately, so verification matters.',
  difficulty: 'Advanced',
  effort: '30-60 minutes (escalate early if unclear)',
  platforms: ['Windows', 'Linux', 'macOS'],
  logSources: ['mde', 'edr', 'sysmon'],
  alertContext: {
    triggers: [
      'EDR injection alert (remote thread, APC, hollowing, reflective load, memory protection change).',
      'Sysmon 8 CreateRemoteThread into another process.',
      'Process that normally has no network activity (e.g. notepad.exe, rundll32.exe with no arguments) connecting to the internet.',
    ],
    reviewFirst: ['Source process: image path, signer, command line, parent.', 'Target process: name, PID, path, parent.', 'Injection type reported by the EDR and whether it was blocked.'],
    oftenMissing: ['What the target process did after injection.', 'How the source process got onto the host.'],
  },
  prerequisites: [
    { text: 'EDR with injection/API-call telemetry (Sysmon 8 is a partial substitute).', type: 'telemetry', required: true },
    { text: 'Network connection telemetry attributed to processes.', type: 'telemetry', required: true },
    { text: 'List of security, accessibility, and monitoring products known to inject.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'source-target',
      title: 'Identify source and target processes',
      action: 'Record both processes: image path, PID, signer, SHA-256, command line, parent, user, integrity level, and the injection type the EDR reports.',
      why: 'The verdict depends on who injected into whom.',
      where: ['EDR alert / process tree', 'DeviceEvents (API-call ActionTypes)', 'Sysmon 8 / 10'],
      fields: ['InitiatingProcessFileName / FolderPath', 'Target FileName / ProcessId', 'ActionType', 'SHA256', 'Signer'],
      suspicious: ['Unsigned source in AppData/Temp', 'Script host, rundll32, regsvr32, or Office process as the source', 'Target is lsass.exe, a browser, or a system process'],
      legitimate: ['Signed security/accessibility/monitoring software from its install path'],
      next: 'Assess the source\'s legitimacy.',
      queryIds: ['kql-injection-events', 'spl-sysmon-remote-thread'],
    },
    {
      id: 'source-legit',
      title: 'Check whether the source is a known injecting product',
      action: 'Compare signer, path, and prevalence with security agents, DLP, accessibility tools, input/IME tools, game anti-cheat, and application-compatibility shims known in your environment.',
      why: 'Legitimate products inject routinely; recognizing them avoids escalating noise.',
      where: ['Software inventory', 'EDR file page (prevalence)', 'Vendor documentation'],
      fields: ['Signer', 'Install path', 'Device count'],
      suspicious: ['Name of a security product but wrong path or signer (masquerading)', 'Present on one device only'],
      legitimate: ['Fleet-wide signed agent from the expected directory'],
      next: 'If not verified, examine the target\'s behavior.',
      queryIds: [],
    },
    {
      id: 'hollowing-check',
      title: 'Look for process hollowing indicators',
      action: 'Check whether the source created the target itself (target\'s parent = source) shortly before injection, and whether the target has an odd parent or command line - e.g. svchost.exe not started by services.exe, or rundll32.exe with no arguments.',
      why: 'Hollowing starts a legitimate binary suspended and replaces its code; the giveaway is an unusual parent-child relationship or command line.',
      where: ['DeviceProcessEvents', 'EDR process tree'],
      fields: ['Target InitiatingProcessFileName', 'Target ProcessCommandLine', 'Creation time vs. injection time'],
      suspicious: ['svchost.exe with a parent other than services.exe', 'rundll32.exe / dllhost.exe without expected arguments', 'Target created seconds before injection by the source'],
      legitimate: ['Target started by its normal parent long before the event'],
      next: 'Check the target\'s behavior after injection.',
      queryIds: [],
    },
    {
      id: 'target-behavior',
      title: 'Check what the target did after injection',
      action: 'Review network connections, child processes, file writes, and LSASS access by the target after the injection time.',
      why: 'Injected code acts through the target. Network beacons or credential access from a benign-looking process confirm malicious injection.',
      where: ['DeviceNetworkEvents / Sysmon 3', 'DeviceProcessEvents', 'DeviceEvents OpenProcessApiCall'],
      fields: ['RemoteIP / RemoteUrl', 'Child processes', 'LSASS access'],
      suspicious: ['notepad.exe / rundll32.exe / dllhost.exe connecting to public IPs', 'Target spawning cmd/powershell', 'Target opening LSASS'],
      legitimate: ['No change in the target\'s normal behavior'],
      next: 'Trace how the source arrived on the host.',
      queryIds: ['kql-unusual-network-procs', 'spl-sysmon-unusual-network'],
    },
    {
      id: 'origin',
      title: 'Trace the origin of the source process',
      action: 'Find how the source binary or script got onto the host (download, email, lateral transfer) and whether persistence exists for it.',
      why: 'Origin reveals the initial access vector and other affected users.',
      where: ['DeviceFileEvents', 'Registry / task events', 'Email and proxy logs'],
      fields: ['File origin', 'Persistence artifacts'],
      suspicious: ['Arrived minutes after a user opened an attachment', 'Run key or task referencing the source'],
      legitimate: ['Installed by the management platform'],
      next: 'Scope and decide.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'known-product',
    nodes: [
      {
        id: 'known-product',
        question: 'Is the source a verified security, accessibility, or monitoring product (correct signer and path, fleet prevalence) injecting into expected targets?',
        yes: { outcome: 'benign', guidance: 'Record product, signer, path, and prevalence. Suggest an exclusion scoped to signer + path.' },
        no: { next: 'malicious-signs', guidance: 'Unverified injector.' },
      },
      {
        id: 'malicious-signs',
        question: 'Is the source unsigned/rare/a script host or LOLBin, or did the target show malicious behavior (public network connections, shells, LSASS access, hollowing indicators)?',
        yes: { next: 'severity', guidance: 'Likely malicious injection.' },
        no: { outcome: 'investigate', guidance: 'Signed but unrecognized software with no malicious behavior observed. Verify with the software owner; escalate if not verified - injection telemetry is easy to misjudge.' },
      },
      {
        id: 'severity',
        question: 'Is the target lsass.exe or a core system process, or is there credential access, lateral movement, or the same source on multiple hosts?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Escalate with source/target details, injection type, and target behavior.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true, 'Include injection type reported by the EDR.'),
    ev('event_time', true),
    ev('hostname', true),
    ev('username', true),
    evCustom('source_process', 'Injecting (source) process', 'Path, PID, signer, SHA-256, command line, parent.', true, true),
    evCustom('target_process', 'Injected (target) process', 'Name, PID, path, parent, command line.', true, true),
    ev('destination', false, 'Network destinations contacted by the target after injection.'),
    evCustom('target_behavior', 'Target behavior after injection', 'Child processes, file writes, LSASS access.', false, true),
    ev('file_hash', false, 'Source binary/DLL hashes.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Injection by an unsigned, rare, or script-host/LOLBin source.',
      'Target process making public network connections or spawning shells after injection.',
      'Process hollowing indicators (unusual parent/command line for the target).',
      'You cannot verify the source as a known product.',
    ],
    immediate: ['Injection into lsass.exe or credential access from the target.', 'Same injecting binary on multiple hosts.', 'Injection on a domain controller or critical server.'],
    benignClosure: ['Source verified as an approved product by signer, path, and prevalence, injecting into expected targets with no abnormal target behavior.'],
  },
  queries: [
    {
      id: 'kql-injection-events',
      title: 'Injection-related API events on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists remote thread creation, APC queuing, thread context changes, and remote memory operations recorded on the host.',
      dataSources: ['DeviceEvents'],
      query: `DeviceEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType in ("CreateRemoteThreadApiCall", "QueueUserApcRemoteApiCall",
        "SetThreadContextRemoteApiCall", "NtAllocateVirtualMemoryRemoteApiCall",
        "NtMapViewOfSectionRemoteApiCall", "WriteToLsassProcessMemory")
| project Timestamp, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          TargetFileName = FileName, TargetProcessId = ProcessId
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [
        { name: 'InitiatingProcess*', meaning: 'Source (injecting) process.' },
        { name: 'TargetFileName / TargetProcessId', meaning: 'Target process (FileName/ProcessId describe the target in these events).' },
      ],
      positive: 'Rows show injection-like operations to attribute. Legitimate products appear frequently.',
      negative: 'These events are sampled/capped by Defender, so absence is not proof. Rely on the alert evidence as primary.',
      prerequisites: 'Defender for Endpoint P2.',
      schemaNotes: 'Verify ActionType names against the current DeviceEvents documentation for your tenant; Microsoft adds and changes API-call events.',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'kql-unusual-network-procs',
      title: 'Public network connections from processes that rarely use the network',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds connections to public IPs from processes commonly used as injection targets.',
      dataSources: ['DeviceNetworkEvents'],
      query: `DeviceNetworkEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("notepad.exe", "calc.exe", "mspaint.exe", "rundll32.exe",
        "regsvr32.exe", "dllhost.exe", "werfault.exe", "searchprotocolhost.exe")
| summarize Connections = count(), Destinations = make_set(strcat(RemoteIP, ":", tostring(RemotePort)), 20),
            First = min(Timestamp), Last = max(Timestamp)
            by InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine
| order by First asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [{ name: 'InitiatingProcessCommandLine', meaning: 'Empty or minimal arguments for rundll32/dllhost are suspicious.' }],
      positive: 'Unusual networking processes are strong evidence of injected code.',
      negative: 'Injected browsers or svchost.exe blend in and are excluded here.',
      prerequisites: 'Defender for Endpoint network telemetry.',
      schemaNotes: 'RemoteIPType classifies Public/Private/Loopback addresses.',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'spl-sysmon-remote-thread',
      title: 'Remote thread creation (Sysmon 8)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Summarizes CreateRemoteThread events by source and target image.',
      dataSources: ['Sysmon Event 8'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=8 host="{{hostname}}" earliest=-{{lookback}}
| stats count min(_time) as first_seen values(StartModule) as start_modules
    values(StartFunction) as start_functions by host SourceImage TargetImage
| convert ctime(first_seen)
| sort first_seen`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Sysmon events.', example: 'sysmon' }, PH.hostname(), PH.lookback('24h')],
      keyFields: [{ name: 'StartModule / StartFunction', meaning: 'Empty start module (thread starting in unbacked memory) is a strong injection indicator.' }],
      positive: 'Source-target pairs to attribute.',
      negative: 'Other injection methods (APC, hollowing) do not generate Event 8.',
      prerequisites: 'Sysmon with CreateRemoteThread logging.',
      schemaNotes: 'Field availability depends on Sysmon version.',
      example: 'index = sysmon',
    },
    {
      id: 'spl-sysmon-unusual-network',
      title: 'Network connections from rarely-networking processes (Sysmon 3)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Finds outbound connections from processes commonly abused as injection targets.',
      dataSources: ['Sysmon Event 3'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=3 host="{{hostname}}" earliest=-{{lookback}}
    (Image="*notepad.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe"
     OR Image="*dllhost.exe" OR Image="*werfault.exe")
| stats count values(DestinationIp) as dest_ips values(DestinationPort) as ports by host Image ProcessId
| sort - count`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Sysmon events.', example: 'sysmon' }, PH.hostname(), PH.lookback('24h')],
      keyFields: [{ name: 'dest_ips', meaning: 'Public destinations deserve reputation checks.' }],
      positive: 'Connections from these processes are leads.',
      negative: 'Sysmon network logging is often filtered; absence may be configuration.',
      prerequisites: 'Sysmon NetworkConnect events enabled.',
      schemaNotes: 'Adjust process list to your environment.',
      example: 'index = sysmon',
    },
    {
      id: 'generic-injection',
      title: 'Generic injection procedure',
      language: 'generic',
      platform: 'Any EDR',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['EDR alert evidence', 'Process and network telemetry'],
      query: `1. Record source and target: path, PID, signer, hash, parent, command line.
2. Verify the source against known injecting products (signer + path + prevalence).
3. Hollowing check: did the source create the target just before? Odd parent/command line?
4. Target behavior after injection: network, children, LSASS access.
5. Origin and persistence of the source; same source on other hosts.`,
      placeholders: [],
      keyFields: [],
      positive: 'Malicious target behavior confirms injection.',
      negative: 'Lack of telemetry for API calls is common; escalate if unsure.',
      prerequisites: 'EDR.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: ['Injection telemetry is noisy; rely on EDR verdicts plus target behavior.', 'Allow-list by signer and path, never by process name.'],
  visibilityGaps: ['Without EDR, injection is largely invisible to Windows native logs.', 'API-call telemetry is sampled.'],
  relatedTechniques: [
    { id: 'T1003.001', reason: 'Injection into or access of LSASS for credentials.' },
    { id: 'T1218.011', reason: 'rundll32.exe is commonly used to load injected DLLs.' },
    { id: 'T1620', reason: 'Reflective code loading is closely related to injection.' },
    { id: 'T1036', reason: 'Injection is often combined with masquerading.' },
  ],
  references: [attackRef('T1055', 'Process Injection'), attackRef('T1055.012', 'Process Hollowing'), { title: 'Microsoft Learn - DeviceEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table' }],
  assumptions: ['Tier 1 relies on EDR verdicts for memory-level evidence; memory forensics is a Tier 2/IR task.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

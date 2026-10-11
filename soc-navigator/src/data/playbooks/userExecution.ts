import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const userExecution: Playbook = {
  schemaVersion: 1,
  id: 'PB-USEREXEC-001',
  version: '1.0.0',
  title: 'User execution of a suspicious file or link',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1204', 'T1204.001', 'T1204.002', 'T1204.004'],
  tactics: ['execution'],
  objective:
    'Determine what the user ran, where it came from, what it did after it started, and whether it is an approved application or the start of an intrusion.',
  alertMeaning:
    'An endpoint alert reports that a user opened a downloaded file, an email attachment, a file from an archive or mounted disk image, or pasted a command (e.g. "fake CAPTCHA / ClickFix" lures), and that the resulting process looks unusual.',
  whyItMatters:
    'Most malware still needs a user to start it. The first minutes after execution decide whether the attacker gains a foothold: script hosts, downloaders, and persistence typically follow quickly.',
  difficulty: 'Beginner',
  effort: '30-60 minutes',
  platforms: ['Windows', 'macOS', 'Linux'],
  logSources: ['mde', 'edr', 'sysmon', 'win-security', 'proxy', 'av'],
  alertContext: {
    triggers: [
      'Office application, PDF reader, or browser spawned a script interpreter (wscript, cscript, mshta, powershell, cmd).',
      'Executable or script launched from Downloads, Temp, an Outlook attachment cache, or an archive extraction folder.',
      'Executable launched from a mounted ISO/IMG/VHD drive letter.',
      'explorer.exe launched powershell/cmd/mshta with a command typed or pasted into the Run dialog.',
    ],
    reviewFirst: [
      'Host, user, file name, full path, SHA-256, and signer.',
      'Parent process and how the file was opened (double-click via explorer.exe, from Outlook, from the browser).',
      'Command line of the suspicious process.',
      'Whether the EDR blocked, killed, or only observed the process.',
    ],
    oftenMissing: [
      'Where the file came from (email, web URL, USB, chat).',
      'What happened after the first process (children, network, files, persistence).',
      'How many other devices have the same file.',
    ],
  },
  prerequisites: [
    { text: 'EDR device timeline / process tree access for the host.', type: 'access', required: true },
    { text: 'File reputation or sandbox service approved for submitting samples (check data-handling rules before uploading internal documents).', type: 'tool', required: true },
    { text: 'Process creation telemetry with command lines (EDR, Sysmon 1, or 4688 with command-line auditing).', type: 'telemetry', required: true },
    { text: 'Proxy or DNS logs to confirm download source and post-execution connections.', type: 'telemetry', required: false },
    { text: 'Approved software list or software-request tickets.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'validate-execution',
      title: 'Confirm what executed and whether it was stopped',
      action:
        'Record host, user, the executed file (name, full path, SHA-256, signer), its parent process, the command line, and the EDR action (detected, blocked, quarantined, or allowed). Confirm the process actually started - a file that was only downloaded or quarantined on write did not execute.',
      why: 'The rest of the investigation depends on whether code ran. "Blocked on write" and "ran for ten minutes" are very different cases.',
      where: ['EDR alert and process tree', 'DeviceProcessEvents', 'Sysmon Event 1', 'Security 4688'],
      fields: ['DeviceName', 'AccountName', 'FileName', 'FolderPath', 'SHA256', 'ProcessCommandLine', 'InitiatingProcessFileName', 'Signer / certificate'],
      suspicious: [
        'Unsigned or newly signed binary in a user-writable folder',
        'Double extension (invoice.pdf.exe) or document icon on an executable',
        'Process ran from a mounted disk image drive letter (e.g. E:\\setup.exe)',
      ],
      legitimate: ['Installer signed by a known vendor and present in the software catalog', 'IT deployment tool launching approved packages'],
      next: 'If nothing executed, record the block and check whether the file still exists elsewhere. Otherwise identify where the file came from.',
      queryIds: ['kql-exec-tree'],
    },
    {
      id: 'file-origin',
      title: 'Find where the file or command came from',
      action:
        'Look for the file\'s origin: download URL and referrer, the email that delivered it, the archive or ISO it was extracted from, or the web page that instructed the user to paste a command. Check the Mark-of-the-Web (Zone.Identifier) data when available.',
      why: 'The origin tells you whether other users were exposed (same email or website) and gives you indicators to block.',
      where: ['DeviceFileEvents (FileOriginUrl, FileOriginReferrerUrl)', 'Sysmon Event 15 (Zone.Identifier stream)', 'Email security logs', 'Proxy logs', 'Browser history (via EDR live response only if permitted)'],
      fields: ['FileOriginUrl', 'FileOriginReferrerUrl', 'FileOriginIP', 'Zone.Identifier HostUrl / ReferrerUrl', 'Email NetworkMessageId'],
      suspicious: [
        'Downloaded from a newly registered domain, file-sharing service, or IP address',
        'Delivered as an email attachment from an external sender',
        'Explorer RunMRU or clipboard-related evidence that the user pasted a command from a web page',
      ],
      legitimate: ['Downloaded from the vendor\'s official site or the internal software portal'],
      next: 'If the file came by email, also run the phishing playbook for the campaign. Continue to what the process did.',
      queryIds: ['kql-file-origin', 'spl-zone-identifier'],
    },
    {
      id: 'post-execution',
      title: 'Reconstruct what happened after execution',
      action:
        'Walk the process tree forward from the executed process for at least two hours: child processes, command lines, files written, registry Run keys or scheduled tasks created, and outbound network connections.',
      why: 'Behavior after launch is the most reliable way to judge intent. Malware commonly launches script hosts, downloads a second stage, and creates persistence within minutes.',
      where: ['EDR process tree / timeline', 'DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents', 'Sysmon 1, 3, 11, 13'],
      fields: ['Child FileName and ProcessCommandLine', 'RemoteIP / RemoteUrl / RemotePort', 'Files created (FolderPath)', 'RegistryKey / RegistryValueData'],
      suspicious: [
        'Children such as powershell -enc, mshta http..., rundll32 with a DLL in AppData, regsvr32 /i:http',
        'Outbound connections to IP addresses or rare domains shortly after launch',
        'New executable/DLL written to AppData, ProgramData, or Temp, then executed',
        'Run key, Startup folder item, scheduled task, or service created',
      ],
      legitimate: ['Installer writes to Program Files and contacts the vendor\'s update domain', 'No child processes or network activity beyond expected application behavior'],
      next: 'Any persistence or second-stage download means the decision tree will lead to escalation. Record each artifact in the evidence checklist.',
      queryIds: ['kql-exec-tree', 'spl-office-children'],
    },
    {
      id: 'reputation-prevalence',
      title: 'Check reputation and prevalence',
      action:
        'Look up the SHA-256 and domains in your threat-intelligence and reputation tools. Check how many devices in the organization have the same file and when it was first seen.',
      why: 'A file seen on one device for the first time today is far more suspicious than one present on 2,000 devices for a year. Reputation helps, but unknown is not the same as clean.',
      where: ['EDR file page (global/organizational prevalence)', 'DeviceFileEvents summarized by SHA256', 'Threat-intelligence platform', 'Sandbox report'],
      fields: ['SHA256', 'First seen in organization', 'Device count', 'Signer', 'Sandbox verdict'],
      suspicious: ['Only seen on this device', 'First seen in the last 24 hours', 'Sandbox shows process injection, credential access, or C2 traffic'],
      legitimate: ['Widely deployed, signed by the expected vendor, and consistent with an approved software list'],
      next: 'Do not upload confidential internal documents to public sandboxes. If prevalence is high and the file is approved, consider a benign closure.',
      queryIds: ['kql-file-origin'],
    },
    {
      id: 'user-context',
      title: 'Establish user and business context',
      action:
        'Check whether the user had a software request ticket, works in a role that installs tools (developer, IT), or reported the event. If your procedure allows, confirm with the user or their manager through an approved channel (not by replying to the suspicious email).',
      why: 'Context distinguishes "developer installed a new tool" from "accountant opened an invoice that launched PowerShell".',
      where: ['Ticketing system', 'HR/role directory', 'Approved software catalog'],
      fields: ['User role / department', 'Ticket number', 'User statement'],
      suspicious: ['User does not recognize the file', 'User was asked by a web page or caller to run a command'],
      legitimate: ['Matching change or software-request ticket', 'User and IT confirm the installation'],
      next: 'Record the source of any confirmation. A user statement alone does not override malicious technical evidence.',
      queryIds: [],
    },
    {
      id: 'scope-exposure',
      title: 'Look for the same file or source on other devices',
      action:
        'Search for the hash, file name, and origin domain across all devices and users for the past 7 days. Check for related alerts on the same host and user.',
      why: 'Commodity campaigns hit many users. Finding all exposed devices early limits spread.',
      where: ['DeviceFileEvents / DeviceProcessEvents by SHA256', 'Proxy logs by domain', 'Alert queue'],
      fields: ['DeviceName list', 'AccountName list', 'Related alert IDs'],
      suspicious: ['Same hash executed on multiple devices', 'Same origin domain contacted by several users'],
      legitimate: ['Hash appears only as part of a known software deployment'],
      next: 'Add every additional affected device to "Additional affected users / systems" and go to the decision tree.',
      queryIds: ['kql-file-origin'],
    },
  ],
  decisionTree: {
    start: 'executed',
    nodes: [
      {
        id: 'executed',
        question: 'Did the file, script, or pasted command actually execute (a process started), rather than being blocked or only downloaded?',
        yes: { next: 'approved', guidance: 'Code ran. Determine whether it is legitimate.' },
        no: { outcome: 'contained', guidance: 'Nothing executed. Confirm the file was quarantined/removed, record the origin indicators for blocking, and close per procedure.' },
      },
      {
        id: 'approved',
        question: 'Is the software verified as legitimate (trusted signer, approved list or ticket, broad prevalence, confirmed by user/IT) with no suspicious behavior after launch?',
        yes: { outcome: 'benign', guidance: 'Document the signer, prevalence, and ticket/confirmation. Note any tuning suggestion for the detection.' },
        no: { next: 'follow-on', guidance: 'Not verified - examine post-execution behavior.' },
      },
      {
        id: 'follow-on',
        question: 'After execution, did it launch script hosts or LOLBins, connect to unknown external destinations, write and run new executables, or create persistence?',
        yes: { next: 'impact', guidance: 'Malicious behavior observed after execution.' },
        no: { next: 'reputation', guidance: 'No follow-on behavior seen. Rely on reputation and sandbox results.' },
      },
      {
        id: 'reputation',
        question: 'Does AV, sandbox, or threat-intelligence classify the file, URL, or command as malicious or suspicious?',
        yes: { outcome: 'escalate', guidance: 'A malicious file executed. Even without visible follow-on activity, escalate - telemetry may be incomplete.' },
        no: { outcome: 'investigate', guidance: 'Unknown, unverified file with no follow-on seen. Seek user/IT confirmation and extend the timeline; escalate if you cannot verify it.' },
      },
      {
        id: 'impact',
        question: 'Is there evidence of credential access, lateral movement, multiple affected hosts, or mass file modification?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now and list every affected host and account.' },
        no: { outcome: 'escalate', guidance: 'Single-host malicious execution. Escalate to Tier 2 with the process tree, network destinations, and persistence artifacts.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'Execution time (UTC) and when the file arrived.'),
    ev('hostname', true),
    ev('username', true),
    ev('file_hash', true, 'Executed file: name, full path, SHA-256, signer.'),
    ev('process', true),
    ev('parent_process', true, 'e.g. explorer.exe, outlook.exe, winword.exe, msedge.exe'),
    ev('command_line', true),
    evCustom('file_origin', 'File or command origin', 'Download URL, referrer, email message ID, archive/ISO name, or web page that instructed the paste.', true, true),
    evCustom('child_activity', 'Post-execution activity', 'Child processes, files written, persistence created (one per line).', false, true),
    ev('destination', false, 'Outbound connections after execution.'),
    evCustom('prevalence', 'Prevalence and reputation', 'Device count, first seen, sandbox/TI verdict.', false, true),
    evCustom('user_context', 'User / business context', 'Ticket number, role, confirmation source.', false),
    ev('affected_assets', false),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'A file classified as malicious by AV, sandbox, or threat intelligence executed (even if later quarantined).',
      'The executed process launched script interpreters or LOLBins, downloaded additional files, or contacted unknown external hosts.',
      'Persistence (Run key, Startup item, scheduled task, service) was created after execution.',
      'The same file executed on more than one device.',
      'The user was instructed by a web page or caller to paste/run a command.',
      'You cannot reconstruct post-execution activity because telemetry is missing.',
    ],
    immediate: [
      'Signs of credential dumping, lateral movement, or ransomware behavior after execution.',
      'Execution on a server, domain controller, or privileged administrator workstation.',
      'Multiple hosts showing the same malicious execution chain.',
    ],
    benignClosure: [
      'Signed by a trusted publisher, present in the approved software catalog or matching an approved request.',
      'Normal prevalence in the organization and clean reputation.',
      'No suspicious child processes, network destinations, or persistence after execution.',
    ],
  },
  queries: [
    {
      id: 'kql-exec-tree',
      title: 'Process activity around the execution on the host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists processes started by common lure parents (Explorer, Office, browsers, archivers) and suspicious interpreters on the host from 30 minutes before to 2 hours after the alert.',
      dataSources: ['DeviceProcessEvents'],
      query: `let alertTime = datetime({{alert_time}});
DeviceProcessEvents
| where DeviceName =~ "{{hostname}}"
| where Timestamp between ((alertTime - 30m) .. (alertTime + 2h))
| where InitiatingProcessFileName in~ ("explorer.exe", "outlook.exe", "winword.exe",
        "excel.exe", "powerpnt.exe", "onenote.exe", "acrord32.exe", "msedge.exe",
        "chrome.exe", "firefox.exe", "7zfm.exe", "winrar.exe")
    or FileName in~ ("wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "msiexec.exe",
        "certutil.exe", "curl.exe", "bitsadmin.exe")
| project Timestamp, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine,
          SHA256, ProcessId, InitiatingProcessId
| order by Timestamp asc`,
      placeholders: [PH.alertTime(), PH.hostname()],
      keyFields: [
        { name: 'InitiatingProcessFileName', meaning: 'Parent process - how the file was launched.' },
        { name: 'ProcessCommandLine', meaning: 'Arguments of the child; look for encoded commands, URLs, and user-writable paths.' },
        { name: 'ProcessId / InitiatingProcessId', meaning: 'Use to link parent and child rows into a tree.' },
      ],
      positive: 'Rows show candidate process chains to review. A matching row is not malicious by itself - Explorer launches almost everything a user double-clicks.',
      negative: 'No rows can mean the device name differs (FQDN vs short name), the time is in another timezone, or the device has no Defender sensor. It does not prove nothing executed.',
      prerequisites: 'Defender for Endpoint onboarded device; advanced hunting or Sentinel read access.',
      schemaNotes: 'DeviceName is usually the FQDN in Defender; =~ is case-insensitive but exact - use startswith or has for short names.',
      example: 'hostname = ws-demo-0142.corp.example.com, alert_time = 2026-10-10T14:03:11Z',
    },
    {
      id: 'kql-file-origin',
      title: 'Origin and prevalence of a file by SHA-256',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Shows every device where the file was written, with download URL/referrer when recorded, to identify the source and other exposed devices.',
      dataSources: ['DeviceFileEvents'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where SHA256 == "{{sha256}}"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileOriginUrl,
          FileOriginReferrerUrl, FileOriginIP, InitiatingProcessFileName,
          InitiatingProcessAccountName
| order by Timestamp asc`,
      placeholders: [PH.lookback('30d'), { name: 'sha256', kind: 'string', description: 'SHA-256 of the executed file (lowercase hex).', example: '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0' }],
      keyFields: [
        { name: 'FileOriginUrl / FileOriginReferrerUrl', meaning: 'Download URL and the page that linked to it (when the browser records Mark-of-the-Web).' },
        { name: 'DeviceName', meaning: 'Count distinct devices to judge prevalence.' },
      ],
      positive: 'Shows where the file landed and possibly where it came from. Multiple devices means a wider exposure to scope.',
      negative: 'Empty results may mean the file was created by a process the sensor did not record, or the hash differs per victim (polymorphic samples). Search by FileName as a fallback.',
      prerequisites: 'Defender for Endpoint file telemetry; 30-day advanced hunting retention.',
      schemaNotes: 'FileOrigin* columns are only populated when origin information was available to the sensor.',
      example: 'sha256 = (from the alert), lookback = 30d',
    },
    {
      id: 'spl-office-children',
      title: 'Office, browser, or Explorer launching interpreters (CIM Endpoint)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds interpreter and LOLBin processes whose parent is an Office app, browser, or Explorer on the host.',
      dataSources: ['CIM Endpoint.Processes (EDR, Sysmon Event 1, or Security 4688 mapped to CIM)'],
      query: `| tstats summariesonly=false count min(_time) as first_seen
    values(Processes.process) as command_lines
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}} Processes.dest="{{hostname}}"
      (Processes.parent_process_name="winword.exe" OR Processes.parent_process_name="excel.exe"
       OR Processes.parent_process_name="powerpnt.exe" OR Processes.parent_process_name="outlook.exe"
       OR Processes.parent_process_name="onenote.exe" OR Processes.parent_process_name="explorer.exe"
       OR Processes.parent_process_name="msedge.exe" OR Processes.parent_process_name="chrome.exe")
      (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe"
       OR Processes.process_name="mshta.exe" OR Processes.process_name="rundll32.exe"
       OR Processes.process_name="regsvr32.exe" OR Processes.process_name="powershell.exe"
       OR Processes.process_name="cmd.exe")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| convert ctime(first_seen)`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [
        { name: 'Processes.parent_process_name', meaning: 'How the interpreter was launched.' },
        { name: 'command_lines', meaning: 'Full command lines - review each one.' },
      ],
      positive: 'Interpreter launched by an Office app or browser is a strong lead. Explorer-launched interpreters are common for admins and need context.',
      negative: 'Empty results may mean the Endpoint data model is not populated for this host or command-line logging is disabled.',
      prerequisites: 'Process creation data mapped to CIM Endpoint.Processes.',
      schemaNotes: 'Host naming (dest) and process_name casing depend on the add-on. If tstats is not available to your role, search the raw Sysmon/EDR index instead.',
      example: 'hostname = WS-DEMO-0142, lookback = 24h',
    },
    {
      id: 'spl-zone-identifier',
      title: 'Download source from Mark-of-the-Web (Sysmon Event 15)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Recovers the HostUrl/ReferrerUrl written to the Zone.Identifier alternate data stream when the file was downloaded.',
      dataSources: ['Sysmon Event 15 (FileCreateStreamHash)'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=15 host="{{hostname}}" TargetFilename="*{{file_name}}*" earliest=-{{lookback}}
| table _time host User Image TargetFilename Contents
| sort _time`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Splunk index that holds Sysmon events in your environment (ask your Splunk admin).', example: 'sysmon' },
        PH.hostname(),
        { name: 'file_name', kind: 'string', description: 'Name of the executed/downloaded file.', example: 'Invoice_2026.iso' },
        PH.lookback('7d'),
      ],
      keyFields: [
        { name: 'Contents', meaning: 'Zone.Identifier text: ZoneId=3 (Internet), HostUrl, ReferrerUrl.' },
        { name: 'Image', meaning: 'Process that wrote the file (browser, mail client, archiver).' },
      ],
      positive: 'HostUrl shows the download location - add it to indicators and check other users who visited it.',
      negative: 'Empty results are common: Event 15 must be enabled in the Sysmon config, and files from archives, ISOs, or some apps may not carry Mark-of-the-Web.',
      prerequisites: 'Sysmon with FileCreateStreamHash enabled; Sysmon channel indexed.',
      schemaNotes: 'The Contents field is only captured by Sysmon versions/configs that record stream contents. Source/sourcetype naming depends on the add-on version.',
      example: 'index = sysmon, file_name = Invoice_2026.iso',
    },
    {
      id: 'generic-user-exec',
      title: 'Generic user-execution procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral steps for reconstructing a user-launched execution.',
      dataSources: ['Process creation', 'File creation', 'Network connections'],
      query: `1. Process tree: on the host, list processes from 30 min before to 2 h after the alert.
   Identify the executed file and its parent (explorer, mail client, browser, archiver).
2. Origin: find the file creation event for the same path/hash; record the creating process
   and any download URL (Mark-of-the-Web / proxy log at the same time).
3. Forward activity: children, files written to AppData/Temp/ProgramData, autostart
   registry or task changes, and outbound connections from the process tree.
4. Prevalence: count devices with the same hash in the last 30 days.
5. Record each data source searched, the time range, and the result.`,
      placeholders: [],
      keyFields: [],
      positive: 'Each finding is a lead to confirm with the decision tree.',
      negative: 'A clean result only covers the sources and time range you searched.',
      prerequisites: 'EDR or equivalent process telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Explorer.exe is the parent of nearly every user double-click, so parent/child rules alone are noisy - combine with path, signer, and prevalence.',
    'Paste-and-run lures (T1204.004) show explorer.exe launching powershell/mshta directly; the RunMRU registry key can record the pasted command.',
    'Archive and ISO containers can strip Mark-of-the-Web, which defeats some Office macro protections.',
  ],
  visibilityGaps: [
    'Command lines are missing if relying on Security 4688 without command-line auditing.',
    'Short-lived processes may be missed by sensors that sample or throttle.',
    'macOS and Linux endpoints may lack equivalent origin metadata.',
  ],
  relatedTechniques: [
    { id: 'T1566', reason: 'Most malicious files and links arrive by phishing.' },
    { id: 'T1059.001', reason: 'PowerShell is a common second stage after a user opens a file.' },
    { id: 'T1218.005', reason: 'mshta.exe is frequently used by HTA and paste-and-run lures.' },
    { id: 'T1027.006', reason: 'HTML smuggling builds the malicious file inside the browser.' },
    { id: 'T1553.005', reason: 'ISO/IMG/archive containers are used to bypass Mark-of-the-Web.' },
    { id: 'T1105', reason: 'Initial payloads usually download additional tools.' },
    { id: 'T1547.001', reason: 'Run keys are a common first persistence mechanism.' },
  ],
  references: [
    attackRef('T1204', 'User Execution'),
    attackRef('T1204.004', 'Malicious Copy and Paste'),
    { title: 'Microsoft Learn - DeviceProcessEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table' },
    { title: 'Microsoft Learn - DeviceFileEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table' },
    { title: 'Sysinternals Sysmon', url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon' },
  ],
  assumptions: [
    'Tier 1 does not isolate devices or delete files; containment is requested through the escalation path.',
    'Uploading files to public sandboxes follows your data-handling policy.',
  ],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

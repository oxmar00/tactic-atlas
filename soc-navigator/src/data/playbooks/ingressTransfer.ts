import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const ingressTransfer: Playbook = {
  schemaVersion: 1,
  id: 'PB-INGRESS-001',
  version: '1.0.0',
  title: 'Ingress tool transfer (download of tools or payloads)',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1105'],
  tactics: ['command-and-control'],
  objective:
    'Determine what was downloaded, from where, by which process, and whether the downloaded file was executed - and decide whether it is legitimate software retrieval or an attacker bringing tools onto the host.',
  alertMeaning:
    'A process downloaded a file in a way that matches attacker tradecraft: built-in utilities used as downloaders (certutil, bitsadmin, curl, PowerShell), downloads from raw IP addresses or file-sharing sites, or an executable written to a user-writable folder by a non-browser process.',
  whyItMatters:
    'After initial access, attackers download their real tooling (remote-access tools, credential dumpers, ransomware). Catching the transfer can stop the intrusion before those tools run.',
  difficulty: 'Intermediate',
  effort: '30-45 minutes',
  platforms: ['Windows', 'Linux', 'macOS'],
  logSources: ['mde', 'edr', 'proxy', 'firewall', 'dns', 'sysmon'],
  alertContext: {
    triggers: [
      'certutil.exe -urlcache -f / -split, bitsadmin /transfer, curl/wget, PowerShell Invoke-WebRequest / DownloadFile writing a file.',
      'Executable, DLL, script, or archive created in AppData, Temp, ProgramData, or Public by a non-browser process.',
      'Download from a raw IP address, paste site, newly registered domain, or public file-sharing service.',
      'Linux: curl/wget piping into sh/bash, or downloads into /tmp or /dev/shm followed by chmod +x.',
    ],
    reviewFirst: ['Downloading process and command line.', 'Source URL/IP/domain.', 'Destination file path, name, type, and SHA-256.', 'Whether the file was later executed.'],
    oftenMissing: ['File reputation and prevalence.', 'What launched the downloader (parent chain).', 'Other hosts contacting the same source.'],
  },
  prerequisites: [
    { text: 'Process creation with command lines.', type: 'telemetry', required: true },
    { text: 'File creation events with hashes.', type: 'telemetry', required: true },
    { text: 'Network/proxy/DNS logs to confirm the source and bytes transferred.', type: 'telemetry', required: false },
    { text: 'Reputation or sandbox service for the file and domain.', type: 'tool', required: true },
  ],
  steps: [
    {
      id: 'download-details',
      title: 'Capture the download: process, source, destination file',
      action:
        'Record the downloading process, full command line, account, source URL/IP, destination path, file name, size, and SHA-256. Defang URLs in your notes (hxxp, [.]).',
      why: 'These are the indicators needed for every later check and for blocking.',
      where: ['DeviceProcessEvents', 'DeviceFileEvents (FileOriginUrl)', 'DeviceNetworkEvents', 'Proxy logs'],
      fields: ['ProcessCommandLine', 'RemoteUrl / RemoteIP', 'FolderPath', 'FileName', 'SHA256', 'FileSize'],
      suspicious: ['certutil -urlcache or bitsadmin /transfer used to fetch a file', 'Source is a raw IP or a dynamic DNS / file-sharing domain', 'File extension mismatch (e.g. .jpg that is actually an executable)'],
      legitimate: ['Package managers or software updaters fetching from their official repositories'],
      next: 'Identify what launched the downloader.',
      queryIds: ['kql-lolbin-downloads', 'spl-lolbin-downloads'],
    },
    {
      id: 'lineage',
      title: 'Identify what launched the downloader',
      action: 'Walk the parent chain of the downloading process. Note whether it began with a user action, an Office document, a script, a service, a scheduled task, or a remote session.',
      why: 'The parent chain shows whether this is the second stage of an infection or an admin task.',
      where: ['EDR process tree', 'DeviceProcessEvents InitiatingProcess*'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'InitiatingProcessParentFileName'],
      suspicious: ['Office/script host/mshta parent', 'WmiPrvSE.exe or services.exe parent soon after a remote logon'],
      legitimate: ['IT deployment script from the management agent'],
      next: 'If the parent is itself suspicious, include its alert or playbook in the investigation.',
      queryIds: [],
    },
    {
      id: 'file-analysis',
      title: 'Assess the downloaded file',
      action: 'Check reputation, signer, prevalence, and file type. If permitted, submit to the approved sandbox. Recognize common attacker tool categories (remote-access tools, tunneling tools, credential tools, archivers, scanners).',
      why: 'Many attacker tools are legitimate utilities (remote admin tools, tunnelers) - the question is whether they are approved here.',
      where: ['EDR file page', 'Threat intelligence', 'Sandbox', 'Approved software list'],
      fields: ['SHA256', 'Signer', 'Prevalence', 'Verdict'],
      suspicious: ['Remote-access or tunneling tool not on the approved list', 'Unsigned binary first seen in the organization today'],
      legitimate: ['Approved tool from the vendor\'s official site, matching a ticket'],
      next: 'Check whether it executed.',
      queryIds: [],
    },
    {
      id: 'execution',
      title: 'Check whether the file was executed and what followed',
      action: 'Search for process creation of the downloaded file (by path or hash) and its subsequent network connections, child processes, and persistence.',
      why: 'A downloaded tool that ran is an active threat; one that never ran may still be waiting.',
      where: ['DeviceProcessEvents (SHA256 / FolderPath)', 'DeviceNetworkEvents', 'Registry / task events'],
      fields: ['Execution time', 'Child processes', 'Network destinations'],
      suspicious: ['Execution followed by outbound connections or new services/tasks'],
      legitimate: ['Installer executed as part of a documented install'],
      next: 'Record outcomes, then scope.',
      queryIds: ['kql-downloaded-file-exec'],
    },
    {
      id: 'scope',
      title: 'Scope the source and file across the environment',
      action: 'Search for other hosts that contacted the same source domain/IP or have the same file hash.',
      why: 'The same staging server is often used against many hosts.',
      where: ['Proxy / DNS / firewall logs', 'DeviceFileEvents by SHA256', 'DeviceNetworkEvents by RemoteIP'],
      fields: ['Host list', 'First/last contact'],
      suspicious: ['Multiple hosts downloading from the same unusual source'],
      legitimate: ['Source is a widely used vendor CDN'],
      next: 'Use the decision tree.',
      queryIds: ['spl-proxy-source'],
    },
  ],
  decisionTree: {
    start: 'legit-source',
    nodes: [
      {
        id: 'legit-source',
        question: 'Is the download an approved software retrieval - official vendor/repository source, expected process (updater, package manager, management agent), signed and approved file?',
        yes: { outcome: 'benign', guidance: 'Record source, process, signer, and approval evidence.' },
        no: { next: 'executed', guidance: 'Not verified as approved.' },
      },
      {
        id: 'executed',
        question: 'Was the downloaded file executed (or loaded) on the host?',
        yes: { next: 'malicious-behavior', guidance: 'Determine what it did.' },
        no: { next: 'file-verdict', guidance: 'Not executed yet - judge the file itself.' },
        unknown: { outcome: 'gap', guidance: 'Cannot confirm execution (missing process telemetry). Record the gap and escalate per policy.' },
      },
      {
        id: 'file-verdict',
        question: 'Is the file malicious, an unapproved remote-access/tunneling/credential tool, or unknown with a suspicious source?',
        yes: { outcome: 'escalate', guidance: 'Attacker tooling staged on the host. Escalate before it is used.' },
        no: { outcome: 'investigate', guidance: 'Unverified but not clearly malicious. Confirm with the user/owner; escalate if unverified.' },
      },
      {
        id: 'malicious-behavior',
        question: 'After execution, did the tool access credentials, appear on multiple hosts, or run on a server or domain controller?',
        yes: { outcome: 'critical', guidance: 'Active attacker tooling with broad impact. Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Unapproved tool executed on a single host. Escalate with download details, execution, network destinations, and any persistence.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('hostname', true),
    ev('username', true),
    ev('process', true, 'Downloading process (certutil.exe, bitsadmin.exe, powershell.exe, curl, ...).'),
    ev('command_line', true),
    ev('parent_process', false),
    evCustom('download_source', 'Download source', 'URL / domain / IP (defanged), with reputation.', true, true),
    ev('file_hash', true, 'Downloaded file: path, name, size, SHA-256, signer.'),
    evCustom('file_execution', 'Execution of the downloaded file', 'Executed? When? What followed?', false, true),
    ev('affected_assets', false, 'Other hosts contacting the same source or holding the same hash.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Built-in utilities (certutil, bitsadmin, PowerShell, curl/wget) used to download executables or scripts without an approved purpose.',
      'Download of remote-access, tunneling, scanning, or credential tools not on the approved list.',
      'Download from raw IPs, paste/file-sharing sites, or newly registered domains.',
      'Downloaded file executed, or execution status cannot be determined.',
    ],
    immediate: [
      'Downloaded tool executed and connected out, created persistence, or accessed credentials.',
      'Same source/file seen on multiple hosts.',
      'Transfer occurred on a server or domain controller.',
    ],
    benignClosure: ['Official source, expected process, signed and approved file, matching ticket or software catalog.'],
  },
  queries: [
    {
      id: 'kql-lolbin-downloads',
      title: 'Built-in utilities used to download files',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds certutil, bitsadmin, curl, wget, and PowerShell download patterns on a host.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "verifyctl"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "transfer")
    or (FileName in~ ("curl.exe", "wget.exe") and ProcessCommandLine has "http")
    or (FileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has_any ("DownloadFile", "Invoke-WebRequest", "Start-BitsTransfer", "wget ", "curl "))
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [{ name: 'ProcessCommandLine', meaning: 'Contains the source URL and output path.' }],
      positive: 'Each row is a download to attribute. Admin scripts use some of these legitimately.',
      negative: 'Custom downloaders or in-memory downloads do not create these process patterns; check network and file events too.',
      prerequisites: 'Defender for Endpoint process telemetry.',
      schemaNotes: 'In PowerShell, "wget" and "curl" can be aliases of Invoke-WebRequest (Windows PowerShell 5.1).',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'kql-downloaded-file-exec',
      title: 'Was a downloaded file executed?',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds executions of a file by SHA-256 on any device and the network connections they made.',
      dataSources: ['DeviceProcessEvents', 'DeviceNetworkEvents'],
      query: `let fileHash = "{{sha256}}";
let since = ago({{lookback}});
let execs = DeviceProcessEvents
    | where Timestamp > since and SHA256 == fileHash
    | project Timestamp, DeviceId, DeviceName, AccountName, FolderPath, ProcessCommandLine, ProcessId;
execs
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > since and InitiatingProcessSHA256 == fileHash
    | summarize Destinations = make_set(strcat(RemoteIP, ":", tostring(RemotePort), " ", RemoteUrl), 25)
              by DeviceId, InitiatingProcessId
  ) on $left.DeviceId == $right.DeviceId and $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, Destinations
| order by Timestamp asc`,
      placeholders: [{ name: 'sha256', kind: 'string', description: 'SHA-256 of the downloaded file.', example: '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0' }, PH.lookback('7d')],
      keyFields: [{ name: 'Destinations', meaning: 'Network destinations contacted by the executed file.' }],
      positive: 'Execution rows confirm the tool ran; destinations show possible C2.',
      negative: 'DLLs loaded by another process or scripts run by an interpreter will not match by process SHA256.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'ProcessId values are reused over time; the join is scoped by DeviceId and window.',
      example: 'sha256 = (from the alert)',
    },
    {
      id: 'spl-lolbin-downloads',
      title: 'Built-in downloaders (CIM Endpoint.Processes)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds certutil/bitsadmin/curl/wget download command lines across hosts.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen values(Processes.process) as command_lines
    values(Processes.parent_process_name) as parents
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}}
      ((Processes.process_name="certutil.exe" Processes.process="*urlcache*")
       OR (Processes.process_name="bitsadmin.exe" Processes.process="*transfer*")
       OR ((Processes.process_name="curl.exe" OR Processes.process_name="wget.exe") Processes.process="*http*"))
    by Processes.dest Processes.user Processes.process_name
| convert ctime(first_seen)
| sort - first_seen`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'command_lines', meaning: 'Source URL and output path.' }],
      positive: 'Download activity to review.',
      negative: 'PowerShell-based downloads need the PowerShell playbook queries.',
      prerequisites: 'Process data mapped to CIM.',
      schemaNotes: 'Field names depend on add-ons.',
      example: 'lookback = 7d',
    },
    {
      id: 'spl-proxy-source',
      title: 'Hosts that contacted a download source (CIM Web)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Lists all hosts and users that requested the same domain through the proxy, with bytes received.',
      dataSources: ['CIM Web data model'],
      query: `| tstats summariesonly=false count sum(Web.bytes_in) as bytes_in min(_time) as first_seen max(_time) as last_seen
    values(Web.url) as urls
    from datamodel=Web
    where earliest=-{{lookback}} Web.dest="{{domain}}"
    by Web.src Web.user
| convert ctime(first_seen) ctime(last_seen)`,
      placeholders: [PH.lookback('7d'), { name: 'domain', kind: 'string', description: 'Source domain or IP of the download.', example: 'files.example-share.test' }],
      keyFields: [{ name: 'bytes_in', meaning: 'Size of content received; large values suggest a file download.' }],
      positive: 'Other hosts contacting the same source expand scope.',
      negative: 'Direct-to-IP or non-proxied traffic will not appear; check firewall logs.',
      prerequisites: 'Proxy logs mapped to CIM Web.',
      schemaNotes: 'Web.dest may be a hostname or IP depending on the proxy.',
      example: 'domain = files.example-share.test',
    },
    {
      id: 'generic-ingress',
      title: 'Generic ingress-transfer procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Process, file, network, proxy logs'],
      query: `1. Download command line, source URL/IP, output path, hash.
2. Parent chain of the downloader.
3. File reputation, signer, prevalence, approval status.
4. Execution of the file (by path/hash) and its network/persistence activity.
5. Other hosts contacting the same source or holding the same hash.`,
      placeholders: [],
      keyFields: [],
      positive: 'Unapproved tools and executions drive escalation.',
      negative: 'Record sources you could not search.',
      prerequisites: 'Endpoint and network telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: ['Downloads over HTTPS hide URLs from network logs without TLS inspection; rely on endpoint command lines and file events.', 'Attackers often rename utilities; match on original file name/signature where available.'],
  visibilityGaps: ['In-memory payloads never touch disk.', 'Downloads on Linux/macOS hosts without EDR are invisible.'],
  relatedTechniques: [
    { id: 'T1059.001', reason: 'PowerShell download cradles.' },
    { id: 'T1219', reason: 'Remote access tools are commonly downloaded after initial access.' },
    { id: 'T1570', reason: 'Lateral tool transfer moves tools between internal hosts.' },
    { id: 'T1071.001', reason: 'Downloads typically use HTTP(S).' },
    { id: 'T1140', reason: 'Downloaded content is often encoded and decoded on the host (e.g. certutil -decode).' },
  ],
  references: [
    attackRef('T1105', 'Ingress Tool Transfer'),
    { title: 'LOLBAS project - Certutil', url: 'https://lolbas-project.github.io/lolbas/Binaries/Certutil/' },
    { title: 'Microsoft Learn - DeviceNetworkEvents table', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table' },
  ],
  assumptions: ['An approved list of remote-access and admin tools exists.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

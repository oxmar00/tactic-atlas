import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const credentialDumping: Playbook = {
  schemaVersion: 1,
  id: 'PB-CREDDUMP-001',
  version: '1.0.0',
  title: 'Credential dumping indicators (LSASS, SAM, NTDS, DCSync)',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1003', 'T1003.001', 'T1003.002', 'T1003.003', 'T1003.006'],
  tactics: ['credential-access'],
  objective:
    'Determine whether a credential store was actually accessed or copied, by which process and account, and whether stolen credentials may already be in use elsewhere.',
  alertMeaning:
    'A detection saw behavior associated with credential theft: a process opening LSASS memory, a memory dump of lsass.exe, saving the SAM/SECURITY/SYSTEM registry hives, copying ntds.dit, or a non-domain-controller account requesting directory replication (DCSync).',
  whyItMatters:
    'Credential dumping usually means an attacker already has administrator rights on a host and is collecting passwords and hashes to move to other systems. Dumping on a domain controller can expose every account in the domain.',
  difficulty: 'Advanced',
  effort: '45-90 minutes (escalate early; do not wait to finish)',
  platforms: ['Windows'],
  logSources: ['mde', 'sysmon', 'win-security', 'edr', 'av'],
  alertContext: {
    triggers: [
      'Process opened lsass.exe with memory-read access (EDR, Sysmon 10).',
      'Command lines such as procdump -ma lsass, rundll32 comsvcs.dll MiniDump, or a .dmp file named like lsass.',
      'reg.exe save of HKLM\\SAM, HKLM\\SECURITY, or HKLM\\SYSTEM.',
      'ntdsutil "ifm" / Volume Shadow Copy used to copy ntds.dit on a domain controller.',
      'Directory replication (DCSync) requested by an account that is not a domain controller (4662 or identity-threat alert).',
    ],
    reviewFirst: [
      'Which credential store: LSASS memory, local SAM hives, NTDS.dit, or DCSync.',
      'Process image path, signer, and command line; account and logon session.',
      'Whether EDR blocked the action.',
      'Host role: workstation, server, or domain controller.',
    ],
    oftenMissing: [
      'Whether the dump file was moved off the host.',
      'Which accounts had credentials on the host at the time (logged-on and cached users).',
      'How the actor obtained administrator rights.',
    ],
  },
  prerequisites: [
    { text: 'EDR or Sysmon process-access telemetry for LSASS (Sysmon 10 / EDR open-process events).', type: 'telemetry', required: true },
    { text: 'Process creation with command lines.', type: 'telemetry', required: true },
    { text: 'Domain controller Security logs (4662 with Directory Service Access auditing) for DCSync.', type: 'telemetry', required: false },
    { text: 'List of security products allowed to access LSASS (AV/EDR/backup agents).', type: 'information', required: true },
    { text: 'Direct escalation contact for credential-theft cases (these are time-critical).', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'variant',
      title: 'Identify the credential store and whether the action was blocked',
      action:
        'Record which variant fired (LSASS memory, SAM/SECURITY/SYSTEM hives, NTDS.dit, DCSync) and the EDR action (blocked, detected only). Note the host role and whether Credential Guard or LSA protection (RunAsPPL) is enabled if your asset inventory shows it.',
      why: 'The variant determines impact: LSASS exposes logged-on users; SAM exposes local accounts; NTDS/DCSync exposes the whole domain.',
      where: ['EDR alert', 'Asset inventory / CMDB', 'Identity threat detection alert (DC variants)'],
      fields: ['Alert category', 'Action taken', 'Host role', 'Protection status'],
      suspicious: ['Detected but not blocked', 'Any variant on a domain controller'],
      legitimate: ['Alert raised on a known security product\'s scan of LSASS (verify signer and path)'],
      next: 'Start the escalation clock now if the host is a domain controller or the action was not blocked; continue gathering evidence in parallel.',
      queryIds: [],
    },
    {
      id: 'accessing-process',
      title: 'Examine the process that accessed or dumped credentials',
      action:
        'Record the process image path, signer, SHA-256, command line, parent, and the access rights requested on LSASS (GrantedAccess / DesiredAccess). Check the call trace for dump functions (dbghelp.dll / dbgcore.dll MiniDumpWriteDump) when available.',
      why: 'Legitimate products access LSASS routinely; attackers use dump utilities, built-in DLL exports, or renamed tools. The image path and signer usually separate the two.',
      where: ['DeviceEvents (OpenProcessApiCall)', 'Sysmon 10 (ProcessAccess)', 'DeviceProcessEvents'],
      fields: ['InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine', 'GrantedAccess / DesiredAccess', 'CallTrace', 'SHA256'],
      suspicious: [
        'procdump(64).exe, rundll32.exe with comsvcs.dll MiniDump, or an unknown binary in Temp/ProgramData',
        'GrantedAccess values such as 0x1010, 0x1410, 0x1438, or 0x1FFFFF from a non-security process',
        'Renamed tool (file name does not match the original file name in its version info)',
        'Task Manager "Create dump file" on lsass.exe by a user',
      ],
      legitimate: ['MsMpEng.exe or the installed EDR agent from its install path, signed by the vendor', 'Windows Error Reporting handling an actual LSASS crash (rare - verify)'],
      next: 'If the process is a verified security product, document it. Otherwise look for the dump artifacts.',
      queryIds: ['kql-lsass-access', 'spl-lsass-sysmon10'],
    },
    {
      id: 'artifacts',
      title: 'Find dump files, hive copies, and their movement',
      action:
        'Search for .dmp files, files containing "lsass" in the name, saved hive files, or ntds.dit copies created around the alert time. Check whether they were compressed, renamed, copied to a share, or uploaded.',
      why: 'A dump file on disk confirms credential material was captured. If it left the host, the attacker can crack or replay credentials offline.',
      where: ['DeviceFileEvents', 'Sysmon 11 (FileCreate)', 'DeviceNetworkEvents / proxy logs after creation'],
      fields: ['FileName', 'FolderPath', 'SHA256', 'InitiatingProcessFileName', 'Subsequent file rename/copy events'],
      suspicious: ['lsass.dmp or random-named .dmp in Temp, ProgramData, or C:\\Windows\\Temp', 'Hive copies (sam, system, security) written to a writable folder', '7z/rar/zip created shortly after, or upload to an external host'],
      legitimate: ['Crash dumps under C:\\Windows\\Minidump or LocalDumps for a crashing application with a support ticket'],
      next: 'Record artifact paths and hashes. Do not delete them - preserve for Tier 2/IR.',
      queryIds: ['kql-dump-commands', 'kql-dump-files'],
    },
    {
      id: 'actor-session',
      title: 'Identify the account and how it obtained privileges',
      action:
        'Determine the account that ran the process and its logon session: logon type and source (4624), special privileges (4672), and when the session started. Check whether the account is normally an administrator on this host.',
      why: 'Dumping credentials requires administrator or SYSTEM rights. How the actor got those rights shows how far the intrusion has already progressed.',
      where: ['DeviceLogonEvents / Security 4624, 4672', 'Group membership changes (4732)', 'EDR timeline'],
      fields: ['AccountName', 'LogonType', 'RemoteIP', 'LogonId', 'IsLocalAdmin'],
      suspicious: ['Remote interactive or network logon from an unusual workstation', 'Account added to local Administrators shortly before', 'Service account used interactively'],
      legitimate: ['Named IT administrator performing a documented diagnostic with a ticket'],
      next: 'Record the account and source host - both are likely compromised.',
      queryIds: [],
    },
    {
      id: 'exposed-accounts',
      title: 'Identify exposed accounts and look for their reuse',
      action:
        'List accounts with interactive, remote-interactive, or service sessions on the host in the last days (credentials likely in LSASS). For each, check for new logons from this host to other systems after the dump, especially NTLM network logons and logons with LogonType 9 (NewCredentials).',
      why: 'Stolen credentials are used quickly for lateral movement. Finding reuse determines scope and urgency.',
      where: ['DeviceLogonEvents', 'Security 4624/4648 on other hosts', 'Domain controller 4768/4769/4776'],
      fields: ['AccountName', 'RemoteDeviceName', 'LogonType', 'Protocol (NTLM/Kerberos)'],
      suspicious: ['Privileged accounts (domain admins, server admins) had sessions on the host', 'Same accounts authenticate from the host to many other hosts after the alert'],
      legitimate: ['Only the local user\'s own account was present and no reuse is observed'],
      next: 'Provide the exposed-account list in the handoff - Tier 2 decides on password resets and session revocation.',
      queryIds: [],
    },
    {
      id: 'dcsync',
      title: 'Domain controllers: check for replication abuse (DCSync)',
      action:
        'On domain controllers, search 4662 events where the properties include the replication rights GUIDs (DS-Replication-Get-Changes 1131f6aa-..., DS-Replication-Get-Changes-All 1131f6ad-..., DS-Replication-Get-Changes-In-Filtered-Set 89e95b76-...) and the requesting account is not a domain controller computer account.',
      why: 'DCSync lets an attacker pull password hashes for any account - including krbtgt - without touching LSASS or ntds.dit on disk.',
      where: ['DC Security log 4662 (Directory Service Access auditing with SACL)', 'Identity threat detection (e.g. Microsoft Defender for Identity) alerts'],
      fields: ['SubjectUserName', 'SubjectDomainName', 'Properties', 'Computer (DC)'],
      suspicious: ['A user or non-DC computer account requesting Get-Changes-All'],
      legitimate: ['Domain controller computer accounts (ending in $) replicating normally', 'Directory synchronization service accounts (e.g. Microsoft Entra Connect) documented by the identity team'],
      next: 'Any unexplained replication request is a critical escalation.',
      queryIds: ['spl-dcsync-4662'],
    },
  ],
  decisionTree: {
    start: 'security-tool',
    nodes: [
      {
        id: 'security-tool',
        question: 'Was the access performed by a verified security product (correct signer and install path) or by an approved, ticketed diagnostic on this host?',
        help: 'Verify signer and path - attackers rename tools to look like security products.',
        yes: { outcome: 'benign', guidance: 'Record the product, signer, path, and ticket. Suggest an allow-list entry scoped to the signed path.' },
        no: { next: 'captured', guidance: 'Treat as attempted credential theft.' },
      },
      {
        id: 'captured',
        question: 'Is there evidence credentials were captured: a dump file, saved hives, an ntds.dit copy, a DCSync request, or memory-read access to LSASS by a non-security process that was not blocked?',
        yes: { next: 'scope', guidance: 'Credential material is likely exposed.' },
        no: { next: 'blocked', guidance: 'Determine whether the attempt was fully blocked.' },
      },
      {
        id: 'blocked',
        question: 'Do logs show the attempt was blocked (EDR prevention, LSA protection) and no other suspicious activity exists on the host?',
        yes: { outcome: 'escalate', guidance: 'A blocked attempt still means someone with admin rights tried to steal credentials. Escalate with the process details and account.' },
        no: { outcome: 'gap', guidance: 'You cannot tell whether access succeeded. Record the missing telemetry and escalate per policy - assume exposure until Tier 2 rules it out.' },
      },
      {
        id: 'scope',
        question: 'Did this occur on a domain controller, involve NTDS/DCSync, involve privileged accounts, or are exposed accounts already being used on other hosts?',
        yes: { outcome: 'critical', guidance: 'Domain-wide or active credential compromise. Follow the incident escalation procedure immediately.' },
        no: { outcome: 'escalate', guidance: 'Credential exposure on a single host. Escalate now with artifacts and the exposed-account list.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('hostname', true, 'Include host role (workstation / server / domain controller).'),
    ev('username', true, 'Account that ran the dumping process.'),
    ev('process', true, 'Accessing/dumping process with full path.'),
    ev('parent_process', true),
    ev('command_line', true),
    evCustom('access_rights', 'LSASS access rights / call trace', 'GrantedAccess or DesiredAccess value and notable call-trace modules.', false),
    evCustom('dump_artifacts', 'Dump artifacts', 'Paths, sizes, hashes of .dmp, hive copies, ntds.dit copies; whether moved or archived.', true, true),
    evCustom('exposed_accounts', 'Potentially exposed accounts', 'Accounts with sessions on the host; mark privileged ones.', true, true),
    ev('src_ip', false, 'Logon source of the actor session.'),
    ev('affected_assets', false, 'Hosts where exposed accounts were used afterwards.'),
    ev('event_ids', false, 'e.g. Sysmon 10 record, 4662 events with GUIDs, EDR ReportIds.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Any non-security process accessed LSASS memory or created an LSASS dump.',
      'SAM/SECURITY/SYSTEM hives were saved or copied by a non-backup process.',
      'Credential-dumping attempt was blocked but the actor and access path are unexplained.',
      'Telemetry is insufficient to determine whether credential material was captured.',
    ],
    immediate: [
      'Any credential-dumping indicator on a domain controller, or NTDS.dit copy, or DCSync from a non-DC account.',
      'Privileged/domain administrator accounts had sessions on the affected host.',
      'Exposed accounts are being used to log on to other hosts.',
      'Dump files were archived or transferred off the host.',
    ],
    benignClosure: [
      'Access by a verified security product (signer and path confirmed) or an approved diagnostic with a ticket.',
      'No dump artifacts, no unexplained privileged sessions, and no subsequent credential reuse.',
    ],
  },
  queries: [
    {
      id: 'kql-lsass-access',
      title: 'Processes opening LSASS on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists processes that opened a handle to lsass.exe, with the requested access rights.',
      dataSources: ['DeviceEvents (ActionType OpenProcessApiCall)'],
      query: `DeviceEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| extend DesiredAccess = tostring(parse_json(AdditionalFields).DesiredAccess)
| project Timestamp, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, DesiredAccess
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [
        { name: 'InitiatingProcessFolderPath', meaning: 'Verify security tools run from their install directory.' },
        { name: 'DesiredAccess', meaning: 'Requested rights; memory-read rights are needed to dump credentials.' },
      ],
      positive: 'Rows show which processes touched LSASS. Security products appear routinely - judge by signer, path, and command line.',
      negative: 'Defender samples/caps some API-call events, so no rows does not prove LSASS was not accessed. Check the alert evidence and file events too.',
      prerequisites: 'Defender for Endpoint P2 telemetry.',
      schemaNotes: 'For OpenProcessApiCall, FileName is the target process. AdditionalFields property names may vary; inspect a sample row.',
      example: 'hostname = ws-demo-0142.corp.example.com, lookback = 24h',
    },
    {
      id: 'kql-dump-commands',
      title: 'Command lines associated with credential dumping',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds common dumping command lines across all devices: LSASS dumps, hive saves, and NTDS extraction.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where (ProcessCommandLine has "lsass"
         and (ProcessCommandLine has_any ("MiniDump", "comsvcs", "procdump")
              or ProcessCommandLine contains " -ma "))
    or (FileName =~ "reg.exe" and ProcessCommandLine has "save"
        and ProcessCommandLine has_any (@"hklm\\sam", @"hklm\\security", @"hklm\\system"))
    or (FileName =~ "ntdsutil.exe" and ProcessCommandLine has "ifm")
    or ProcessCommandLine has "ntds.dit"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'ProcessCommandLine', meaning: 'Shows the dump method and output path.' }],
      positive: 'Matching rows are high-priority leads. Some backup/forensic tools use similar commands - verify ownership.',
      negative: 'Custom tools and in-memory techniques do not produce these command lines.',
      prerequisites: 'Defender for Endpoint process telemetry.',
      schemaNotes: 'has matches whole terms; renamed binaries are still caught by command-line content but not by FileName.',
      example: 'lookback = 7d',
    },
    {
      id: 'kql-dump-files',
      title: 'Dump and hive-copy files written on a host',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds .dmp files, files named like lsass, and ntds.dit copies created on the host.',
      dataSources: ['DeviceFileEvents'],
      query: `DeviceFileEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName endswith ".dmp" or FileName has "lsass" or FileName =~ "ntds.dit"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [{ name: 'FolderPath / InitiatingProcessFileName', meaning: 'Where the dump landed and which process wrote it.' }],
      positive: 'A dump of lsass by a non-security process is strong evidence of credential capture.',
      negative: 'Attackers can name dumps arbitrarily or never write to disk; no rows does not exclude in-memory theft.',
      prerequisites: 'Defender for Endpoint file telemetry.',
      schemaNotes: 'Standard Defender columns.',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'spl-lsass-sysmon10',
      title: 'Sysmon 10 process access to LSASS',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Sysmon)',
      purpose: 'Summarizes processes that accessed lsass.exe on a host with granted access and call traces.',
      dataSources: ['Sysmon Event 10 (ProcessAccess)'],
      query: `index="{{index}}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=10 TargetImage="*lsass.exe" host="{{hostname}}" earliest=-{{lookback}}
| stats count min(_time) as first_seen values(GrantedAccess) as granted_access
    values(CallTrace) as call_traces by host SourceImage SourceUser
| convert ctime(first_seen)
| sort - count`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Index holding Sysmon events.', example: 'sysmon' },
        PH.hostname(),
        PH.lookback('24h'),
      ],
      keyFields: [
        { name: 'SourceImage', meaning: 'Process that opened LSASS.' },
        { name: 'granted_access', meaning: 'Access mask; memory-read masks (e.g. 0x1010, 0x1410, 0x1FFFFF) are typical of dumping.' },
        { name: 'call_traces', meaning: 'dbghelp/dbgcore in the trace suggests MiniDumpWriteDump.' },
      ],
      positive: 'Non-security SourceImage values are leads requiring escalation.',
      negative: 'Many Sysmon configs filter Event 10 heavily; no events may be a configuration gap.',
      prerequisites: 'Sysmon with ProcessAccess rules for lsass.exe.',
      schemaNotes: 'SourceUser exists in recent Sysmon versions; older versions omit it.',
      example: 'index = sysmon, hostname = WS-DEMO-0142',
    },
    {
      id: 'spl-dcsync-4662',
      title: 'Directory replication requests by non-DC accounts (DCSync)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Finds 4662 events on domain controllers containing replication rights GUIDs from accounts that are not computer accounts.',
      dataSources: ['Domain controller Security EventCode 4662'],
      query: `index="{{index}}" source="XmlWinEventLog:Security" EventCode=4662 earliest=-{{lookback}}
    ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
     OR "89e95b76-444d-4c62-991a-0facbeda640c")
| where NOT like(SubjectUserName, "%$")
| stats count min(_time) as first_seen max(_time) as last_seen by host SubjectDomainName SubjectUserName
| convert ctime(first_seen) ctime(last_seen)`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding domain controller Security events.', example: 'wineventlog' }, PH.lookback('7d')],
      keyFields: [
        { name: 'SubjectUserName', meaning: 'Account that requested replication rights.' },
        { name: 'host', meaning: 'Domain controller that logged the request.' },
      ],
      positive: 'A user account requesting replication rights is a critical finding unless it is a documented sync service account.',
      negative: 'Requires Directory Service Access auditing and a SACL on the domain object; otherwise nothing is logged.',
      prerequisites: 'DC Security logs forwarded; audit policy for Directory Service Access.',
      schemaNotes: 'GUIDs: DS-Replication-Get-Changes 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2; DS-Replication-Get-Changes-All 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2; Get-Changes-In-Filtered-Set 89e95b76-444d-4c62-991a-0facbeda640c.',
      example: 'index = wineventlog',
    },
    {
      id: 'generic-creddump',
      title: 'Generic credential-dumping procedure',
      language: 'generic',
      platform: 'Any EDR / SIEM',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Process access', 'Process creation', 'File creation', 'Logon events'],
      query: `1. Process access to lsass.exe on the host +/- 1 hour: source image, signer, access mask.
2. Command lines containing lsass + dump keywords, reg save of SAM/SECURITY/SYSTEM, ntdsutil ifm.
3. Files created: *.dmp, names containing lsass, ntds.dit, hive copies; then archives/uploads.
4. Actor session: 4624/4672 for the account; source host and logon type.
5. Exposed accounts: sessions on the host; their logons to other hosts after the alert.
6. DCs only: 4662 with replication GUIDs from non-DC accounts.`,
      placeholders: [],
      keyFields: [],
      positive: 'Findings feed the decision tree - escalate early.',
      negative: 'Absence of logs is not absence of theft.',
      prerequisites: 'Endpoint and DC telemetry.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Security products legitimately open LSASS; allow-list by signer and full path, never by file name alone.',
    'Credential Guard and LSA protection reduce what can be dumped but do not stop all techniques.',
    'DCSync generates no activity on the attacker\'s host that looks like dumping - DC logs or identity threat detection are required.',
  ],
  visibilityGaps: [
    'Sysmon Event 10 is often filtered out for performance.',
    'Defender API-call events are sampled; a missing event is not proof.',
    'DC 4662 requires specific auditing and SACL configuration.',
  ],
  relatedTechniques: [
    { id: 'T1550.002', reason: 'Dumped NTLM hashes are reused via pass-the-hash.' },
    { id: 'T1021.002', reason: 'Stolen credentials are used for SMB/admin-share lateral movement.' },
    { id: 'T1078.002', reason: 'Dumped domain credentials become valid accounts for the attacker.' },
    { id: 'T1558.003', reason: 'Kerberoasting is an alternative credential-access path to check.' },
    { id: 'T1560.001', reason: 'Dump files are often archived before exfiltration.' },
  ],
  references: [
    attackRef('T1003.001', 'LSASS Memory'),
    attackRef('T1003.006', 'DCSync'),
    { title: 'Microsoft Learn - Configure added LSA protection', url: 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' },
    { title: 'Microsoft Learn - 4662(S, F): An operation was performed on an object', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662' },
  ],
  assumptions: ['Password resets and session revocation are performed by Tier 2/IR or the identity team, not by Tier 1.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, sigma, starterReview } from './helpers';

export const defenseTampering: Playbook = {
  schemaVersion: 1,
  id: 'PB-DEFTAMPER-001',
  version: '1.0.0',
  title: 'Security tool disabled or logging tampered with',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1685', 'T1685.001', 'T1685.005'],
  tactics: ['defense-impairment'],
  objective: 'Confirm whether a security control or log source was disabled, changed, or cleared, who did it, and whether it was authorized maintenance or an attacker reducing visibility.',
  alertMeaning: 'Antivirus or EDR protection was turned off or given new exclusions, a security service was stopped, the audit policy was changed, or a Windows event log was cleared.',
  whyItMatters: 'Attackers blind defenders before their main action. Tampering frequently comes minutes before credential theft or ransomware, and anything that happened while protection was off may not have been recorded.',
  difficulty: 'Intermediate',
  effort: '30-45 minutes',
  platforms: ['Windows', 'Linux', 'macOS'],
  logSources: ['mde', 'edr', 'av', 'win-security', 'sysmon'],
  alertContext: {
    triggers: ['Defender real-time protection disabled (5001) or configuration changed (5007), including new exclusions.', 'Commands such as Set-MpPreference -DisableRealtimeMonitoring, sc stop / net stop on security services, fltmc unload.', 'Security log cleared (1102), other log cleared (System 104), wevtutil cl, audit policy changed (4719).', 'EDR sensor health alert or tamper-protection block.'],
    reviewFirst: ['Which control was affected and whether the change succeeded or was blocked.', 'Process, command line, and account.', 'Host role and time.'],
    oftenMissing: ['What happened on the host while protection was reduced.', 'Whether a change ticket exists.'],
  },
  prerequisites: [
    { text: 'Process creation with command lines.', type: 'telemetry', required: true },
    { text: 'AV/EDR health and configuration events.', type: 'telemetry', required: true },
    { text: 'Security log events 1102 and 4719 from the host.', type: 'telemetry', required: false },
    { text: 'Change records and the list of approved exclusions.', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'what-changed',
      title: 'Identify exactly which control changed and whether it took effect',
      action: 'Record the control (real-time protection, exclusion path, EDR service, audit policy, event log), the new state, and whether tamper protection blocked the attempt.',
      why: 'A blocked attempt and a successful shutdown carry different risk, but both mean someone with admin rights tried.',
      where: ['Defender Operational log 5001/5007', 'EDR health console', 'Security 1102 / 4719', 'DeviceEvents'],
      fields: ['New value / old value', 'Exclusion path or extension', 'Cleared log name', 'Action result'],
      suspicious: ['Exclusion for a whole drive, Temp, ProgramData, or a script extension', 'Security log cleared', 'EDR service stopped outside maintenance'],
      legitimate: ['Exclusion on the approved list for a line-of-business application'],
      next: 'Identify who made the change.',
      queryIds: ['kql-tamper-commands', 'spl-tamper-commands', 'esql-tamper-commands'],
    },
    {
      id: 'actor',
      title: 'Identify the process, account, and session',
      action: 'Record the process and full command line, its parent chain, the account, and how that account logged on (type and source).',
      why: 'Management tooling changing settings under a service account is routine; a user session or script host doing it is not.',
      where: ['DeviceProcessEvents', 'Sysmon 1', 'Security 4624/4672'],
      fields: ['ProcessCommandLine', 'InitiatingProcessFileName', 'AccountName', 'LogonType', 'RemoteIP'],
      suspicious: ['PowerShell or cmd launched from Office, a script host, or a remote session', 'Account that does not administer this host'],
      legitimate: ['Endpoint management agent applying policy', 'Named administrator with a ticket'],
      next: 'Check change records.',
      queryIds: ['kql-tamper-commands'],
    },
    {
      id: 'authorization',
      title: 'Check for authorization',
      action: 'Look for a change ticket, vendor-support case, or approved-exclusion entry that matches the host, time, and setting.',
      why: 'Authorized maintenance is the main benign explanation and should be provable.',
      where: ['Change management system', 'Approved exclusion list'],
      fields: ['Ticket number', 'Approver'],
      suspicious: ['No record', 'Record exists but for a different host or time'],
      legitimate: ['Matching ticket and expected actor'],
      next: 'Examine what happened during the gap.',
      queryIds: [],
    },
    {
      id: 'gap-activity',
      title: 'Review activity during the protection gap',
      action: 'From 30 minutes before the change until protection returned, review process executions, new files, logons, and network connections on the host. If an exclusion was added, look specifically at files in the excluded path.',
      why: 'The tampering is preparation; the real objective usually runs immediately afterwards.',
      where: ['EDR timeline', 'DeviceProcessEvents / DeviceFileEvents', 'Network logs'],
      fields: ['Processes started', 'Files written in excluded paths', 'Outbound connections'],
      suspicious: ['New executable written to and run from the excluded path', 'Credential-dumping or archive tools run during the gap'],
      legitimate: ['Only the documented installer ran'],
      next: 'Record that telemetry may be incomplete for this window.',
      queryIds: [],
    },
    {
      id: 'scope-hosts',
      title: 'Check other hosts for the same change',
      action: 'Search all devices for the same command line, exclusion, or log-clearing event in the last 7 days.',
      why: 'Tampering pushed to many hosts at once is a common ransomware precursor.',
      where: ['DeviceProcessEvents across devices', 'AV configuration events'],
      fields: ['Device list', 'Timing'],
      suspicious: ['Same command on several hosts within minutes'],
      legitimate: ['Fleet-wide policy change with a ticket'],
      next: 'Use the decision tree.',
      queryIds: ['kql-log-cleared'],
    },
  ],
  decisionTree: {
    start: 'authorized',
    nodes: [
      { id: 'authorized', question: 'Is the change authorized - matching ticket or approved-exclusion entry, performed by the expected tool or administrator?', yes: { outcome: 'benign', guidance: 'Document the ticket, actor, and setting.' }, no: { next: 'effective', guidance: 'Unauthorized change or attempt.' } },
      { id: 'effective', question: 'Did the change take effect (protection off, exclusion added, service stopped, or log cleared)?', yes: { next: 'follow-on', guidance: 'Visibility was reduced.' }, no: { outcome: 'escalate', guidance: 'Blocked attempt by an actor with admin rights. Escalate with the command and account.' } },
      { id: 'follow-on', question: 'Was there suspicious activity during the gap, a security log cleared, or the same change on multiple hosts?', yes: { outcome: 'critical', guidance: 'Likely preparation for a larger action. Follow the incident escalation procedure now.' }, no: { outcome: 'escalate', guidance: 'Unauthorized reduction of protection. Escalate and note that telemetry for the gap may be incomplete.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'When protection changed and when it was restored (UTC).'),
    ev('hostname', true),
    ev('username', true),
    evCustom('control_changed', 'Control changed and new state', 'e.g. Defender exclusion added for C:\\Users\\Public; Security log cleared.', true, true),
    ev('process', true),
    ev('command_line', true),
    evCustom('authorization', 'Authorization checked', 'Ticket number or "none found", and where you looked.', true),
    evCustom('gap_activity', 'Activity during the gap', 'Processes, files, connections of note.', false, true),
    ev('affected_assets', false),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['Protection disabled, exclusion added, or security service stopped without authorization.', 'Tampering attempt blocked but the actor is unexplained.', 'Audit policy weakened without a change record.'],
    immediate: ['Security event log cleared without authorization.', 'Same tampering on multiple hosts.', 'Suspicious execution, credential access, or mass file changes during the gap.', 'Tampering on a domain controller or backup server.'],
    benignClosure: ['Matching change record or approved-exclusion entry, expected actor, and nothing unusual during the window.'],
  },
  queries: [
    {
      id: 'kql-tamper-commands',
      title: 'Commands that disable protection or clear logs',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds common tampering command lines on a host.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where DeviceName =~ "{{hostname}}"
| where (ProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference")
         and ProcessCommandLine has_any ("Disable", "Exclusion"))
    or (FileName in~ ("sc.exe", "net.exe", "net1.exe") and ProcessCommandLine has_any ("stop", "delete", "disabled")
        and ProcessCommandLine has_any ("WinDefend", "Sense", "MsMpSvc", "Sysmon", "EventLog"))
    or (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl", "clear-log"))
    or (ProcessCommandLine has "Clear-EventLog")
    or (FileName =~ "auditpol.exe" and ProcessCommandLine has_any ("/clear", "/remove", "disable"))
    or (FileName =~ "fltmc.exe" and ProcessCommandLine has "unload")
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc`,
      placeholders: [PH.lookback('24h'), PH.hostname()],
      keyFields: [{ name: 'ProcessCommandLine', meaning: 'The exact setting or service targeted.' }],
      positive: 'Each row is a tampering action or attempt to attribute. Management tools run some of these legitimately.',
      negative: 'Changes made through the registry, Group Policy, or vendor consoles do not appear as these commands.',
      prerequisites: 'Defender for Endpoint process telemetry.',
      schemaNotes: 'Extend the service list with your EDR and logging agents.',
      example: 'hostname = ws-demo-0142.corp.example.com',
    },
    {
      id: 'kql-log-cleared',
      title: 'Security log cleared or audit policy changed',
      language: 'kql',
      platform: 'Microsoft Sentinel (Windows Security Events connector)',
      purpose: 'Lists audit-log-cleared (1102) and audit-policy-change (4719) events across hosts.',
      dataSources: ['SecurityEvent'],
      query: `SecurityEvent
| where TimeGenerated > ago({{lookback}})
| where EventID in (1102, 4719)
| project TimeGenerated, Computer, EventID, Activity, Account, SubjectUserName
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'Account / SubjectUserName', meaning: 'Who cleared the log or changed the policy.' }],
      positive: 'Log clearing outside documented maintenance is rarely legitimate.',
      negative: 'If the host does not forward its Security log, the clearing is not visible centrally.',
      prerequisites: 'Security events collected from the host.',
      schemaNotes: 'The account for 1102 may appear in different columns depending on the agent.',
      example: 'lookback = 7d',
    },
    {
      id: 'spl-tamper-commands',
      title: 'Protection-tampering commands (CIM Endpoint.Processes)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds Defender-disable, log-clear, and audit-policy commands across hosts.',
      dataSources: ['CIM Endpoint.Processes'],
      query: `| tstats summariesonly=false count min(_time) as first_seen values(Processes.process) as command_lines
    from datamodel=Endpoint.Processes
    where earliest=-{{lookback}}
      (Processes.process="*Set-MpPreference*Disable*" OR Processes.process="*Add-MpPreference*Exclusion*"
       OR Processes.process="*wevtutil* cl *" OR Processes.process="*Clear-EventLog*"
       OR Processes.process="*auditpol*/clear*" OR Processes.process="*fltmc*unload*")
    by Processes.dest Processes.user Processes.parent_process_name
| convert ctime(first_seen)
| sort first_seen`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'Processes.dest', meaning: 'Several hosts in a short time is a strong warning sign.' }],
      positive: 'Tampering commands to attribute.',
      negative: 'Requires command lines in the data model.',
      prerequisites: 'Process data mapped to CIM.',
      schemaNotes: 'Field population depends on add-ons.',
      example: 'lookback = 7d',
    },
    esql(
      'esql-tamper-commands',
      'Protection-tampering commands on a host',
      'Finds Defender-disable, log-clear, and audit-policy commands on one host over the last 24 hours.',
      ['logs-endpoint.events.process-*'],
      `FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24 hours AND host.name == "{{hostname}}"
| WHERE process.command_line LIKE "*Set-MpPreference*Disable*"
    OR process.command_line LIKE "*Add-MpPreference*Exclusion*"
    OR process.command_line LIKE "*wevtutil* cl *"
    OR process.command_line LIKE "*Clear-EventLog*"
    OR process.command_line LIKE "*auditpol*/clear*"
| KEEP @timestamp, user.name, process.name, process.command_line, process.parent.name
| SORT @timestamp ASC
| LIMIT 200`,
      [PH.hostname()],
      'Rows are tampering actions or attempts to attribute.',
      'Changes made through policy or consoles do not appear as process events.',
    ),
    genericProcedure('generic-tamper', 'Generic defense-tampering procedure', `1. Which control changed, to what state, and did it take effect?
2. Process, command line, account, and logon source.
3. Change ticket or approved-exclusion entry?
4. Activity from 30 minutes before the change until protection returned.
5. Same change on other hosts in the last 7 days.`),
  ],
  sigmaRules: [
    sigma(
      'sigma-defender-disabled',
      '6fa602f6-10ac-444a-9183-755dcd263d8c',
      'Defender Protection Disabled Or Exclusion Added Via PowerShell',
      'Detects PowerShell commands that disable Microsoft Defender protections or add exclusions.',
      ['attack.defense-impairment', 'attack.t1685'],
      '    category: process_creation\n    product: windows',
      `    selection_cmdlet:
        CommandLine|contains:
            - 'Set-MpPreference'
            - 'Add-MpPreference'
    selection_setting:
        CommandLine|contains:
            - 'DisableRealtimeMonitoring'
            - 'DisableBehaviorMonitoring'
            - 'DisableIOAVProtection'
            - 'ExclusionPath'
            - 'ExclusionExtension'
            - 'ExclusionProcess'
    condition: all of selection_*`,
      ['Endpoint management tools applying approved exclusions', 'Software installers documented by the vendor'],
      'high',
    ),
  ],
  detectionConsiderations: ['Tamper protection blocks many attempts; the blocked attempt is still a finding.', 'Exclusions are quieter than disabling protection and are often overlooked.'],
  visibilityGaps: ['Events during the gap may be missing by design.', 'If the host log was cleared before forwarding, local evidence is gone.'],
  relatedTechniques: [
    { id: 'T1486', reason: 'Ransomware operators disable protection before encryption.' },
    { id: 'T1003', reason: 'Credential dumping is often run right after protection is reduced.' },
    { id: 'T1112', reason: 'Protection settings are frequently changed through the registry.' },
    { id: 'T1484.001', reason: 'Group Policy can push tampering to many hosts.' },
  ],
  references: [attackRef('T1685', 'Disable or Modify Tools'), attackRef('T1685.005', 'Clear Windows Event Logs'), { title: 'Microsoft Learn - 1102(S): The audit log was cleared', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102' }],
  assumptions: ['Tier 1 does not re-enable protection or remove exclusions; this is requested through escalation.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

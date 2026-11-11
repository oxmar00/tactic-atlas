import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, sigma, starterReview } from './helpers';

export const accountChanges: Playbook = {
  schemaVersion: 1,
  id: 'PB-ACCTCHANGE-001',
  version: '1.0.0',
  title: 'Unexpected account creation or privileged group change',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1136', 'T1136.001', 'T1136.002', 'T1098', 'T1098.007'],
  tactics: ['persistence', 'privilege-escalation'],
  objective: 'Establish who created the account or changed group membership, whether it followed the normal provisioning process, and whether the new access has been used.',
  alertMeaning: 'A user account was created, or an account was added to a privileged group such as local Administrators or Domain Admins, outside the usual provisioning tool or by an unusual actor.',
  whyItMatters: 'New accounts and group additions give attackers access that survives password resets and malware removal, and they look like ordinary administration.',
  difficulty: 'Beginner',
  effort: '20-40 minutes',
  platforms: ['Windows', 'Identity Provider'],
  logSources: ['win-security', 'mde', 'entra-audit', 'edr'],
  alertContext: {
    triggers: ['4720 (user created) by an account other than the provisioning service.', '4728 / 4732 / 4756 (member added to a security group) for a privileged group.', 'Command lines such as net user /add or net localgroup administrators /add.'],
    reviewFirst: ['New or changed account, target group, and host or domain.', 'Actor account and source.', 'Time relative to business hours and change windows.'],
    oftenMissing: ['Whether a provisioning ticket exists.', 'Whether the new account has logged on.'],
  },
  prerequisites: [
    { text: 'Account management auditing (4720, 4728, 4732, 4756) from domain controllers and, for local accounts, the host.', type: 'telemetry', required: true },
    { text: 'Provisioning or identity-management records and tickets.', type: 'information', required: true },
    { text: 'Process creation telemetry on the host.', type: 'telemetry', required: false },
  ],
  steps: [
    {
      id: 'change-details',
      title: 'Record what was created or changed',
      action: 'Record the new account name (or the member added), the group, whether it is local or domain, the actor account, and the host or domain controller that logged it.',
      why: 'Local Administrators on one workstation and Domain Admins are very different levels of risk.',
      where: ['Security 4720, 4728, 4732, 4756', 'DeviceEvents (UserAccountCreated)', 'Entra AuditLogs'],
      fields: ['TargetUserName', 'MemberName / MemberSid', 'SubjectUserName', 'Computer'],
      suspicious: ['Account name imitating a service or built-in account (e.g. "adm1n", "svc_backup$")', 'Addition to Domain Admins, Enterprise Admins, or local Administrators', 'Name ending in $ to hide among computer accounts'],
      legitimate: ['Account created by the identity-management service account following the naming standard'],
      next: 'Check how the change was made.',
      queryIds: ['kql-account-changes', 'spl-account-changes', 'esql-account-changes'],
    },
    {
      id: 'method',
      title: 'Determine how the change was made',
      action: 'On the host or source system, find the process and command line (net.exe, PowerShell New-LocalUser / Add-LocalGroupMember / New-ADUser, management console) and its parent.',
      why: 'A command typed in a remote shell or spawned by a script host indicates an intruder, not provisioning.',
      where: ['DeviceProcessEvents', 'Sysmon 1', 'Security 4688'],
      fields: ['ProcessCommandLine', 'InitiatingProcessFileName', 'AccountName'],
      suspicious: ['net user <name> <password> /add from cmd launched by a web server, WMI, or a service', 'Password given on the command line'],
      legitimate: ['Identity-management tool or documented admin script'],
      next: 'Verify against provisioning records.',
      queryIds: ['kql-net-user-add'],
    },
    {
      id: 'provisioning-check',
      title: 'Verify against provisioning records',
      action: 'Look for a matching joiner/mover ticket, access request, or change record for the account and group. Confirm the actor is allowed to make that change.',
      why: 'Authorized changes leave a paper trail; a missing one is the key finding.',
      where: ['Identity-management system', 'Ticketing system'],
      fields: ['Ticket number', 'Approver'],
      suspicious: ['No record', 'Actor is not part of the identity or admin team'],
      legitimate: ['Matching approved request'],
      next: 'Check whether the access was used.',
      queryIds: [],
    },
    {
      id: 'usage',
      title: 'Check whether the new access has been used',
      action: 'Search for logons by the new account, or by the account that gained membership, since the change. Note hosts, logon types, and sources.',
      why: 'Use of the access shows the change was purposeful and extends the scope.',
      where: ['Security 4624 / 4672', 'DeviceLogonEvents', 'Identity sign-in logs'],
      fields: ['TargetUserName', 'LogonType', 'IpAddress', 'Computer'],
      suspicious: ['Logon within minutes of creation from the same host as the actor', 'RDP or network logons to servers'],
      legitimate: ['First logon by the new employee on their assigned device'],
      next: 'Review the actor.',
      queryIds: [],
    },
    {
      id: 'actor-review',
      title: 'Review the actor account and host',
      action: 'Check the actor account for unusual sign-ins and the host where the change originated for other alerts in the last 7 days.',
      why: 'If the actor is a compromised admin, other changes are likely.',
      where: ['Alert queue', 'Sign-in logs', 'EDR timeline'],
      fields: ['Related alerts', 'Other account changes by the same actor'],
      suspicious: ['Several accounts created or modified by the same actor in a short period', 'Actor signed in from an unfamiliar source'],
      legitimate: ['Normal pattern for a provisioning administrator'],
      next: 'Use the decision tree.',
      queryIds: ['kql-account-changes'],
    },
  ],
  decisionTree: {
    start: 'provisioned',
    nodes: [
      { id: 'provisioned', question: 'Does the change match an approved request and was it made by the expected provisioning tool or administrator?', yes: { outcome: 'benign', guidance: 'Record the ticket and actor.' }, no: { next: 'privileged', guidance: 'Unexplained account change.' } },
      { id: 'privileged', question: 'Does the change grant administrative rights (local Administrators, Domain Admins, or similar) or create an account by command line from an unusual parent?', yes: { next: 'domain-level', guidance: 'Likely attacker persistence.' }, no: { outcome: 'investigate', guidance: 'Low-privilege change without a record. Confirm with the actor\'s manager or identity team; escalate if unverified.' } },
      { id: 'domain-level', question: 'Is it a domain-level privileged group, has the new access already been used, or did the actor make several such changes?', yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now.' }, no: { outcome: 'escalate', guidance: 'Escalate with the change details, method, and actor.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    evCustom('account_changed', 'Account created or member added', 'Name, SID if shown, local or domain.', true),
    evCustom('group_changed', 'Group affected', 'e.g. BUILTIN\\Administrators on WS-01; Domain Admins.', true),
    ev('username', true, 'Actor account that made the change.'),
    ev('hostname', true, 'Host or domain controller where it was logged.'),
    ev('command_line', false, 'Command used, if found.'),
    evCustom('provisioning_record', 'Provisioning record checked', 'Ticket number or "none found", and where you looked.', true),
    evCustom('access_used', 'Use of the new access', 'Logons since the change, or "none found".', false, true),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['Account created or added to an administrative group with no provisioning record.', 'Change made by command line from a script host, service, or remote shell.', 'Actor is not authorized to manage accounts.'],
    immediate: ['Addition to Domain Admins, Enterprise Admins, or equivalent without approval.', 'New account already used to log on to servers.', 'Multiple unexplained account changes by the same actor.'],
    benignClosure: ['Approved request matches account, group, actor, and time.'],
  },
  queries: [
    {
      id: 'kql-account-changes',
      title: 'Account creation and security-group additions',
      language: 'kql',
      platform: 'Microsoft Sentinel (Windows Security Events connector)',
      purpose: 'Lists user creations and group-membership additions with actor and target.',
      dataSources: ['SecurityEvent'],
      query: `SecurityEvent
| where TimeGenerated > ago({{lookback}})
| where EventID in (4720, 4728, 4732, 4756)
| project TimeGenerated, Computer, EventID, Activity,
          Actor = SubjectUserName, Target = TargetUserName, MemberName, MemberSid
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'Target', meaning: 'For 4720 the new account; for 4728/4732/4756 the group.' }, { name: 'MemberSid', meaning: 'Account added to the group (MemberName is often empty for local groups).' }],
      positive: 'Each row is an account change to match against provisioning records.',
      negative: 'Local account events exist only if that host forwards its Security log.',
      prerequisites: 'Account management auditing; Security events collected.',
      schemaNotes: 'Column availability follows the SecurityEvent schema; resolve MemberSid in the directory when MemberName is "-".',
      example: 'lookback = 7d',
    },
    {
      id: 'kql-net-user-add',
      title: 'Command-line account creation or admin-group addition',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds net.exe and PowerShell commands that create accounts or add members to groups.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where (FileName in~ ("net.exe", "net1.exe") and ProcessCommandLine has "/add"
         and ProcessCommandLine has_any ("user", "localgroup", "group"))
    or ProcessCommandLine has_any ("New-LocalUser", "Add-LocalGroupMember", "New-ADUser", "Add-ADGroupMember")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'InitiatingProcessFileName', meaning: 'What launched the command.' }],
      positive: 'Shows the method and parent for attribution.',
      negative: 'Changes through consoles or APIs do not create these command lines.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'Standard Defender columns.',
      example: 'lookback = 7d',
    },
    {
      id: 'spl-account-changes',
      title: 'Account creation and group additions (Windows Security)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Lists 4720, 4728, 4732, and 4756 events with actor and target.',
      dataSources: ['Windows Security EventCodes 4720, 4728, 4732, 4756'],
      query: `index="{{index}}" source="*:Security" earliest=-{{lookback}}
    (EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time host EventCode SubjectUserName TargetUserName MemberSid
| sort _time`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Windows Security events.', example: 'wineventlog' }, PH.lookback('7d')],
      keyFields: [{ name: 'SubjectUserName', meaning: 'Actor.' }],
      positive: 'Account changes to verify.',
      negative: 'Depends on which hosts forward Security logs.',
      prerequisites: 'Account management auditing.',
      schemaNotes: 'Classic rendering uses different field names (e.g. Account_Name multivalue).',
      example: 'index = wineventlog',
    },
    esql(
      'esql-account-changes',
      'Account creation and group additions',
      'Lists user creations and security-group additions over the last 7 days.',
      ['logs-system.security-*'],
      `FROM logs-system.security-*
| WHERE @timestamp > NOW() - 7 days
| WHERE event.code IN ("4720", "4728", "4732", "4756")
| KEEP @timestamp, host.name, event.code, event.action, user.name, user.target.name, group.name
| SORT @timestamp ASC
| LIMIT 500`,
      [],
      'Each row is an account change to verify against provisioning records.',
      'Local account events appear only for hosts that ship their Security log.',
    ),
    genericProcedure('generic-account-change', 'Generic account-change procedure', `1. Record the account, group, scope (local/domain), actor, and logging host.
2. Find the process and command line that made the change, and its parent.
3. Match against provisioning tickets and the actor's authority.
4. Search for logons using the new access since the change.
5. Review the actor account and origin host for other alerts and changes.`),
  ],
  sigmaRules: [
    sigma(
      'sigma-net-admin-add',
      '49f5ff73-a965-4591-a639-b8636f51b6fe',
      'Account Added To Administrators Group Via Net Command',
      'Detects net.exe adding an account to the local Administrators or a domain admin group.',
      ['attack.persistence', 'attack.t1098.007'],
      '    category: process_creation\n    product: windows',
      `    selection_img:
        Image|endswith:
            - '\\net.exe'
            - '\\net1.exe'
    selection_cmd:
        CommandLine|contains|all:
            - 'group'
            - '/add'
    selection_group:
        CommandLine|contains:
            - 'Administrators'
            - 'Domain Admins'
            - 'Enterprise Admins'
    condition: all of selection_*`,
      ['Provisioning scripts run by IT', 'Software installers that create service administrators'],
      'medium',
    ),
  ],
  detectionConsiderations: ['Baseline the accounts that normally create users; alert on everyone else.', 'Group names are localized on non-English systems; prefer well-known SIDs where possible.'],
  visibilityGaps: ['Local account changes on workstations are missed if their logs are not collected.', 'Cloud directory changes are logged separately from on-premises AD.'],
  relatedTechniques: [
    { id: 'T1078', reason: 'Created accounts become valid accounts for the attacker.' },
    { id: 'T1021.001', reason: 'New admin accounts are often used for RDP access.' },
    { id: 'T1136.003', reason: 'Cloud account creation is the equivalent in identity providers.' },
    { id: 'T1098.003', reason: 'Additional cloud roles are the equivalent privilege change in cloud tenants.' },
  ],
  references: [attackRef('T1136', 'Create Account'), attackRef('T1098', 'Account Manipulation'), { title: 'Microsoft Learn - 4720(S): A user account was created', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720' }],
  assumptions: ['Disabling or deleting accounts is a containment action requested through escalation.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

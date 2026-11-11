import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, sigma, starterReview } from './helpers';

export const kerberoasting: Playbook = {
  schemaVersion: 1,
  id: 'PB-KERBEROAST-001',
  version: '1.0.0',
  title: 'Possible Kerberoasting (service ticket harvesting)',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1558', 'T1558.003'],
  tactics: ['credential-access'],
  objective: 'Determine whether an account requested Kerberos service tickets in order to crack service-account passwords offline, and which service accounts are exposed.',
  alertMeaning: 'One account requested service tickets for many different service accounts in a short time, often with weak RC4 encryption. Any domain user can request these tickets; the attack is the volume and pattern.',
  whyItMatters: 'Tickets are encrypted with the service account\'s password hash. Weak service-account passwords can be cracked offline with no further noise, often yielding highly privileged accounts.',
  difficulty: 'Intermediate',
  effort: '30-45 minutes',
  platforms: ['Windows'],
  logSources: ['win-security', 'mde', 'edr'],
  alertContext: {
    triggers: ['Many 4769 events from one account for distinct service names within minutes.', '4769 with ticket encryption type 0x17 (RC4) where AES is the norm.', 'Identity-threat alert for Kerberos SPN exposure or Kerberoasting.'],
    reviewFirst: ['Requesting account and source IP/host.', 'Number and names of services requested.', 'Encryption types.'],
    oftenMissing: ['Which requested accounts are privileged or have old passwords.', 'What the requesting host was running at the time.'],
  },
  prerequisites: [
    { text: 'Domain controller Security logs with 4769 (Audit Kerberos Service Ticket Operations).', type: 'telemetry', required: true },
    { text: 'EDR on the requesting host.', type: 'telemetry', required: false },
    { text: 'Service-account inventory (privilege, password age).', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'request-pattern',
      title: 'Measure the ticket-request pattern',
      action: 'For the requesting account, count 4769 events and distinct service names in the alert window, and list the encryption types. Exclude krbtgt and computer accounts (names ending in $).',
      why: 'Normal users request a few service tickets for services they use. Dozens of distinct services in minutes is enumeration.',
      where: ['Domain controller Security log 4769'],
      fields: ['TargetUserName (requester)', 'ServiceName', 'TicketEncryptionType', 'IpAddress', 'Status'],
      suspicious: ['Ten or more distinct service names in a few minutes', 'RC4 (0x17) requested when the environment uses AES (0x12)', 'Requests for services the user has no reason to use'],
      legitimate: ['Vulnerability scanner or identity-audit tool running from its documented host', 'Legacy application that still uses RC4 for one known service'],
      next: 'Identify the source host and what ran there.',
      queryIds: ['kql-4769-rc4', 'spl-4769-rc4', 'esql-4769-rc4'],
    },
    {
      id: 'source-host',
      title: 'Investigate the requesting host',
      action: 'Map the source IP to a host. Review processes around the request time for tooling or PowerShell that requests tickets or queries service principal names (setspn -Q, LDAP searches for servicePrincipalName).',
      why: 'The requesting host is where the attacker is operating.',
      where: ['DHCP / asset inventory', 'DeviceProcessEvents', 'PowerShell 4104'],
      fields: ['ProcessCommandLine', 'ScriptBlockText', 'InitiatingProcessFileName'],
      suspicious: ['setspn -Q */* or scripts referencing KerberosRequestorSecurityToken', 'Unknown binaries or encoded PowerShell at the same time'],
      legitimate: ['Documented audit tooling'],
      next: 'Check the requesting account.',
      queryIds: ['kql-spn-enumeration'],
    },
    {
      id: 'requester',
      title: 'Check the requesting account',
      action: 'Review the account\'s recent logons (hosts, hours, sources) and related alerts to judge whether it is compromised.',
      why: 'Kerberoasting is done with an already compromised user account.',
      where: ['Security 4624 / 4768', 'Identity sign-in logs', 'Alert queue'],
      fields: ['Logon sources', 'Related alerts'],
      suspicious: ['Logons from a host the user does not normally use', 'Recent phishing or malware alerts for this user'],
      legitimate: ['Identity team member running a sanctioned assessment'],
      next: 'Identify which service accounts are at risk.',
      queryIds: [],
    },
    {
      id: 'exposed-services',
      title: 'List exposed service accounts and their privilege',
      action: 'List the service accounts whose tickets were requested. With the identity team\'s inventory, flag those that are privileged or have old or weak passwords.',
      why: 'Impact depends on what the crackable accounts can do. Tier 2 needs this list to prioritize password resets.',
      where: ['Service-account inventory', 'Directory (group membership, pwdLastSet)'],
      fields: ['ServiceName', 'Privilege level', 'Password age'],
      suspicious: ['Domain admin or equivalent service accounts in the list', 'Passwords unchanged for years'],
      legitimate: [],
      next: 'Look for use of those accounts.',
      queryIds: [],
    },
    {
      id: 'service-account-use',
      title: 'Look for new use of the exposed service accounts',
      action: 'Search for logons by the exposed service accounts from hosts they do not normally use, after the request burst.',
      why: 'A cracked password is used quietly; a service account logging on from a workstation is the signal.',
      where: ['Security 4624 across hosts', 'DeviceLogonEvents'],
      fields: ['TargetUserName', 'LogonType', 'IpAddress', 'Computer'],
      suspicious: ['Interactive or network logon by a service account from the requesting host or a workstation'],
      legitimate: ['Only logons on the service\'s own servers'],
      next: 'Use the decision tree.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'sanctioned',
    nodes: [
      { id: 'sanctioned', question: 'Is this a sanctioned scanner, audit tool, or assessment confirmed by its owner for this host and time?', yes: { outcome: 'benign', guidance: 'Document the tool, owner, and schedule.' }, no: { next: 'enumeration', guidance: 'Not explained.' } },
      { id: 'enumeration', question: 'Did one account request tickets for many distinct services in a short time, or request RC4 tickets against the norm?', yes: { next: 'used', guidance: 'Consistent with Kerberoasting.' }, no: { outcome: 'investigate', guidance: 'Pattern is weak. Check the source host and requester before deciding.' } },
      { id: 'used', question: 'Are privileged service accounts among the targets, or is an exposed service account already logging on from unusual hosts?', yes: { outcome: 'critical', guidance: 'Privileged credentials may be cracked or in use. Follow the incident escalation procedure now.' }, no: { outcome: 'escalate', guidance: 'Escalate with the requester, source host, and list of exposed service accounts for password resets.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('username', true, 'Requesting account.'),
    ev('src_ip', true, 'Source IP and host of the requests.'),
    evCustom('services_requested', 'Service accounts requested', 'One per line; mark privileged ones.', true, true),
    evCustom('encryption_types', 'Ticket encryption types', 'e.g. 0x17 x 42, 0x12 x 3.', true),
    ev('command_line', false, 'Tooling or script seen on the source host.'),
    evCustom('service_account_use', 'New use of exposed service accounts', 'Logons from unusual hosts after the burst, or "none found".', false, true),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['Burst of service-ticket requests for many services by one account, not attributable to sanctioned tooling.', 'RC4 ticket requests against the environment\'s norm.', 'SPN enumeration tooling on the source host.'],
    immediate: ['Privileged service accounts were requested.', 'An exposed service account logs on from an unusual host.', 'The requesting account or host has other compromise indicators.'],
    benignClosure: ['Sanctioned tool or assessment confirmed by its owner for this host and time.'],
  },
  queries: [
    {
      id: 'kql-4769-rc4',
      title: 'Service-ticket requests per account with encryption types',
      language: 'kql',
      platform: 'Microsoft Sentinel (Windows Security Events connector)',
      purpose: 'Summarizes 4769 requests per requesting account and source: total, distinct services, and RC4 count.',
      dataSources: ['SecurityEvent (domain controllers)'],
      query: `SecurityEvent
| where TimeGenerated > ago({{lookback}})
| where EventID == 4769
| extend Requester = extract(@'<Data Name="TargetUserName">([^<]*)</Data>', 1, EventData),
         Service = extract(@'<Data Name="ServiceName">([^<]*)</Data>', 1, EventData),
         EncType = extract(@'<Data Name="TicketEncryptionType">([^<]*)</Data>', 1, EventData),
         ClientIp = extract(@'<Data Name="IpAddress">([^<]*)</Data>', 1, EventData)
| where Service !endswith "$" and Service != "krbtgt"
| summarize Requests = count(), DistinctServices = dcount(Service), Rc4Requests = countif(EncType =~ "0x17"),
            Services = make_set(Service, 50), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by Requester, ClientIp
| where DistinctServices >= {{min_services}}
| order by DistinctServices desc`,
      placeholders: [PH.lookback('24h'), { name: 'min_services', kind: 'number', description: 'Minimum distinct services per requester to show.', example: '10' }],
      keyFields: [{ name: 'DistinctServices', meaning: 'High values in a short span indicate enumeration.' }, { name: 'Rc4Requests', meaning: 'RC4 tickets are faster to crack.' }],
      positive: 'A requester with many distinct services is a lead; scanners and audit tools produce the same pattern.',
      negative: 'Requires 4769 auditing on every domain controller. Slow, low-volume roasting stays under the threshold.',
      prerequisites: 'Domain controller Security logs with Kerberos service ticket auditing.',
      schemaNotes: 'Fields are parsed from EventData XML; some workspaces expose them as columns. ClientIp is often prefixed with ::ffff:.',
      example: 'lookback = 24h, min_services = 10',
    },
    {
      id: 'kql-spn-enumeration',
      title: 'SPN enumeration commands',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Finds setspn queries and scripts that request service tickets.',
      dataSources: ['DeviceProcessEvents'],
      query: `DeviceProcessEvents
| where Timestamp > ago({{lookback}})
| where (FileName =~ "setspn.exe" and ProcessCommandLine has_any ("-Q", "/Q"))
    or ProcessCommandLine has_any ("KerberosRequestorSecurityToken", "servicePrincipalName=*")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'DeviceName', meaning: 'Host where enumeration ran.' }],
      positive: 'Enumeration tooling near the ticket burst supports Kerberoasting.',
      negative: 'In-memory tools leave no such command line.',
      prerequisites: 'Defender for Endpoint.',
      schemaNotes: 'Administrators use setspn legitimately; check the account and host.',
      example: 'lookback = 7d',
    },
    {
      id: 'spl-4769-rc4',
      title: 'Service-ticket requests per account (4769)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Counts distinct services requested per account and source, with RC4 count.',
      dataSources: ['Domain controller Security EventCode 4769'],
      query: `index="{{index}}" source="*:Security" EventCode=4769 earliest=-{{lookback}}
| where NOT like(ServiceName, "%$") AND ServiceName!="krbtgt"
| eval rc4=if(TicketEncryptionType="0x17", 1, 0)
| stats count dc(ServiceName) as distinct_services sum(rc4) as rc4_requests values(ServiceName) as services
    by TargetUserName IpAddress
| where distinct_services >= {{min_services}}
| sort - distinct_services`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding domain controller Security events.', example: 'wineventlog' }, PH.lookback('24h'), { name: 'min_services', kind: 'number', description: 'Minimum distinct services.', example: '10' }],
      keyFields: [{ name: 'distinct_services', meaning: 'Enumeration indicator.' }],
      positive: 'Candidates to investigate.',
      negative: 'Requires 4769 from all domain controllers.',
      prerequisites: 'Kerberos service ticket auditing; DC logs forwarded.',
      schemaNotes: 'Classic rendering uses Service_Name and Ticket_Encryption_Type.',
      example: 'index = wineventlog, min_services = 10',
    },
    esql(
      'esql-4769-rc4',
      'Service-ticket requests per account (4769)',
      'Counts distinct services requested per account and source over the last 24 hours.',
      ['logs-system.security-*'],
      `FROM logs-system.security-*
| WHERE @timestamp > NOW() - 24 hours AND event.code == "4769"
| WHERE NOT (winlog.event_data.ServiceName LIKE "*$") AND winlog.event_data.ServiceName != "krbtgt"
| STATS requests = COUNT(*), distinct_services = COUNT_DISTINCT(winlog.event_data.ServiceName)
    BY winlog.event_data.TargetUserName, source.ip
| WHERE distinct_services >= 10
| SORT distinct_services DESC`,
      [],
      'Requesters with many distinct services are leads; sanctioned scanners look the same.',
      'Requires domain controller Security logs through the Elastic System or Windows integration.',
    ),
    genericProcedure('generic-kerberoast', 'Generic Kerberoasting procedure', `1. Count service-ticket requests and distinct services per requester; note encryption types.
2. Map the source IP to a host; review processes and scripts at that time.
3. Review the requesting account's recent logons and alerts.
4. List requested service accounts; flag privileged and old-password accounts.
5. Search for those service accounts logging on from unusual hosts afterwards.`),
  ],
  sigmaRules: [
    sigma(
      'sigma-kerberoast-rc4',
      'ddbf4783-4cc2-415d-8082-594bf4980806',
      'Kerberos Service Ticket Requested With RC4 Encryption',
      'Detects Kerberos service ticket requests using RC4 for non-machine, non-krbtgt services. Needs aggregation by requester in the SIEM to be useful.',
      ['attack.credential-access', 'attack.t1558.003'],
      '    product: windows\n    service: security',
      `    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter_machine:
        ServiceName|endswith: '$'
    filter_krbtgt:
        ServiceName: 'krbtgt'
    condition: selection and not 1 of filter_*`,
      ['Legacy applications that only support RC4', 'Sanctioned identity audits'],
      'medium',
    ),
  ],
  detectionConsiderations: ['A single request is normal; detection depends on aggregation per requester over time.', 'Attackers can request AES tickets to avoid RC4-based rules; distinct-service counts still apply.'],
  visibilityGaps: ['4769 auditing must be enabled on all domain controllers.', 'Offline cracking generates no telemetry.'],
  relatedTechniques: [
    { id: 'T1087.002', reason: 'Domain account discovery identifies service accounts.' },
    { id: 'T1078.002', reason: 'Cracked service accounts are used as valid domain accounts.' },
    { id: 'T1003', reason: 'Other credential-access activity often accompanies it.' },
    { id: 'T1550.003', reason: 'Pass-the-ticket is a related Kerberos abuse.' },
  ],
  references: [attackRef('T1558.003', 'Kerberoasting'), { title: 'Microsoft Learn - 4769(S, F): A Kerberos service ticket was requested', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769' }],
  assumptions: ['Service-account password resets are coordinated by the identity team.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

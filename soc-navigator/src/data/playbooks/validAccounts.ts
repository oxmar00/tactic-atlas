import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const validAccounts: Playbook = {
  schemaVersion: 1,
  id: 'PB-VALIDACCT-001',
  version: '1.0.0',
  title: 'Suspicious use of a valid account',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1078', 'T1078.002', 'T1078.004'],
  tactics: ['initial-access', 'persistence', 'privilege-escalation', 'stealth'],
  objective:
    'Decide whether a successful sign-in or logon was made by the real account owner, and if not, what the session did and how far access extends.',
  alertMeaning:
    'A legitimate account authenticated successfully in an unusual way: unfamiliar country or network, impossible/atypical travel, anonymizing IP, unknown device, off-hours access, a dormant account waking up, or a service account logging on interactively.',
  whyItMatters:
    'Attackers with real credentials look like normal users. Logins succeed, so preventive controls stay silent - behavioral anomalies are often the only signal.',
  difficulty: 'Intermediate',
  effort: '30-60 minutes',
  platforms: ['Identity Provider', 'SaaS', 'Office Suite', 'Windows', 'IaaS'],
  logSources: ['entra-signin', 'entra-audit', 'm365-audit', 'win-security', 'vpn', 'cloud-audit'],
  alertContext: {
    triggers: [
      'Identity protection risk detection (unfamiliar sign-in properties, atypical travel, anonymous IP, malicious IP, leaked credentials, anomalous token).',
      'Successful logon outside the account\'s normal hours, hosts, or geography.',
      'Dormant or disabled-then-re-enabled account used.',
      'Service account used for interactive (LogonType 2) or RDP (LogonType 10) logon.',
    ],
    reviewFirst: [
      'Account, time, source IP, location, device, user agent, application, and MFA details of the flagged sign-in.',
      'Whether the sign-in was successful and whether MFA was satisfied (and how).',
      'Account type: standard, privileged, service, guest.',
    ],
    oftenMissing: [
      'A 30-day baseline of normal sign-ins for the account.',
      'What the session did after authentication.',
      'Whether other accounts signed in from the same IP.',
    ],
  },
  prerequisites: [
    { text: 'Sign-in logs for the IdP/application (Entra ID SigninLogs, VPN, Windows 4624).', type: 'telemetry', required: true },
    { text: 'Directory audit logs (MFA method changes, role changes, consents).', type: 'telemetry', required: true },
    { text: 'Corporate egress / VPN IP list.', type: 'information', required: false },
    { text: 'Approved channel to contact users (e.g. phone number from the directory), per policy.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'sign-in-details',
      title: 'Capture the flagged sign-in in detail',
      action:
        'Record the account, timestamp, result, IP, location, device details (ID, OS, browser, compliant/managed), user agent, application, client app, Conditional Access result, MFA requirement and method, and correlation ID.',
      why: 'These attributes are what you will compare with the baseline. MFA details show whether a second factor actually protected the account.',
      where: ['SigninLogs', 'Identity protection risk detections', 'VPN / Windows 4624'],
      fields: ['UserPrincipalName', 'IPAddress', 'LocationDetails', 'DeviceDetail', 'UserAgent', 'AppDisplayName', 'ClientAppUsed', 'ConditionalAccessStatus', 'AuthenticationRequirement', 'CorrelationId'],
      suspicious: ['Single-factor success where MFA is normally required', 'Unregistered device with an unusual browser/OS combination', 'Hosting provider, Tor, or commercial VPN IP'],
      legitimate: ['Compliant, managed device ID the user has used before'],
      next: 'Build the baseline next.',
      queryIds: ['kql-signin-baseline'],
    },
    {
      id: 'baseline',
      title: 'Build the account\'s normal sign-in baseline',
      action:
        'Summarize 30 days of sign-ins: usual IPs, countries, devices, browsers, apps, and hours. Mark whether the flagged IP, country, device, and app are new.',
      why: 'A "new" attribute is only meaningful against history. Many alerts are explained by a new phone or a trip.',
      where: ['SigninLogs (30 days)', 'Authentication data model', 'VPN logs'],
      fields: ['IPAddress', 'Country', 'DeviceId', 'OS / Browser', 'AppDisplayName'],
      suspicious: ['Several new attributes at once (new country + new device + new browser)', 'Sign-ins from two distant locations within an impossible time'],
      legitimate: ['Only one attribute is new and it is explained (new laptop issued by IT)'],
      next: 'Look for an explanation for whatever is new.',
      queryIds: ['kql-signin-baseline', 'spl-user-auth-baseline'],
    },
    {
      id: 'explanation',
      title: 'Look for a legitimate explanation',
      action:
        'Check whether the IP belongs to corporate VPN or a known cloud egress, whether IT issued a new device, and whether the user is travelling or working remotely (through approved sources). If your procedure allows, confirm with the user using contact details from the directory - never via the session under suspicion.',
      why: 'Avoids escalating benign travel, while ensuring an attacker cannot "confirm" their own activity.',
      where: ['Network team IP lists', 'Asset management', 'Ticketing', 'User/manager confirmation (approved channel)'],
      fields: ['IP ownership', 'Device assignment', 'Confirmation source and time'],
      suspicious: ['User denies the sign-in', 'No explanation and the user cannot be reached'],
      legitimate: ['IP is a documented corporate egress', 'User confirms via a verified channel and the device matches'],
      next: 'If confirmed benign, document it. Otherwise review post-authentication activity.',
      queryIds: [],
    },
    {
      id: 'post-auth',
      title: 'Review what the session did',
      action:
        'Review activity after the sign-in: apps accessed, mailbox access and inbox rules, file downloads/sharing, admin portal actions, MFA method registration, password changes, OAuth consents, and subsequent sign-ins from the same IP.',
      why: 'Post-authentication actions show intent and reveal persistence the attacker may have set up.',
      where: ['AuditLogs', 'OfficeActivity / CloudAppEvents', 'Cloud audit logs (CloudTrail, Azure Activity)', 'DeviceLogonEvents'],
      fields: ['OperationName', 'TargetResources', 'Operation', 'ClientIP', 'eventName'],
      suspicious: ['New MFA method or authenticator app registered', 'Inbox rules forwarding or deleting mail', 'Mass file download or anonymous sharing links', 'Role assignment or app consent'],
      legitimate: ['Activity consistent with the user\'s normal work'],
      next: 'Record all actions with timestamps for the handoff timeline.',
      queryIds: ['kql-account-audit'],
    },
    {
      id: 'on-prem',
      title: 'Domain/service accounts: check on-premises logon behavior',
      action:
        'For domain or service accounts, review 4624 logons by logon type and source host. Service accounts should log on as service (5) or batch (4) on their own servers - interactive (2) or RDP (10) logons are a strong anomaly.',
      why: 'Service accounts often have broad privileges and static passwords; their misuse is a common attacker path.',
      where: ['Security 4624 / 4648 / 4672', 'DeviceLogonEvents', 'Domain controller 4768/4769'],
      fields: ['TargetUserName', 'LogonType', 'IpAddress', 'WorkstationName', 'Computer'],
      suspicious: ['Service account with LogonType 2/10', 'Account logging on to many hosts it never used', 'Logons at unusual hours'],
      legitimate: ['Logon pattern matches the documented service'],
      next: 'Record anomalies and continue to scoping.',
      queryIds: ['spl-service-interactive'],
    },
    {
      id: 'scope',
      title: 'Scope the source IP and related accounts',
      action:
        'Search for other accounts that signed in from the same IP or user agent in the last 7 days, and for related risk detections.',
      why: 'Attackers commonly use the same infrastructure for several compromised accounts.',
      where: ['SigninLogs by IPAddress', 'Identity protection risk detections', 'Alert queue'],
      fields: ['Other UserPrincipalNames', 'Risk detections'],
      suspicious: ['Multiple unrelated users from the same unfamiliar IP'],
      legitimate: ['IP is shared corporate egress'],
      next: 'Use the decision tree.',
      queryIds: ['kql-risk-events'],
    },
  ],
  decisionTree: {
    start: 'explained',
    nodes: [
      {
        id: 'explained',
        question: 'Does the sign-in match the user\'s baseline or a verified explanation (known device, corporate egress/VPN, confirmed travel, confirmation through an approved channel)?',
        yes: { outcome: 'benign', guidance: 'Record the explanation and its source. Note any detection tuning suggestion.' },
        no: { next: 'successful', guidance: 'Unexplained anomaly.' },
      },
      {
        id: 'successful',
        question: 'Was the authentication successful and did it produce a usable session (not blocked by MFA or Conditional Access)?',
        yes: { next: 'post-activity', guidance: 'An unknown party may be using the account.' },
        no: { next: 'password-known', guidance: 'Sign-in was blocked - check how far it got.' },
      },
      {
        id: 'password-known',
        question: 'Was the correct password presented (blocked only at MFA or Conditional Access)?',
        yes: { outcome: 'escalate', guidance: 'The password is likely compromised even though the session was blocked. Escalate for credential reset decisions.' },
        no: { outcome: 'contained', guidance: 'Failed attempt with a wrong password. Record it; if part of a broader pattern, use the brute-force playbook.' },
      },
      {
        id: 'post-activity',
        question: 'Is there suspicious post-authentication activity (new MFA method, inbox rules, mass download/sharing, role/app changes) or other accounts from the same source?',
        yes: { next: 'privileged', guidance: 'Account compromise with attacker activity.' },
        no: { outcome: 'escalate', guidance: 'Unexplained successful access. Escalate so Tier 2 can confirm and decide on session revocation.' },
      },
      {
        id: 'privileged',
        question: 'Is the account privileged (admin roles, domain/service account with broad access), or are multiple accounts affected?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Escalate with the sign-in, baseline comparison, and post-auth timeline.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true, 'Include the risk detection type if any.'),
    ev('event_time', true),
    ev('username', true),
    ev('src_ip', true, 'IP, ASN, country/city; corporate egress?'),
    ev('auth_outcome', true, 'Result code, MFA requirement and method, Conditional Access status.'),
    evCustom('device_details', 'Device and client details', 'Device ID, OS, browser, compliant/managed, user agent, client app.', true),
    evCustom('baseline_comparison', 'Baseline comparison', 'Which attributes are new vs. seen in the last 30 days.', true, true),
    evCustom('explanation', 'Explanation checked', 'VPN/egress/travel/device/user confirmation and its source.', false, true),
    evCustom('post_auth', 'Post-authentication activity', 'Timestamped actions after sign-in.', false, true),
    ev('hostname', false, 'For domain/service accounts: hosts logged on to.'),
    ev('affected_assets', false, 'Other accounts from the same source.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Successful sign-in that cannot be explained by baseline, egress/VPN, device, or verified user confirmation.',
      'Correct password presented from an unfamiliar source but blocked by MFA/Conditional Access.',
      'User denies the activity.',
      'Service account used interactively or from an unexpected host.',
      'Dormant or recently re-enabled account used without a ticket.',
    ],
    immediate: [
      'Privileged account (admin roles, domain admin, cloud owner) used anomalously.',
      'Persistence observed: new MFA method, OAuth consent, inbox forwarding rule, new credentials on cloud identities.',
      'Multiple accounts signed in from the same attacker infrastructure.',
    ],
    benignClosure: [
      'Sign-in matches baseline or a verified explanation documented with its source.',
      'No suspicious post-authentication activity.',
    ],
  },
  queries: [
    {
      id: 'kql-signin-baseline',
      title: '30-day sign-in baseline for a user',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID connector)',
      purpose: 'Summarizes a user\'s sign-ins by IP, country, OS, browser, and device to show what is normal and what is new.',
      dataSources: ['SigninLogs'],
      query: `SigninLogs
| where TimeGenerated > ago({{lookback}})
| where UserPrincipalName =~ "{{upn}}"
| extend Country = tostring(LocationDetails.countryOrRegion),
         OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser),
         DeviceId = tostring(DeviceDetail.deviceId),
         Compliant = tostring(DeviceDetail.isCompliant)
| summarize SignIns = count(), Successes = countif(ResultType == "0"),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Apps = make_set(AppDisplayName, 10)
            by IPAddress, Country, OS, Browser, DeviceId, Compliant
| order by FirstSeen asc`,
      placeholders: [PH.lookback('30d'), PH.upn()],
      keyFields: [
        { name: 'FirstSeen', meaning: 'Rows first seen near the alert are new attributes.' },
        { name: 'DeviceId / Compliant', meaning: 'Empty DeviceId means an unregistered device.' },
      ],
      positive: 'Shows which attributes are new. New does not mean malicious.',
      negative: 'Missing history (new user, short retention) limits the comparison - record it.',
      prerequisites: 'Entra ID sign-in logs in Sentinel with at least 30 days retention.',
      schemaNotes: 'DeviceDetail and LocationDetails are dynamic columns. Non-interactive sign-ins are in AADNonInteractiveUserSignInLogs.',
      example: 'upn = jdoe@example.com, lookback = 30d',
    },
    {
      id: 'kql-account-audit',
      title: 'Directory changes made by or to a user',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID connector)',
      purpose: 'Lists audit events initiated by the user or targeting the user (MFA registration, role changes, consents, password resets).',
      dataSources: ['AuditLogs'],
      query: `AuditLogs
| where TimeGenerated > ago({{lookback}})
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName),
         InitiatorIp = tostring(InitiatedBy.user.ipAddress)
| where Initiator =~ "{{upn}}" or tostring(TargetResources) has "{{upn}}"
| project TimeGenerated, OperationName, Category, Result, Initiator, InitiatorIp, TargetResources
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d'), PH.upn()],
      keyFields: [
        { name: 'OperationName', meaning: 'e.g. "User registered security info", "Consent to application", "Add member to role".' },
        { name: 'InitiatorIp', meaning: 'Compare with the suspicious sign-in IP.' },
      ],
      positive: 'Changes made from the suspicious session are evidence of attacker persistence.',
      negative: 'No changes does not mean the session was harmless - data access is logged elsewhere (OfficeActivity, CloudAppEvents).',
      prerequisites: 'Entra ID audit logs in Sentinel.',
      schemaNotes: 'InitiatedBy and TargetResources are nested dynamic columns.',
      example: 'upn = jdoe@example.com',
    },
    {
      id: 'kql-risk-events',
      title: 'Identity protection risk detections for a user or IP',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID Protection diagnostic export)',
      purpose: 'Lists risk detections for the user and any detections from the same IP.',
      dataSources: ['AADUserRiskEvents'],
      query: `AADUserRiskEvents
| where TimeGenerated > ago({{lookback}})
| where UserPrincipalName =~ "{{upn}}" or IpAddress == "{{src_ip}}"
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, RiskState,
          DetectionTimingType, IpAddress, Location
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d'), PH.upn(), PH.srcIp()],
      keyFields: [
        { name: 'RiskEventType', meaning: 'Detection type (e.g. unfamiliarFeatures, anonymizedIPAddress, leakedCredentials).' },
        { name: 'RiskState', meaning: 'atRisk, confirmedCompromised, remediated, dismissed.' },
      ],
      positive: 'Related detections add weight; other users from the same IP expand scope.',
      negative: 'Requires Entra ID P2 and the UserRiskEvents diagnostic category; no rows may mean it is not exported.',
      prerequisites: 'Entra ID P2; diagnostic settings sending risk events to the workspace.',
      schemaNotes: 'Risk event type names are defined by Microsoft and change over time.',
      example: 'upn = jdoe@example.com, src_ip = 203.0.113.25',
    },
    {
      id: 'spl-user-auth-baseline',
      title: 'Successful authentications for a user by source (CIM)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Baseline of where and to what the user successfully authenticated.',
      dataSources: ['CIM Authentication data model'],
      query: `| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen
    values(Authentication.app) as apps
    from datamodel=Authentication
    where earliest=-{{lookback}} Authentication.user="{{username}}" Authentication.action="success"
    by Authentication.src Authentication.dest
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen`,
      placeholders: [PH.lookback('30d'), PH.username()],
      keyFields: [{ name: 'Authentication.src / dest', meaning: 'Where the user authenticated from and to.' }],
      positive: 'New sources/destinations near the alert time are anomalies to explain.',
      negative: 'User name formats differ between sources (UPN vs DOMAIN\\user); try both.',
      prerequisites: 'Authentication logs mapped to CIM.',
      schemaNotes: 'Field normalization depends on add-ons.',
      example: 'username = jdoe, lookback = 30d',
    },
    {
      id: 'spl-service-interactive',
      title: 'Interactive or RDP logons by service accounts',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Windows)',
      purpose: 'Finds 4624 interactive (2) or RemoteInteractive (10) logons by accounts matching your service-account naming pattern.',
      dataSources: ['Windows Security EventCode 4624'],
      query: `index="{{index}}" source="*:Security" EventCode=4624 earliest=-{{lookback}}
    (LogonType=2 OR LogonType=10 OR Logon_Type=2 OR Logon_Type=10)
    TargetUserName="{{account_pattern}}"
| stats count min(_time) as first_seen max(_time) as last_seen values(IpAddress) as sources
    by host TargetUserName LogonType
| convert ctime(first_seen) ctime(last_seen)`,
      placeholders: [
        { name: 'index', kind: 'string', description: 'Index holding Windows Security events.', example: 'wineventlog' },
        PH.lookback('7d'),
        { name: 'account_pattern', kind: 'string', description: 'Service-account naming pattern with wildcard.', example: 'svc_*' },
      ],
      keyFields: [{ name: 'LogonType', meaning: '2 = interactive, 10 = RDP. Service accounts should normally use 4/5.' }],
      positive: 'Interactive use of a service account needs an owner explanation.',
      negative: 'Naming conventions vary; accounts not matching the pattern are missed.',
      prerequisites: 'Security logs from servers/workstations forwarded.',
      schemaNotes: 'XML collection exposes LogonType/TargetUserName; classic collection may use Logon_Type/Account_Name - the OR covers both type fields.',
      example: 'index = wineventlog, account_pattern = svc_*',
    },
    {
      id: 'generic-valid-accounts',
      title: 'Generic valid-account procedure',
      language: 'generic',
      platform: 'Any IdP / SIEM',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Authentication logs', 'Directory audit logs', 'Application audit logs'],
      query: `1. Record the flagged sign-in (IP, location, device, user agent, app, MFA, result).
2. Baseline 30 days of sign-ins; mark new attributes.
3. Check egress/VPN lists, device assignments, and verified user confirmation.
4. Review post-sign-in actions: MFA/method changes, rules, downloads, admin actions.
5. Search the same IP/user agent for other accounts.`,
      placeholders: [],
      keyFields: [],
      positive: 'Unexplained successful access is an escalation.',
      negative: 'Absence of post-auth activity only covers logs you searched.',
      prerequisites: 'Authentication and audit logs.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Mobile carriers, cloud proxies, and VPNs cause misleading geolocation - check the ASN.',
    'Token theft can produce sign-ins with satisfied MFA claims from an unfamiliar IP.',
  ],
  visibilityGaps: [
    'Non-interactive sign-ins and service principal sign-ins are separate log categories.',
    'SaaS applications with local accounts are invisible to IdP logs.',
  ],
  relatedTechniques: [
    { id: 'T1110', reason: 'Brute force or spraying often precedes valid-account use.' },
    { id: 'T1566', reason: 'Credential phishing is a common source of valid credentials.' },
    { id: 'T1098.005', reason: 'Attackers register devices for persistence.' },
    { id: 'T1556.006', reason: 'Attackers modify MFA configuration to keep access.' },
    { id: 'T1550.004', reason: 'Stolen session cookies allow access without the password.' },
    { id: 'T1114.003', reason: 'Mail forwarding rules are a common follow-up in compromised mailboxes.' },
  ],
  references: [
    attackRef('T1078', 'Valid Accounts'),
    { title: 'Microsoft Learn - Sign-in logs in Microsoft Entra ID', url: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins' },
    { title: 'Microsoft Learn - What are risk detections?', url: 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks' },
  ],
  assumptions: ['User contact for confirmation is permitted only through channels defined in your procedure.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const bruteForce: Playbook = {
  schemaVersion: 1,
  id: 'PB-BRUTE-001',
  version: '1.0.0',
  title: 'Brute-force or password-spraying authentication activity',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'],
  tactics: ['credential-access'],
  objective:
    'Characterize the failed-authentication pattern (guessing vs. spraying vs. stuffing), identify its source, and - most importantly - determine whether any attempt succeeded.',
  alertMeaning:
    'Many failed logons were seen for one account (password guessing), for many accounts from one source (password spraying), or with leaked username/password pairs (credential stuffing). The alert counts failures; the key question is whether a success followed.',
  whyItMatters:
    'Failed attempts alone are common internet noise. A successful logon after many failures, or a spray that finds one weak password, gives the attacker a valid account.',
  difficulty: 'Beginner',
  effort: '20-40 minutes',
  platforms: ['Identity Provider', 'Windows', 'SaaS', 'Office Suite', 'Linux'],
  logSources: ['entra-signin', 'win-security', 'vpn', 'firewall', 'mde'],
  alertContext: {
    triggers: [
      'Threshold of failed sign-ins for one user (e.g. Entra ResultType 50126, Windows 4625 / 4771 / 4776 failures).',
      'One source IP failing against many different accounts in a short window (spray).',
      'Smart Lockout / account lockout events (Entra 50053, Windows 4740).',
      'Failures against VPN, RDP, OWA, SSH, or other externally exposed services.',
    ],
    reviewFirst: [
      'Target account(s), source IP(s), service/application, and time window.',
      'Failure reason codes (bad password vs. unknown user vs. locked).',
      'Whether any success exists for the same user or source in the window.',
    ],
    oftenMissing: [
      'Successful logons from the same source (often a different table or event ID).',
      'Whether the source is a corporate egress IP, VPN, or a misconfigured device with a stale password.',
    ],
  },
  prerequisites: [
    { text: 'Authentication logs for the targeted service (IdP sign-ins, DC security logs, VPN, SSH).', type: 'telemetry', required: true },
    { text: 'IP reputation / geolocation enrichment.', type: 'tool', required: false },
    { text: 'List of corporate egress IPs, VPN ranges, and known scanners.', type: 'information', required: false },
  ],
  steps: [
    {
      id: 'characterize',
      title: 'Characterize the pattern and target',
      action:
        'Count failures by user and by source IP. Classify: many failures for one user (guessing), one source against many users with few attempts each (spraying), or many user/password pairs from distributed IPs (stuffing). Record the service targeted.',
      why: 'The pattern changes what you look for next: spraying needs a check across all targeted users; guessing focuses on one account.',
      where: ['SigninLogs', 'Security 4625 (member servers/workstations), 4771/4776 (domain controllers)', 'VPN / RDP gateway logs'],
      fields: ['UserPrincipalName / TargetUserName', 'IPAddress / IpAddress', 'ResultType / Status, SubStatus', 'AppDisplayName / LogonType'],
      suspicious: [
        'One IP failing against dozens of accounts with 1-3 attempts each (spray)',
        'Many failures with "user does not exist" (0xC0000064 / AADSTS50034) - username enumeration',
        'Attempts against disabled or former-employee accounts',
      ],
      legitimate: ['A single user\'s device repeatedly retrying an old password after a password change (mail client, mapped drive, mobile device)'],
      next: 'Record counts and pattern type. Then check for successes - this is the most important step.',
      queryIds: ['kql-failures-by-ip', 'spl-auth-failures'],
    },
    {
      id: 'success-check',
      title: 'Check whether any attempt succeeded',
      action:
        'For every targeted user and every attacking source IP, search for successful authentications in the same window and up to 24 hours after. Include MFA outcomes - a correct password followed by an MFA failure (e.g. Entra 500121) still means the password is compromised.',
      why: 'A success turns a noisy alert into an account compromise. Correct password + MFA prompt also means the password is known to the attacker.',
      where: ['SigninLogs (ResultType 0 and MFA-related codes)', 'Security 4624 / 4768 success', 'VPN session logs'],
      fields: ['ResultType', 'AuthenticationRequirement', 'ConditionalAccessStatus', 'Status (Windows)', 'LogonType'],
      suspicious: ['Success from the attacking IP', 'Password accepted but MFA denied/not completed (50074/50076 followed by 500121)', 'Success for a targeted user from a new IP/country shortly after the spray'],
      legitimate: ['Successes only from the user\'s known device/location'],
      next: 'If any success or password-accepted-MFA-failed is found, go straight to the decision tree escalation path.',
      queryIds: ['kql-success-after-failures', 'spl-success-after-failures'],
    },
    {
      id: 'source',
      title: 'Profile the source',
      action:
        'Enrich source IPs: internal vs. external, ASN/hosting provider, geolocation, reputation, Tor/VPN/proxy, and whether the IP is a corporate egress or known scanner. For internal sources, identify the host and process (e.g. a service with stale credentials).',
      why: 'An internal source might be a compromised host or a misconfigured service. External hosting-provider IPs are typical of automated attacks.',
      where: ['IP enrichment/TI platform', 'DHCP / VPN logs (internal IP to host)', 'EDR network events on internal source'],
      fields: ['Source IP', 'ASN', 'Country', 'Reputation', 'Internal hostname'],
      suspicious: ['Hosting-provider or anonymization network IPs', 'Internal workstation generating failures against many accounts (possible compromised host)'],
      legitimate: ['Corporate egress IP with a single user\'s stale credentials', 'Authorized vulnerability scanner within its scan window'],
      next: 'If the source is internal and attacking many accounts, treat the source host as potentially compromised.',
      queryIds: [],
    },
    {
      id: 'account-context',
      title: 'Review the targeted accounts',
      action:
        'Identify privileged, service, executive, and disabled accounts among the targets. Check lockouts, recent password changes, and whether MFA is enforced for the targeted application.',
      why: 'Attacks against privileged or MFA-exempt accounts (legacy protocols, service accounts) are more dangerous.',
      where: ['Directory / IdP user details', 'Conditional Access results', 'Security 4740 lockouts'],
      fields: ['Account type', 'MFA registration/enforcement', 'Lockout status', 'Password last set'],
      suspicious: ['Service or admin accounts targeted', 'Legacy authentication (ClientAppUsed such as "Other clients", IMAP, POP, SMTP) bypassing MFA'],
      legitimate: ['Locked account belonging to the user with a known stale-device issue'],
      next: 'Record high-value targets for the handoff.',
      queryIds: [],
    },
    {
      id: 'post-auth',
      title: 'If a success occurred, review post-authentication activity',
      action:
        'For any successful account: review subsequent sign-ins, new MFA methods, mailbox rules, file access, VPN sessions, and hosts accessed. Do not reset the password yourself unless your procedure authorizes it.',
      why: 'Attackers act quickly after getting access - persistence (new MFA method, OAuth consent) may already be in place.',
      where: ['SigninLogs / AuditLogs', 'OfficeActivity', 'DeviceLogonEvents'],
      fields: ['OperationName', 'TargetResources', 'Subsequent IPs and apps'],
      suspicious: ['New MFA method registered', 'Inbox rule creation', 'Access to many files or admin portals'],
      legitimate: ['User confirms the activity and it matches their normal pattern'],
      next: 'Escalate with the timeline.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'any-success',
    nodes: [
      {
        id: 'any-success',
        question: 'Did any attempt succeed, or was a correct password accepted but MFA blocked/not completed, for a targeted user or from the attacking source?',
        yes: { next: 'privileged', guidance: 'The attacker likely knows a valid password.' },
        no: { next: 'stale-creds', guidance: 'No success found in available logs.' },
      },
      {
        id: 'stale-creds',
        question: 'Is the pattern explained by a known benign cause - one user\'s device with a stale password, an authorized scanner, or a misconfigured service - confirmed by the device/user/owner?',
        yes: { outcome: 'benign', guidance: 'Document the cause and owner; request the device/service fix through the service desk.' },
        no: { next: 'spray-scale', guidance: 'Unexplained failed-authentication attack with no success.' },
      },
      {
        id: 'spray-scale',
        question: 'Is the attack targeting privileged/service accounts, many accounts (spray), or coming from an internal host?',
        yes: { outcome: 'escalate', guidance: 'Escalate for blocking decisions, scoping, and (for internal sources) host investigation.' },
        no: { outcome: 'contained', guidance: 'External, failed-only attempts against a few standard accounts. Request IP blocking/monitoring per procedure and record the targeted accounts.' },
      },
      {
        id: 'privileged',
        question: 'Is the successful account privileged, or is there post-login activity (new MFA method, mailbox rules, admin portal access, lateral movement)?',
        yes: { outcome: 'critical', guidance: 'Likely account takeover with impact. Follow the incident escalation procedure now.' },
        no: { outcome: 'escalate', guidance: 'Password compromise of a standard account. Escalate for credential reset and session revocation decisions.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'First and last failure, and time of any success (UTC).'),
    ev('src_ip', true, 'Source IP(s) with ASN/country and internal/external.'),
    evCustom('targeted_accounts', 'Targeted accounts and counts', 'One per line: account - failures - lockout? - privileged?', true, true),
    evCustom('failure_codes', 'Failure reason codes', 'e.g. 50126 x 420, 50053 x 12; or 4625 0xC000006A x 300.', true),
    evCustom('pattern', 'Attack pattern', 'Guessing / spraying / stuffing; service targeted (Entra, VPN, RDP, SSH).', true),
    ev('auth_outcome', true, 'Any success or password-accepted-MFA-failed, with time and IP. Write "none found" with sources searched.'),
    ev('username', false, 'Account with a successful logon (if any).'),
    ev('hostname', false, 'Internal source host (if any).'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Any successful authentication from the attacking source or for a targeted user from a new location shortly after the attack.',
      'Password accepted but MFA not completed (attacker knows the password).',
      'Spraying across many accounts or targeting privileged/service accounts, even without success.',
      'Failures originating from an internal host that is not a known misconfigured service.',
      'Legacy-authentication attempts against accounts where MFA cannot be enforced.',
    ],
    immediate: [
      'Successful compromise of a privileged account.',
      'Post-login persistence (new MFA method, OAuth consent, mailbox rule) on a compromised account.',
      'Multiple accounts successfully accessed from the attacking infrastructure.',
    ],
    benignClosure: [
      'Cause confirmed as a single user\'s stale credentials, authorized scanner, or misconfigured service.',
      'No successful authentication from the source or for targeted users in the reviewed window.',
    ],
  },
  queries: [
    {
      id: 'kql-failures-by-ip',
      title: 'Failed Entra ID sign-ins grouped by source IP',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID connector)',
      purpose: 'Shows each source IP\'s failure count and number of distinct targeted users to distinguish guessing from spraying.',
      dataSources: ['SigninLogs'],
      query: `SigninLogs
| where TimeGenerated > ago({{lookback}})
| where ResultType in ("50126", "50053", "50055", "50057", "50034")
| summarize Failures = count(), DistinctUsers = dcount(UserPrincipalName),
            Users = make_set(UserPrincipalName, 50), Apps = make_set(AppDisplayName, 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by IPAddress, Location
| order by DistinctUsers desc, Failures desc`,
      placeholders: [PH.lookback('24h')],
      keyFields: [
        { name: 'DistinctUsers', meaning: 'High values with low per-user counts suggest password spraying.' },
        { name: 'ResultType', meaning: '50126 bad password; 50053 locked/blocked; 50055 expired password; 50057 disabled account; 50034 user not found.' },
      ],
      positive: 'Identifies attacking IPs and their targets. It does not show successes - run the success query next.',
      negative: 'No rows may mean sign-ins are logged in AADNonInteractiveUserSignInLogs or another IdP, or the failure codes differ.',
      prerequisites: 'Entra ID sign-in logs in Sentinel.',
      schemaNotes: 'ResultType is a string column in SigninLogs. Add AADNonInteractiveUserSignInLogs with union for complete coverage.',
      example: 'lookback = 24h',
    },
    {
      id: 'kql-success-after-failures',
      title: 'Successful or MFA-interrupted sign-ins from attacking IPs',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID connector)',
      purpose: 'Finds IPs with many failures that also produced a success or a password-accepted MFA interruption.',
      dataSources: ['SigninLogs'],
      query: `let failures = SigninLogs
    | where TimeGenerated > ago({{lookback}})
    | where ResultType == "50126"
    | summarize FailCount = count() by IPAddress
    | where FailCount >= {{min_failures}};
SigninLogs
| where TimeGenerated > ago({{lookback}})
| where IPAddress in ((failures | project IPAddress))
| where ResultType in ("0", "50074", "50076", "500121")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          ResultType, ResultDescription, AuthenticationRequirement, ClientAppUsed
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('24h'), { name: 'min_failures', kind: 'number', description: 'Minimum failures for an IP to be considered attacking.', example: '10' }],
      keyFields: [
        { name: 'ResultType', meaning: '0 success; 50074/50076 MFA required (password was correct); 500121 MFA failed/not completed.' },
        { name: 'ClientAppUsed', meaning: 'Legacy protocols may bypass MFA.' },
      ],
      positive: 'Any row means the attacker likely has a valid password for that user - escalate.',
      negative: 'No rows means no success from those IPs in this table; attackers may switch IPs after finding a password. Also review targeted users\' successes from any new IP.',
      prerequisites: 'Entra ID sign-in logs in Sentinel.',
      schemaNotes: 'Result codes are documented in Microsoft Entra error codes; behavior of MFA-related codes can vary by policy.',
      example: 'lookback = 24h, min_failures = 10',
    },
    {
      id: 'spl-auth-failures',
      title: 'Authentication failures by source (CIM Authentication)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Counts failures and distinct users per source across any authentication data mapped to CIM (Windows, VPN, SSH, IdP).',
      dataSources: ['CIM Authentication data model'],
      query: `| tstats summariesonly=false count as failures dc(Authentication.user) as distinct_users
    values(Authentication.app) as apps min(_time) as first_seen max(_time) as last_seen
    from datamodel=Authentication
    where earliest=-{{lookback}} Authentication.action="failure"
    by Authentication.src
| where failures >= {{min_failures}}
| convert ctime(first_seen) ctime(last_seen)
| sort - distinct_users`,
      placeholders: [PH.lookback('24h'), { name: 'min_failures', kind: 'number', description: 'Minimum failure count to show.', example: '20' }],
      keyFields: [
        { name: 'distinct_users', meaning: 'Many users per source suggests spraying.' },
        { name: 'Authentication.src', meaning: 'Source IP or host.' },
      ],
      positive: 'Lists candidate attacking sources. Pair with the success search.',
      negative: 'Sources not mapped to CIM Authentication are missed.',
      prerequisites: 'Authentication logs mapped to CIM.',
      schemaNotes: 'Windows 4625 typically maps to action=failure; field quality varies by add-on.',
      example: 'lookback = 24h, min_failures = 20',
    },
    {
      id: 'spl-success-after-failures',
      title: 'Sources with both failures and successes (CIM Authentication)',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds source/user pairs with many failures followed by at least one success.',
      dataSources: ['CIM Authentication data model'],
      query: `| tstats summariesonly=false count from datamodel=Authentication
    where earliest=-{{lookback}} by Authentication.src Authentication.user Authentication.action
| rename Authentication.* as *
| eval failures=if(action="failure", count, 0), successes=if(action="success", count, 0)
| stats sum(failures) as failures sum(successes) as successes by src user
| where failures >= {{min_failures}} AND successes > 0
| sort - failures`,
      placeholders: [PH.lookback('24h'), { name: 'min_failures', kind: 'number', description: 'Minimum failures before a success to flag.', example: '10' }],
      keyFields: [{ name: 'successes', meaning: 'Any success after many failures needs review.' }],
      positive: 'A source/user pair with a success is a potential compromise - confirm timing (success after failures).',
      negative: 'This does not order events in time; a success before the failures is not the same thing. Check the raw timeline.',
      prerequisites: 'Authentication logs mapped to CIM.',
      schemaNotes: 'Action values depend on add-on mapping.',
      example: 'lookback = 24h, min_failures = 10',
    },
    {
      id: 'generic-brute',
      title: 'Generic brute-force procedure',
      language: 'generic',
      platform: 'Any IdP / SIEM',
      purpose: 'Platform-neutral checklist.',
      dataSources: ['Authentication logs for the targeted service'],
      query: `1. Group failures by source and by user; classify guessing vs spraying vs stuffing.
2. For each source and each targeted user: search successes (and "password correct, MFA
   failed") from the attack start to +24h.
3. Enrich sources: internal/external, ASN, reputation, corporate egress, scanners.
4. Flag privileged/service/MFA-exempt targets.
5. For any success: review the account's subsequent activity.`,
      placeholders: [],
      keyFields: [],
      positive: 'A success is the critical finding.',
      negative: 'No success found only covers the logs searched.',
      prerequisites: 'Authentication logs.',
      schemaNotes: 'Adapt to your platform.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Spraying is designed to stay under per-account lockout thresholds; aggregate by source and by time, not only per user.',
    'Distributed attacks use many IPs; group by user agent, target list, or timing as well.',
    'Windows: 4625 is logged where the logon was attempted; domain-account failures also appear as 4771/4776 on DCs.',
  ],
  visibilityGaps: [
    'Non-interactive sign-ins and legacy protocols may be logged separately or not at all.',
    'Cloud-to-cloud attacks against SaaS apps with their own authentication bypass the IdP logs.',
  ],
  relatedTechniques: [
    { id: 'T1078.004', reason: 'A successful brute force results in use of a valid cloud account.' },
    { id: 'T1078.002', reason: 'Successful guessing of domain accounts.' },
    { id: 'T1621', reason: 'Attackers with a valid password may flood the user with MFA prompts.' },
    { id: 'T1110.002', reason: 'Offline password cracking follows credential dumping and does not appear in authentication logs.' },
  ],
  references: [
    attackRef('T1110.003', 'Password Spraying'),
    { title: 'Microsoft Entra authentication and authorization error codes', url: 'https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes' },
    { title: 'Microsoft Learn - 4625(F): An account failed to log on', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625' },
    { title: 'Splunk CIM - Authentication data model', url: 'https://docs.splunk.com/Documentation/CIM/latest/User/Authentication' },
  ],
  assumptions: ['IP blocking and account resets are requested through the approved process.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

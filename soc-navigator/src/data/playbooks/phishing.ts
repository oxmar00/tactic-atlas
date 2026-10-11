import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, ev, evCustom, starterReview } from './helpers';

export const phishing: Playbook = {
  schemaVersion: 1,
  id: 'PB-PHISH-001',
  version: '1.0.0',
  title: 'Reported or detected phishing email',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1566', 'T1566.001', 'T1566.002'],
  tactics: ['initial-access'],
  objective:
    'Decide whether a reported or filtered email is phishing, find every recipient of the same campaign, and determine whether anyone clicked, opened, replied, or entered credentials.',
  alertMeaning:
    'A user reported a suspicious email, or the mail filter flagged a message for a malicious URL, attachment, spoofed sender, or impersonation. The alert says a message exists; it does not say anyone interacted with it.',
  whyItMatters:
    'Phishing is one of the most common ways attackers get initial access. The danger is not the email itself but what happens after delivery: a click that harvests a password, or an attachment that runs code.',
  difficulty: 'Beginner',
  effort: '20-45 minutes per campaign',
  platforms: ['Office Suite', 'SaaS', 'Windows', 'macOS'],
  logSources: ['email-security', 'm365-audit', 'proxy', 'dns', 'mde', 'entra-signin'],
  alertContext: {
    triggers: [
      'User clicked "Report phishing" in the mail client.',
      'Email filter verdict: phish, malware, spoof, or impersonation (e.g. Defender for Office 365, secure email gateway).',
      'Post-delivery removal (ZAP) or a URL detonation verdict changed after delivery.',
    ],
    reviewFirst: [
      'Message identifiers: NetworkMessageId / InternetMessageId, delivery time, and recipient.',
      'Sender display name, From address, Return-Path / MailFrom, and sending IP.',
      'Whether it was delivered to Inbox, Junk, or quarantined.',
      'URLs and attachments listed by the filter (do not open them).',
    ],
    oftenMissing: [
      'Whether the user actually clicked or opened anything.',
      'Other recipients of the same campaign.',
      'What happened on the identity side after a click (sign-ins, MFA prompts).',
    ],
  },
  prerequisites: [
    { text: 'Read access to email security logs / message trace (Defender for Office 365 or your gateway).', type: 'access', required: true },
    { text: 'Access to an approved URL/file detonation sandbox or reputation service. Never open links or attachments on your workstation.', type: 'tool', required: true },
    { text: 'Proxy, DNS, or Safe Links click logs to confirm interaction.', type: 'telemetry', required: true },
    { text: 'Entra ID / IdP sign-in logs for recipients who clicked.', type: 'telemetry', required: false },
    { text: 'EDR timeline for recipients who opened an attachment.', type: 'telemetry', required: false },
    { text: 'Your organization\'s phishing procedure (who may purge mail, block senders, and reset passwords).', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'identify-message',
      title: 'Identify the exact message and how it was detected',
      action:
        'Open the alert or user report and record the message identifiers, sender, recipients, subject, delivery time (with timezone), and the detection source. Confirm the message exists in message trace.',
      why: 'You need a stable identifier (NetworkMessageId / InternetMessageId) to search for copies and clicks. User reports sometimes forward the message, which changes headers.',
      where: ['Email security console / message trace', 'EmailEvents (Defender XDR)', 'Gateway message logs'],
      fields: ['NetworkMessageId', 'InternetMessageId', 'SenderFromAddress', 'RecipientEmailAddress', 'Subject', 'DeliveryAction', 'DeliveryLocation', 'ThreatTypes', 'DetectionMethods'],
      suspicious: ['Delivered to Inbox although a threat type was recorded', 'Message removed by post-delivery protection (ZAP) after users already had it'],
      legitimate: ['Message was quarantined before delivery and no copy reached a mailbox', 'Report is a known phishing-simulation campaign (check with the awareness team)'],
      next: 'If no copy reached any mailbox, note it and continue only to confirm the sender is malicious for blocking. Otherwise continue to sender analysis.',
      queryIds: ['kql-message-scope', 'spl-email-scope'],
    },
    {
      id: 'sender-authentication',
      title: 'Check sender identity and authentication results',
      action:
        'Compare display name, From address, Return-Path/MailFrom, and Reply-To. Review SPF, DKIM, DMARC and composite authentication results. Look for lookalike domains (extra letters, swapped characters, different TLD) and first-time senders.',
      why: 'Many phishing emails impersonate a trusted person or vendor. Authentication failures or lookalike domains are strong evidence; passing authentication only proves the domain sent it, not that the domain is trustworthy.',
      where: ['Message headers / message trace detail', 'EmailEvents.AuthenticationDetails', 'Gateway authentication fields'],
      fields: ['SenderFromAddress', 'SenderMailFromAddress', 'SenderIPv4', 'AuthenticationDetails (SPF, DKIM, DMARC, CompAuth)', 'Reply-To header'],
      suspicious: [
        'DMARC fail or CompAuth fail for the claimed domain',
        'Display name of an executive or vendor with an external or free-mail address',
        'Reply-To points to a different domain than From',
        'Recently registered or lookalike domain',
      ],
      legitimate: ['Known partner domain with SPF/DKIM/DMARC pass and an established mail history', 'Marketing platform sending on behalf of a known vendor (check the vendor relationship)'],
      next: 'Record the authentication results. Continue to content analysis regardless; legitimate accounts can be compromised and used to send phishing.',
      queryIds: [],
    },
    {
      id: 'analyze-content',
      title: 'Analyze URLs and attachments safely',
      action:
        'Extract URLs and attachment names/hashes from the security console (not by opening the message). Submit to your approved sandbox or reputation service. Note file types that commonly deliver malware (HTML, ISO/IMG, ZIP with scripts, LNK, OneNote, macro-enabled Office) and pages that ask for credentials.',
      why: 'The URL or attachment determines the risk: credential harvesting leads to account takeover, malicious files lead to code execution on endpoints.',
      where: ['EmailUrlInfo / EmailAttachmentInfo', 'Sandbox or detonation reports', 'Threat-intelligence platform (internal)'],
      fields: ['Url', 'UrlDomain', 'FileName', 'FileType', 'SHA256', 'Sandbox verdict'],
      suspicious: [
        'Credential prompt imitating Microsoft 365, VPN, or payroll login',
        'URL shortener or open redirect chaining to an unrelated domain',
        'HTML attachment that builds a file locally (HTML smuggling)',
        'Password-protected archive with the password in the email body',
      ],
      legitimate: ['URL resolves to the vendor\'s real domain and the sandbox shows no malicious behavior', 'Attachment is a document type and template the sender routinely uses'],
      next: 'If the content is malicious, scope the campaign. If benign but the sender is unverified, continue scoping before deciding.',
      queryIds: [],
    },
    {
      id: 'scope-campaign',
      title: 'Find every recipient of the campaign',
      action:
        'Search for other messages with the same sender, subject, sending IP, URL domain, or attachment hash in the last 7 days. Record how many were delivered, to whom, and where (Inbox, Junk, quarantine).',
      why: 'Attackers rarely send one email. The reported message is usually one of many, and the riskiest recipient may not be the one who reported it.',
      where: ['EmailEvents / message trace', 'Email data model in Splunk'],
      fields: ['RecipientEmailAddress', 'DeliveryAction', 'DeliveryLocation', 'SenderIPv4', 'UrlDomain', 'SHA256'],
      suspicious: ['Many recipients across departments', 'Recipients in finance, HR, executive assistants, or IT administrators', 'Messages delivered to Inbox'],
      legitimate: ['Single recipient with a documented business relationship to the sender'],
      next: 'List the delivered recipients; they are the people you must check for interaction in the next step.',
      queryIds: ['kql-message-scope', 'spl-email-scope'],
    },
    {
      id: 'check-interaction',
      title: 'Determine whether anyone clicked, opened, or replied',
      action:
        'For each delivered recipient, check URL click logs, proxy/DNS logs for the phishing domain, endpoint file events for the attachment hash, and sent items for replies. Note the time of the first interaction.',
      why: 'Interaction is what turns a phishing email into a potential compromise. Without click evidence you cannot rule out compromise.',
      where: ['UrlClickEvents (Safe Links)', 'Proxy / secure web gateway logs', 'DNS logs', 'DeviceFileEvents (attachment saved or opened)'],
      fields: ['AccountUpn', 'Url', 'ActionType (ClickAllowed / ClickBlocked)', 'IsClickedThrough', 'Proxy src/user/url/status', 'DeviceFileEvents SHA256'],
      suspicious: ['ClickAllowed or IsClickedThrough = true', 'Proxy request to the phishing domain with HTTP 200 and a POST (form submission)', 'Attachment written to Downloads/Temp and opened'],
      legitimate: ['All clicks blocked by policy', 'No proxy/DNS hits for the domain from any recipient'],
      next: 'If anyone interacted, check identity and endpoint follow-on activity. If click logging is unavailable, record that as a visibility gap - it is not proof that nobody clicked.',
      queryIds: ['kql-url-clicks', 'spl-web-clicks'],
    },
    {
      id: 'check-follow-on',
      title: 'Check for account or endpoint compromise after interaction',
      action:
        'For users who clicked a credential-harvesting link: review sign-ins in the 48 hours after the click for new IPs, countries, devices, user agents, MFA prompts, and new inbox rules or MFA methods. For users who opened an attachment: review the endpoint for Office or browser launching scripts or binaries.',
      why: 'This is where you find out whether the attack succeeded. An unfamiliar successful sign-in or new mailbox forwarding rule is a likely account takeover.',
      where: ['SigninLogs / IdP logs', 'AuditLogs (security info registered)', 'OfficeActivity (New-InboxRule)', 'EDR process timeline'],
      fields: ['IPAddress', 'Location', 'ResultType', 'AuthenticationRequirement', 'UserAgent', 'OperationName', 'InitiatingProcessFileName', 'ProcessCommandLine'],
      suspicious: [
        'Successful sign-in from a new country/ASN shortly after the click',
        'MFA prompts the user did not initiate, or a new MFA method registered',
        'Inbox rule that forwards, deletes, or moves mail to RSS/Archive folders',
        'Outlook/Word spawning powershell.exe, mshta.exe, wscript.exe, or rundll32.exe',
      ],
      legitimate: ['Sign-ins only from the user\'s usual devices and locations', 'User confirms they closed the page without entering anything AND logs agree'],
      next: 'Use the decision tree. Any sign of compromise is an escalation; do not try to remediate the account yourself unless your procedure says so.',
      queryIds: ['kql-signins-after-click'],
    },
    {
      id: 'recommend-disposition',
      title: 'Record findings and recommend a disposition',
      action:
        'Summarize: verdict on the message, number of recipients, who interacted, and what follow-on activity you checked. Request purge/blocking through the approved process. Choose closure, escalation, or evidence gap using the decision tree.',
      why: 'Tier 2 and future analysts rely on your notes. A clear record of what was checked (and what could not be checked) prevents repeated work and missed compromises.',
      where: ['Investigation workspace', 'Ticketing / case system'],
      fields: ['Recipients delivered', 'Recipients who clicked', 'Accounts with anomalous sign-ins', 'Remediation requested'],
      suspicious: ['Any interaction you could not fully rule out'],
      legitimate: ['Verified business sender or documented simulation'],
      next: 'Generate the Tier 2 handoff if any escalation criterion is met.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'malicious-content',
    nodes: [
      {
        id: 'malicious-content',
        question: 'Is the message malicious or suspicious (authentication failure, lookalike/impersonated sender, credential-harvesting page, malicious sandbox verdict, or a risky attachment type)?',
        help: 'Base this on Steps 2-3. "Suspicious" is enough to continue - you do not need a confirmed malware verdict.',
        yes: { next: 'delivered', guidance: 'Treat as a phishing campaign and determine its reach.' },
        no: { next: 'verified-legit', guidance: 'Confirm the sender is genuinely legitimate before closing.' },
      },
      {
        id: 'verified-legit',
        question: 'Is the sender verified as legitimate and the content expected (authentication passes, known relationship, URLs go to the expected domain, clean sandbox result) - or is it a documented phishing simulation?',
        yes: { outcome: 'benign', guidance: 'Document the verification source (e.g. vendor contact, simulation campaign ID) and the authentication results. Release from quarantine only through the approved process.' },
        no: { outcome: 'investigate', guidance: 'You could not verify legitimacy. Treat as suspicious: scope recipients and check interaction before closing.' },
      },
      {
        id: 'delivered',
        question: 'Was at least one copy delivered to a mailbox (Inbox, Junk, or other folder) rather than blocked before delivery?',
        yes: { next: 'interaction', guidance: 'Delivered phishing needs an interaction check for every recipient.' },
        no: { outcome: 'contained', guidance: 'Blocked pre-delivery. Request sender/URL blocking per procedure, record the campaign indicators, and close if your procedure allows.' },
      },
      {
        id: 'interaction',
        question: 'Did any recipient click the link, open the attachment, or reply with information?',
        help: 'Use click logs, proxy/DNS logs, endpoint file events, and sent items. If click logging is not available for these users, answer "Cannot determine".',
        yes: { next: 'compromise', guidance: 'Check identity and endpoint follow-on activity for each interacting user.' },
        no: { outcome: 'contained', guidance: 'No interaction found in available logs. Request purge of delivered copies and blocking of indicators per procedure. Record the log sources you checked.' },
        unknown: { outcome: 'gap', guidance: 'Click/interaction telemetry is missing for some recipients. Missing logs are not proof of no click - document the gap and escalate per policy.' },
      },
      {
        id: 'compromise',
        question: 'Is there evidence of compromise: unfamiliar successful sign-in, unexpected MFA prompts or new MFA method, a new forwarding/deletion inbox rule, or code execution after opening the attachment?',
        yes: { next: 'widespread', guidance: 'Account or endpoint compromise is likely.' },
        no: { outcome: 'escalate', guidance: 'A user interacted with confirmed phishing. Even with no follow-on activity found, escalate so Tier 2 can confirm and decide on password reset / session revocation.' },
      },
      {
        id: 'widespread',
        question: 'Does the compromise involve a privileged/executive account, multiple users, or active malware with outbound connections?',
        yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure immediately. Provide the list of affected users and hosts.' },
        no: { outcome: 'escalate', guidance: 'Single-user compromise. Escalate to Tier 2 with sign-in and mailbox evidence for containment decisions.' },
      },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true, 'Filter verdict or "User reported" plus the reporting user.'),
    ev('event_time', true, 'Delivery time and, if known, first click time (UTC).'),
    evCustom('message_id', 'NetworkMessageId / InternetMessageId', 'Copy from message trace. Needed for purge and click searches.', true),
    evCustom('sender', 'Sender (From, MailFrom, Reply-To) and sending IP', 'e.g. From: billing@examp1e.com, MailFrom: bounce@mailer.test, IP 198.51.100.7', true, true),
    evCustom('auth_results', 'SPF / DKIM / DMARC / CompAuth results', 'Copy from AuthenticationDetails or headers.', true),
    evCustom('subject', 'Subject line', 'Exact subject, including any prefixes.', false),
    evCustom('recipients', 'Recipients and delivery location', 'Count delivered vs. blocked; list delivered recipients.', true, true),
    evCustom('urls', 'URLs and domains', 'Defanged, e.g. hxxps://login-examp1e[.]com/auth', false, true),
    ev('file_hash', false, 'Attachment name, type, and SHA-256.'),
    evCustom('sandbox', 'Sandbox / reputation verdicts', 'Tool, verdict, and report link.', false, true),
    evCustom('interaction', 'Recipients who clicked, opened, or replied', 'User, time, and source (click log, proxy, EDR).', true, true),
    ev('username', false, 'UPN of each recipient who interacted (used for the sign-in review).'),
    ev('auth_outcome', false, 'Sign-ins after the click: IP, location, result, MFA requirement.'),
    ev('hostname', false, 'Endpoints where an attachment was opened.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: [
      'Any recipient clicked a malicious link, opened a malicious attachment, or replied with sensitive information.',
      'A user may have entered credentials on a phishing page (user statement or log evidence).',
      'Recipients include executives, finance staff handling payments, HR, or privileged IT administrators.',
      'The campaign was delivered to more mailboxes than the threshold in your phishing policy.',
      'Interaction cannot be ruled out because click, proxy, or DNS logs are unavailable for delivered recipients.',
      'The message is a business email compromise (payment change, gift card, or invoice fraud) request.',
    ],
    immediate: [
      'Successful sign-in by an unknown party, new MFA method, or new inbox forwarding/deletion rule on a recipient account.',
      'Code execution on an endpoint after an attachment was opened, especially with outbound connections.',
      'Multiple accounts compromised by the same campaign, or a privileged account compromised.',
    ],
    benignClosure: [
      'Sender verified through an independent channel or established relationship, with SPF/DKIM/DMARC pass for the claimed domain.',
      'All URLs resolve to the expected legitimate domain and attachments have clean sandbox results.',
      'Or: message confirmed as an authorized phishing simulation (record the campaign ID).',
    ],
  },
  queries: [
    {
      id: 'kql-message-scope',
      title: 'Scope the campaign: all copies from the sender or with the subject',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Lists every message from the reported sender or with the same subject, with delivery outcome and authentication details, so you can see who received it.',
      dataSources: ['EmailEvents'],
      query: `EmailEvents
| where Timestamp > ago({{lookback}})
| where SenderFromAddress =~ "{{sender}}" or Subject == "{{subject}}"
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress,
          SenderMailFromAddress, SenderIPv4, RecipientEmailAddress, Subject,
          DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods,
          AuthenticationDetails
| order by Timestamp asc`,
      placeholders: [
        PH.lookback('7d'),
        { name: 'sender', kind: 'string', description: 'Sender From address.', example: 'billing@examp1e.com' },
        { name: 'subject', kind: 'string', description: 'Exact subject line (case-sensitive match with ==).', example: 'Invoice overdue - action required' },
      ],
      keyFields: [
        { name: 'DeliveryAction / DeliveryLocation', meaning: 'Whether the copy was delivered, junked, or blocked, and to which folder.' },
        { name: 'ThreatTypes / DetectionMethods', meaning: 'Filter verdict (Phish, Malware, Spam) and the technology that produced it.' },
        { name: 'AuthenticationDetails', meaning: 'JSON with SPF, DKIM, DMARC and CompAuth results.' },
      ],
      positive: 'Rows show which mailboxes received copies and whether they were delivered. It does not show whether anyone opened or clicked.',
      negative: 'No rows can mean the sender/subject differ slightly between copies, the lookback is too short, or mail flows through a gateway not logged here. It does not prove the message was not delivered elsewhere.',
      prerequisites: 'Defender for Office 365 Plan 2 (or Defender XDR) advanced hunting access, or the Defender XDR connector streaming EmailEvents to Sentinel. In Sentinel you may filter on TimeGenerated instead of Timestamp.',
      schemaNotes: 'Column names follow the Microsoft Defender XDR advanced hunting schema. Retention in advanced hunting is 30 days. Subject matching with == is exact; use has for partial matches.',
      example: 'sender = billing@examp1e.com, subject = "Invoice overdue - action required", lookback = 7d',
    },
    {
      id: 'kql-url-clicks',
      title: 'Who clicked links to the phishing domain',
      language: 'kql',
      platform: 'Microsoft Defender XDR advanced hunting / Microsoft Sentinel',
      purpose: 'Shows Safe Links click events for URLs containing the phishing domain, including whether the click was allowed or the user clicked through a warning.',
      dataSources: ['UrlClickEvents'],
      query: `UrlClickEvents
| where Timestamp > ago({{lookback}})
| where Url has "{{url_domain}}"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough,
          IPAddress, Workload, NetworkMessageId, ThreatTypes
| order by Timestamp asc`,
      placeholders: [PH.lookback('7d'), { name: 'url_domain', kind: 'string', description: 'Phishing domain (not defanged).', example: 'login-examp1e.com' }],
      keyFields: [
        { name: 'ActionType', meaning: 'ClickAllowed, ClickBlocked, ClickBlockedByTenantPolicy, and similar.' },
        { name: 'IsClickedThrough', meaning: 'True when the user bypassed a warning page.' },
        { name: 'AccountUpn', meaning: 'User who clicked.' },
      ],
      positive: 'A ClickAllowed or clicked-through row shows the user reached the URL. It does not prove credentials were entered - check sign-ins next.',
      negative: 'No rows mean no click was recorded by Safe Links. Clicks from personal devices, non-rewritten links, copied/pasted URLs, or QR codes are not recorded here. Check proxy and DNS logs before concluding.',
      prerequisites: 'Defender for Office 365 Safe Links enabled for the recipients; UrlClickEvents available in advanced hunting or Sentinel.',
      schemaNotes: 'ActionType values are documented by Microsoft and may be extended over time. Only links rewritten/protected by Safe Links appear.',
      example: 'url_domain = login-examp1e.com, lookback = 7d',
    },
    {
      id: 'kql-signins-after-click',
      title: 'Sign-ins for a user in the 48 hours after a click',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID connector)',
      purpose: 'Reviews a recipient\'s sign-ins after the click to spot an attacker using harvested credentials (new IP, country, client, or MFA anomalies).',
      dataSources: ['SigninLogs'],
      query: `let clickTime = datetime({{click_time}});
SigninLogs
| where TimeGenerated between (clickTime .. (clickTime + 2d))
| where UserPrincipalName =~ "{{upn}}"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location,
          ResultType, ResultDescription, ConditionalAccessStatus,
          AuthenticationRequirement, ClientAppUsed, UserAgent, RiskLevelDuringSignIn
| order by TimeGenerated asc`,
      placeholders: [
        { name: 'click_time', kind: 'datetime', description: 'Time of the first click (ISO 8601 UTC).', example: '2026-10-10T14:03:11Z' },
        PH.upn(),
      ],
      keyFields: [
        { name: 'ResultType', meaning: '0 = success. 50126 = bad password, 500121 = MFA not completed, 53003 = blocked by Conditional Access.' },
        { name: 'IPAddress / Location', meaning: 'Compare against the user\'s normal locations and corporate egress IPs.' },
        { name: 'AuthenticationRequirement', meaning: 'singleFactorAuthentication vs multiFactorAuthentication.' },
      ],
      positive: 'A successful sign-in from an unfamiliar IP/location soon after the click is strong evidence of credential compromise and needs escalation. Unfamiliar does not automatically mean malicious (travel, VPN, mobile carrier).',
      negative: 'No unusual sign-ins in this table does not rule out compromise: non-interactive sign-ins (AADNonInteractiveUserSignInLogs), token theft, and other IdPs are not covered.',
      prerequisites: 'Entra ID sign-in logs exported to the Sentinel workspace (Entra ID P1/P2).',
      schemaNotes: 'If your IdP is not Entra ID (e.g. Okta, Ping), use the equivalent authentication log. Consider also querying AADNonInteractiveUserSignInLogs.',
      example: 'click_time = 2026-10-10T14:03:11Z, upn = jdoe@example.com',
    },
    {
      id: 'spl-email-scope',
      title: 'Scope the campaign with the CIM Email data model',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Counts messages from the sender grouped by subject and lists recipients and filter actions.',
      dataSources: ['CIM Email data model (gateway or Microsoft 365 add-on mapped to CIM)'],
      query: `| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen
    values(All_Email.recipient) as recipients values(All_Email.action) as actions
    from datamodel=Email
    where earliest=-{{lookback}} All_Email.src_user="{{sender}}"
    by All_Email.src_user All_Email.subject
| convert ctime(first_seen) ctime(last_seen)`,
      placeholders: [PH.lookback('7d'), { name: 'sender', kind: 'string', description: 'Sender address.', example: 'billing@examp1e.com' }],
      keyFields: [
        { name: 'All_Email.recipient', meaning: 'Recipients of matching messages.' },
        { name: 'All_Email.action', meaning: 'Gateway action (delivered, blocked, quarantined) as mapped by your add-on.' },
      ],
      positive: 'Shows campaign size and recipients. Does not show clicks or opens.',
      negative: 'Empty results may mean the Email data model is not populated or not accelerated (summariesonly=false searches raw mapped events but is slower). Confirm with a raw search of your gateway index.',
      prerequisites: 'Email logs mapped to the CIM Email data model; permission to run tstats on it.',
      schemaNotes: 'CIM field population depends on the vendor add-on. Some gateways put the sender in All_Email.src_user, others in a vendor field.',
      example: 'sender = billing@examp1e.com, lookback = 7d',
    },
    {
      id: 'spl-web-clicks',
      title: 'Proxy requests to the phishing domain',
      language: 'spl',
      platform: 'Splunk Enterprise / Enterprise Security (CIM)',
      purpose: 'Finds users and source IPs that requested the phishing domain through the web proxy, which also covers clicks not seen by email link protection.',
      dataSources: ['CIM Web data model (proxy / secure web gateway)'],
      query: `| tstats summariesonly=false count min(_time) as first_seen max(_time) as last_seen
    values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as status
    from datamodel=Web
    where earliest=-{{lookback}} Web.dest="*{{url_domain}}*"
    by Web.src Web.user
| convert ctime(first_seen) ctime(last_seen)`,
      placeholders: [PH.lookback('7d'), { name: 'url_domain', kind: 'string', description: 'Phishing domain.', example: 'login-examp1e.com' }],
      keyFields: [
        { name: 'Web.http_method', meaning: 'POST to a credential page suggests a form was submitted.' },
        { name: 'Web.status', meaning: 'HTTP status; 200 means content was served.' },
      ],
      positive: 'A request shows the user\'s browser reached the domain. A POST suggests data submission but is not proof that real credentials were sent.',
      negative: 'No results do not prove no visit: off-network devices, mobile devices, and DNS-over-HTTPS can bypass the proxy.',
      prerequisites: 'Proxy logs mapped to the CIM Web data model.',
      schemaNotes: 'Leading wildcards are slow; prefer an exact Web.dest value if known. Field names depend on the proxy add-on.',
      example: 'url_domain = login-examp1e.com',
    },
    {
      id: 'generic-phish',
      title: 'Generic phishing investigation procedure (any email platform)',
      language: 'generic',
      platform: 'Any email gateway, SIEM, or EDR',
      purpose: 'Platform-neutral checklist when you do not know which SIEM or mail platform holds the data.',
      dataSources: ['Message trace', 'Click / proxy / DNS logs', 'Identity provider sign-ins'],
      query: `1. Message trace: search sender address AND subject AND sending IP over the last 7 days.
   Record delivered vs blocked per recipient.
2. URL/attachment: collect domains and SHA-256 hashes from the security console.
   Submit to the approved sandbox only.
3. Interaction: search click logs, proxy logs (dest = phishing domain), and DNS logs
   (query = phishing domain) for each delivered recipient.
4. Follow-on: for interacting users, review IdP sign-ins for 48h after the first click;
   for opened attachments, review endpoint process trees under the mail client.
5. Record each source you searched, the time range, and the result count.`,
      placeholders: [],
      keyFields: [],
      positive: 'Each positive result is a lead to confirm, not a verdict.',
      negative: 'A negative result only covers the data source and time range you searched. Record both.',
      prerequisites: 'Read access to mail, network, and identity logs.',
      schemaNotes: 'Adapt to your platform; field names differ between products.',
      example: '',
    },
  ],
  detectionConsiderations: [
    'Filter verdicts change after delivery (URL detonation, ZAP). Check the latest verdict, not only the one in the original alert.',
    'Legitimate but compromised vendor mailboxes pass SPF/DKIM/DMARC - authentication pass is not proof of safety.',
    'QR-code phishing moves the click to a phone that may not be monitored.',
  ],
  visibilityGaps: [
    'Safe Links / click logs do not record clicks from personal devices or links the user copied manually.',
    'Mailbox rules and MFA registrations are in separate audit logs that may not be collected.',
    'If mail flows through a third-party gateway, Microsoft email tables may show only partial data.',
  ],
  relatedTechniques: [
    { id: 'T1204.001', reason: 'User clicking a malicious link is the execution step that follows a link-based phish.' },
    { id: 'T1204.002', reason: 'Opening a malicious attachment is the execution step for attachment-based phishing.' },
    { id: 'T1078.004', reason: 'Harvested credentials are used to sign in to cloud accounts.' },
    { id: 'T1114.003', reason: 'Attackers often create forwarding rules in compromised mailboxes.' },
    { id: 'T1564.008', reason: 'Inbox rules that hide security notifications or replies.' },
    { id: 'T1534', reason: 'Compromised mailboxes are used to phish other employees internally.' },
    { id: 'T1684.002', reason: 'Spoofed sender addresses are a common phishing component.' },
  ],
  references: [
    attackRef('T1566', 'Phishing'),
    { title: 'Microsoft Learn - EmailEvents table (advanced hunting)', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table' },
    { title: 'Microsoft Learn - UrlClickEvents table (advanced hunting)', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table' },
    { title: 'Microsoft Entra authentication and authorization error codes', url: 'https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes' },
    { title: 'Splunk CIM - Email data model', url: 'https://docs.splunk.com/Documentation/CIM/latest/User/Email' },
  ],
  assumptions: [
    'Tier 1 does not purge mail or reset passwords unless the phishing procedure explicitly grants that permission.',
    'The escalation threshold for campaign size is defined in your local phishing policy.',
  ],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, starterReview } from './helpers';

export const inboxRules: Playbook = {
  schemaVersion: 1,
  id: 'PB-INBOXRULE-001',
  version: '1.0.0',
  title: 'Suspicious mailbox forwarding or hiding rule',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1114.003', 'T1564.008'],
  tactics: ['collection', 'stealth'],
  objective: 'Decide whether a new mailbox rule or forwarding setting was created by the mailbox owner for a normal reason, or by an attacker to collect mail and hide their activity.',
  alertMeaning: 'A mailbox rule was created or changed that forwards mail outside the organization, deletes messages, or moves them to a rarely viewed folder - or mailbox-level forwarding was enabled.',
  whyItMatters: 'Forwarding and hiding rules are a standard step after a mailbox is taken over. They let an attacker read mail without signing in again and hide replies during payment fraud.',
  difficulty: 'Beginner',
  effort: '20-40 minutes',
  platforms: ['Office Suite', 'SaaS'],
  logSources: ['m365-audit', 'entra-signin', 'email-security'],
  alertContext: {
    triggers: ['New-InboxRule / Set-InboxRule / UpdateInboxRules with forward, redirect, delete, or move-to-folder actions.', 'Set-Mailbox enabling ForwardingSmtpAddress to an external address.', 'Rule with a blank or one-character name, or keywords such as invoice, payment, bank, password.'],
    reviewFirst: ['Mailbox, rule name, conditions, and actions.', 'Who created it, from which IP and client.', 'Destination address or folder.'],
    oftenMissing: ['The sign-in session that created the rule.', 'Which messages the rule has already acted on.'],
  },
  prerequisites: [
    { text: 'Microsoft 365 unified audit log (Exchange operations).', type: 'telemetry', required: true },
    { text: 'Sign-in logs for the mailbox owner.', type: 'telemetry', required: true },
    { text: 'Message trace to see forwarded mail.', type: 'telemetry', required: false },
  ],
  steps: [
    {
      id: 'rule-definition',
      title: 'Record the rule conditions and actions',
      action: 'From the audit event, record the rule name, conditions (sender, subject or body keywords), and actions (ForwardTo, RedirectTo, ForwardAsAttachmentTo, DeleteMessage, MoveToFolder, MarkAsRead). For mailbox forwarding record ForwardingSmtpAddress and DeliverToMailboxAndForward.',
      why: 'The actions show intent: external forwarding collects mail; delete or move-to-RSS hides it from the owner.',
      where: ['OfficeActivity (Parameters)', 'Exchange admin audit log'],
      fields: ['Operation', 'Parameters', 'UserId', 'ClientIP'],
      suspicious: ['Forward or redirect to an external or free-mail address', 'Move to "RSS Feeds", "Conversation History", or "Archive" combined with mark-as-read', 'Keywords such as invoice, payment, wire, password, security alert'],
      legitimate: ['Rule that files newsletters into a named folder', 'Forward to the user\'s documented shared mailbox or delegate'],
      next: 'Identify who created it and from where.',
      queryIds: ['kql-inbox-rules', 'spl-inbox-rules', 'esql-inbox-rules'],
    },
    {
      id: 'creator-session',
      title: 'Identify the session that created the rule',
      action: 'Match the audit event\'s ClientIP and time with sign-ins for the mailbox owner. Record the IP, location, device, and client application.',
      why: 'A rule created from an unfamiliar IP shortly after an unusual sign-in was almost certainly not made by the owner.',
      where: ['SigninLogs', 'OfficeActivity ClientIP'],
      fields: ['IPAddress', 'Location', 'DeviceDetail', 'UserAgent'],
      suspicious: ['IP never used by the owner before', 'Rule created minutes after a risky sign-in', 'Created through a legacy or scripted client'],
      legitimate: ['Created from the owner\'s usual managed device'],
      next: 'If the session is unfamiliar, also apply the valid-accounts playbook.',
      queryIds: ['kql-rule-creator-signins'],
    },
    {
      id: 'destination',
      title: 'Assess the forwarding destination or target folder',
      action: 'Check whether the destination address is internal, a known partner, or external/free-mail, and whether it appears in other mailboxes\' rules.',
      why: 'The same attacker address often appears across several compromised mailboxes.',
      where: ['OfficeActivity across all mailboxes', 'Directory lookup'],
      fields: ['ForwardTo / RedirectTo / ForwardingSmtpAddress'],
      suspicious: ['Free-mail or lookalike domain', 'Same destination in more than one mailbox'],
      legitimate: ['Internal address with a documented delegation'],
      next: 'Measure the impact.',
      queryIds: ['kql-inbox-rules'],
    },
    {
      id: 'impact',
      title: 'Measure what the rule has already done',
      action: 'Use message trace to count messages forwarded to the destination since the rule was created, and note senders and subjects. Check for sent mail the owner does not recognize.',
      why: 'This sizes the data exposure and reveals fraud in progress (for example replies to a payment thread).',
      where: ['Message trace / EmailEvents', 'Mailbox sent items (via approved process)'],
      fields: ['Recipient = destination address', 'Message count', 'Subjects'],
      suspicious: ['Finance or contract threads forwarded', 'Outbound mail changing bank details'],
      legitimate: ['No messages matched yet'],
      next: 'Confirm with the owner if procedure allows.',
      queryIds: [],
    },
    {
      id: 'owner-confirmation',
      title: 'Confirm with the mailbox owner',
      action: 'Through an approved channel, ask the owner whether they created the rule and recognize the destination.',
      why: 'Owners do create forwarding rules; confirmation avoids an unnecessary incident, while a denial confirms compromise.',
      where: ['Phone or chat via approved channel'],
      fields: ['Owner statement'],
      suspicious: ['Owner does not recognize the rule'],
      legitimate: ['Owner created it and the session evidence agrees'],
      next: 'Use the decision tree. Do not remove the rule yourself unless your procedure says so; it is evidence.',
      queryIds: [],
    },
  ],
  decisionTree: {
    start: 'owner-made',
    nodes: [
      { id: 'owner-made', question: 'Did the owner create the rule (confirmed) from their usual device and location, with an internal or approved destination?', yes: { outcome: 'benign', guidance: 'Document the confirmation. If external forwarding breaks policy, refer it to the policy owner.' }, no: { next: 'collecting', guidance: 'Unexplained rule.' } },
      { id: 'collecting', question: 'Does the rule forward mail externally, or delete/hide messages, and was it created from an unfamiliar session?', yes: { next: 'fraud', guidance: 'Mailbox compromise is likely.' }, no: { outcome: 'investigate', guidance: 'Ambiguous rule. Reach the owner; escalate if they cannot confirm it.' } },
      { id: 'fraud', question: 'Is there payment or bank-detail fraud in progress, an executive or finance mailbox involved, or the same destination in several mailboxes?', yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now; finance may need to stop a payment.' }, no: { outcome: 'escalate', guidance: 'Escalate with the rule definition, creating session, and messages affected.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true, 'Rule creation time (UTC).'),
    ev('username', true, 'Mailbox owner and the account that created the rule.'),
    evCustom('rule_definition', 'Rule name, conditions, and actions', 'Copy from the audit Parameters.', true, true),
    evCustom('destination_address', 'Forwarding destination or target folder', 'Defang external addresses in notes.', true),
    ev('src_ip', true, 'ClientIP of the creating session.'),
    evCustom('messages_affected', 'Messages forwarded or hidden', 'Count, date range, notable subjects.', false, true),
    evCustom('owner_statement', 'Owner statement', 'What the owner said and how you reached them.', false),
    ev('affected_assets', false, 'Other mailboxes with the same destination.'),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['External forwarding or hiding rule the owner did not create.', 'Rule created from an unfamiliar IP or after a risky sign-in.', 'Owner cannot be reached and the destination is external.'],
    immediate: ['Evidence of payment or bank-detail fraud.', 'Executive, finance, or administrator mailbox affected.', 'Same attacker destination found in multiple mailboxes.'],
    benignClosure: ['Owner confirmed the rule; creating session matches their baseline; destination is internal or approved.'],
  },
  queries: [
    {
      id: 'kql-inbox-rules',
      title: 'Mailbox rule and forwarding changes',
      language: 'kql',
      platform: 'Microsoft Sentinel (Microsoft 365 connector)',
      purpose: 'Lists rule and forwarding operations with their parameters, flagging external-forward and hide actions.',
      dataSources: ['OfficeActivity'],
      query: `OfficeActivity
| where TimeGenerated > ago({{lookback}})
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| extend Params = tostring(Parameters)
| where Operation != "Set-Mailbox" or Params has "Forwarding"
| extend Forwards = Params has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress"),
         Hides = Params has_any ("DeleteMessage", "MoveToFolder", "MarkAsRead")
| project TimeGenerated, UserId, ClientIP, Operation, Forwards, Hides, Params
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'Params', meaning: 'Rule name, conditions, and actions as recorded by Exchange.' }, { name: 'ClientIP', meaning: 'Address of the session that made the change.' }],
      positive: 'Each row is a rule change to attribute to its owner.',
      negative: 'Rules created before the lookback, or through clients that log different operations, are not shown.',
      prerequisites: 'Unified audit log enabled; Office 365 connector with Exchange.',
      schemaNotes: 'Operation names come from the Microsoft 365 audit log. Outlook desktop may log UpdateInboxRules with different parameter detail.',
      example: 'lookback = 7d',
    },
    {
      id: 'kql-rule-creator-signins',
      title: 'Sign-ins from the IP that created the rule',
      language: 'kql',
      platform: 'Microsoft Sentinel (Entra ID connector)',
      purpose: 'Shows every account that signed in from the creating IP, to confirm the session and find other affected users.',
      dataSources: ['SigninLogs'],
      query: `SigninLogs
| where TimeGenerated > ago({{lookback}})
| where IPAddress == "{{src_ip}}"
| summarize SignIns = count(), Successes = countif(ResultType == "0"),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Apps = make_set(AppDisplayName, 10)
            by UserPrincipalName, Location
| order by FirstSeen asc`,
      placeholders: [PH.lookback('14d'), PH.srcIp()],
      keyFields: [{ name: 'UserPrincipalName', meaning: 'More than one user from an unfamiliar IP widens the incident.' }],
      positive: 'Confirms which accounts used that IP.',
      negative: 'The audit ClientIP can be a Microsoft service address for some clients; no match does not clear the rule.',
      prerequisites: 'Entra ID sign-in logs in Sentinel.',
      schemaNotes: 'ClientIP in OfficeActivity may include a port; strip it before searching.',
      example: 'src_ip = 203.0.113.25',
    },
    {
      id: 'spl-inbox-rules',
      title: 'Mailbox rule changes (Microsoft 365 audit in Splunk)',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for Microsoft Office 365)',
      purpose: 'Lists inbox-rule operations with the acting user and IP.',
      dataSources: ['sourcetype o365:management:activity'],
      query: `index="{{index}}" sourcetype="o365:management:activity" earliest=-{{lookback}}
    Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| table _time UserId ClientIP Operation Parameters{}.Name Parameters{}.Value
| sort _time`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding Microsoft 365 audit events.', example: 'o365' }, PH.lookback('7d')],
      keyFields: [{ name: 'Parameters{}.Value', meaning: 'Rule conditions and actions.' }],
      positive: 'Rule changes to attribute.',
      negative: 'Audit ingestion can lag by hours.',
      prerequisites: 'Microsoft 365 management activity logs in Splunk.',
      schemaNotes: 'Parameter field extraction depends on the add-on version.',
      example: 'index = o365',
    },
    esql(
      'esql-inbox-rules',
      'Mailbox rule changes',
      'Lists inbox-rule operations from the Microsoft 365 audit log over the last 7 days.',
      ['logs-o365.audit-*'],
      `FROM logs-o365.audit-*
| WHERE @timestamp > NOW() - 7 days
| WHERE event.action IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| KEEP @timestamp, user.id, source.ip, event.action, o365.audit.Parameters
| SORT @timestamp ASC
| LIMIT 200`,
      [],
      'Each row is a rule change to attribute to its owner.',
      'Requires the Elastic Microsoft 365 integration; audit events can arrive late.',
    ),
    genericProcedure('generic-inbox-rule', 'Generic mailbox-rule procedure', `1. Record rule name, conditions, actions, and destination.
2. Match the creating IP and time to the owner's sign-ins.
3. Check the destination: internal, partner, or external; reused in other mailboxes?
4. Count messages forwarded or hidden since creation.
5. Confirm with the owner through an approved channel.`),
  ],
  detectionConsiderations: ['Attackers favor short or blank rule names and folders users rarely open.', 'Mailbox-level forwarding (Set-Mailbox) is separate from inbox rules and needs its own check.'],
  visibilityGaps: ['Rules created before audit retention are invisible.', 'On-premises Exchange needs separate admin audit logging.'],
  relatedTechniques: [
    { id: 'T1078.004', reason: 'The rule is created from a compromised cloud account.' },
    { id: 'T1566', reason: 'Credential phishing usually precedes the mailbox takeover.' },
    { id: 'T1534', reason: 'Compromised mailboxes are used for internal phishing.' },
    { id: 'T1114.002', reason: 'Remote email collection is the alternative to forwarding.' },
  ],
  references: [attackRef('T1114.003', 'Email Forwarding Rule'), attackRef('T1564.008', 'Email Hiding Rules')],
  assumptions: ['Rule removal and account remediation are done through the escalation path so evidence is preserved.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

import type { Playbook } from '../../lib/playbooks/schema';
import { PH, STARTER_DATE, attackRef, esql, ev, evCustom, genericProcedure, starterReview } from './helpers';

const ACTOR = { name: 'actor_arn', kind: 'string' as const, description: 'ARN of the IAM user or role that made the calls.', example: 'arn:aws:iam::111122223333:user/demo.user' };

export const cloudCredentials: Playbook = {
  schemaVersion: 1,
  id: 'PB-CLOUDKEY-001',
  version: '1.0.0',
  title: 'Suspicious cloud credential creation or public storage exposure (AWS)',
  status: 'Draft',
  source: 'starter-library',
  aiAssisted: true,
  techniques: ['T1098.001', 'T1078.004', 'T1530'],
  tactics: ['persistence', 'privilege-escalation', 'initial-access', 'collection'],
  objective: 'Determine whether new cloud credentials, permissions, or storage exposure were created by an authorized engineer or pipeline, or by someone using a compromised cloud identity.',
  alertMeaning: 'Cloud audit logs show a new access key or login profile, a policy granting broad permissions, or a storage bucket made public - by an unusual identity, from an unusual network, or outside the deployment pipeline.',
  whyItMatters: 'Extra access keys and policies let an attacker keep cloud access after the original credential is rotated. Public buckets expose data to anyone, immediately.',
  difficulty: 'Intermediate',
  effort: '30-60 minutes',
  platforms: ['IaaS', 'SaaS', 'Identity Provider'],
  logSources: ['cloud-audit', 'entra-signin'],
  alertContext: {
    triggers: ['CloudTrail CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, or CreateUser by an unusual principal.', 'AttachUserPolicy / AttachRolePolicy / PutUserPolicy granting administrator access.', 'PutBucketPolicy, PutBucketAcl, or DeletePublicAccessBlock making a bucket public.', 'ConsoleLogin without MFA or from a new country.'],
    reviewFirst: ['Acting identity (user, role, assumed-role session) and account.', 'API calls, target resources, source IP, and user agent.', 'Whether the calls succeeded (no errorCode).'],
    oftenMissing: ['How the acting identity\'s own credential was obtained.', 'Whether data events (object reads) are logged for the bucket.'],
  },
  prerequisites: [
    { text: 'CloudTrail management events for all accounts and regions in the SIEM.', type: 'telemetry', required: true },
    { text: 'CloudTrail data events for sensitive buckets.', type: 'telemetry', required: false },
    { text: 'Cloud platform or DevOps contact and the list of deployment roles.', type: 'information', required: true },
  ],
  steps: [
    {
      id: 'api-calls',
      title: 'List the sensitive API calls and their result',
      action: 'For the alert window, list identity- and storage-changing API calls by the acting identity: event name, target user/role/bucket, region, source IP, user agent, and error code.',
      why: 'The combination of calls shows intent: creating a key for another user plus attaching an admin policy is a persistence pattern.',
      where: ['AWSCloudTrail', 'CloudTrail console event history'],
      fields: ['EventName', 'UserIdentityArn', 'RequestParameters', 'SourceIpAddress', 'UserAgent', 'ErrorCode'],
      suspicious: ['Access key created for a different user than the caller', 'AdministratorAccess attached outside the pipeline', 'Many AccessDenied errors before a success (permission probing)'],
      legitimate: ['Calls made by the deployment role from the CI system\'s addresses'],
      next: 'Profile the acting identity.',
      queryIds: ['kql-cloudtrail-sensitive', 'spl-cloudtrail-sensitive', 'esql-cloudtrail-sensitive'],
    },
    {
      id: 'actor-profile',
      title: 'Profile the acting identity and source',
      action: 'Summarize the identity\'s activity for 30 days: usual source IPs, user agents, regions, and services. Compare the alerting calls with that baseline.',
      why: 'Stolen keys are typically used from new networks, with different tooling, in regions the team never uses.',
      where: ['AWSCloudTrail (30 days)'],
      fields: ['SourceIpAddress', 'UserAgent', 'AWSRegion', 'EventSource'],
      suspicious: ['First-seen IP, user agent, or region', 'Long-lived access key suddenly used interactively', 'Discovery calls (List*, Get*, Describe*) across many services just before'],
      legitimate: ['Same IPs, tooling, and regions as the identity\'s normal work'],
      next: 'Confirm with the owner.',
      queryIds: ['kql-cloud-actor-baseline'],
    },
    {
      id: 'owner-confirmation',
      title: 'Confirm with the identity owner or platform team',
      action: 'Ask the platform or DevOps contact whether the change was planned (ticket, pull request, pipeline run) and whether the engineer was working at that time from that location.',
      why: 'Cloud changes are frequent and legitimate; the owner can confirm quickly.',
      where: ['Change records', 'Pipeline run history', 'Team chat via approved channel'],
      fields: ['Ticket or pipeline run', 'Confirmation source'],
      suspicious: ['Nobody recognizes the change', 'The key belongs to a departed employee or an unused service'],
      legitimate: ['Matching change record'],
      next: 'Check what the new access has done.',
      queryIds: [],
    },
    {
      id: 'new-credential-use',
      title: 'Check use of the new credential or exposure',
      action: 'Search for activity by the newly created access key or user, and for access to the exposed bucket from outside addresses, since the change.',
      why: 'Use of the new key or reads from the public bucket show the impact has started.',
      where: ['AWSCloudTrail (UserIdentityAccessKeyId)', 'S3 data events / server access logs'],
      fields: ['UserIdentityAccessKeyId', 'EventName', 'SourceIpAddress', 'Bucket and object'],
      suspicious: ['New key used from a different network than its creator', 'GetObject or ListBucket from unknown addresses'],
      legitimate: ['No use yet, or use only by the documented service'],
      next: 'Scope the account.',
      queryIds: [],
    },
    {
      id: 'scope-account',
      title: 'Scope other changes in the account',
      action: 'Look for other persistence or impact by the same identity or source IP: new users or roles, trust-policy changes, disabled logging (StopLogging, DeleteTrail), new compute instances, or snapshot sharing.',
      why: 'Attackers in a cloud account usually make several changes; disabling the trail is a critical sign.',
      where: ['AWSCloudTrail'],
      fields: ['EventName', 'RequestParameters'],
      suspicious: ['StopLogging or DeleteTrail', 'Instances launched in unused regions', 'Role trust policy opened to an external account'],
      legitimate: ['Only the documented change set'],
      next: 'Use the decision tree.',
      queryIds: ['kql-cloudtrail-sensitive'],
    },
  ],
  decisionTree: {
    start: 'planned',
    nodes: [
      { id: 'planned', question: 'Is the change confirmed as planned (ticket, pull request, or pipeline run) and made by the expected identity from its usual network?', yes: { outcome: 'benign', guidance: 'Record the change reference and confirming person. If a public bucket is intentional, note the data owner\'s approval.' }, no: { next: 'succeeded', guidance: 'Unplanned change.' } },
      { id: 'succeeded', question: 'Did the calls succeed (credential created, policy attached, or bucket exposed)?', yes: { next: 'impact', guidance: 'New access or exposure exists now.' }, no: { outcome: 'escalate', guidance: 'Failed attempts still mean the acting credential may be compromised. Escalate for key review.' } },
      { id: 'impact', question: 'Was administrator-level access granted, a bucket with sensitive data exposed, logging disabled, or the new credential already used?', yes: { outcome: 'critical', guidance: 'Follow the incident escalation procedure now; the cloud team may need to revoke keys and block public access immediately.' }, no: { outcome: 'escalate', guidance: 'Escalate with the API calls, acting identity, and resources.' } },
    ],
  },
  evidence: [
    ev('alert_id', true),
    ev('detection_name', true),
    ev('event_time', true),
    ev('username', true, 'Acting identity ARN and cloud account ID.'),
    ev('src_ip', true, 'Source IP and user agent of the calls.'),
    evCustom('api_calls', 'API calls and results', 'Event name - target - result (one per line).', true, true),
    evCustom('resources', 'Resources created or changed', 'Access key ID (not the secret), user/role, policy, bucket.', true, true),
    evCustom('change_record', 'Change record checked', 'Ticket, pull request, or pipeline run - or "none found".', true),
    evCustom('new_access_use', 'Use of the new credential or exposure', 'Calls by the new key, or external reads of the bucket.', false, true),
    ev('related_alerts', false),
  ],
  escalation: {
    tier2: ['Credential, policy, or bucket exposure change with no change record.', 'Acting identity used from a new network, tool, or region.', 'Failed privilege attempts suggesting a compromised key.'],
    immediate: ['Administrator-level access granted to an unexpected principal.', 'Bucket with sensitive data made public or read from unknown addresses.', 'Cloud audit logging stopped or deleted.', 'Newly created credential already in use.'],
    benignClosure: ['Change matches a ticket, pull request, or pipeline run and the expected identity and network.'],
  },
  queries: [
    {
      id: 'kql-cloudtrail-sensitive',
      title: 'Sensitive identity and storage changes in AWS',
      language: 'kql',
      platform: 'Microsoft Sentinel (AWS connector)',
      purpose: 'Lists credential, policy, bucket-exposure, and logging changes with actor, source, and result.',
      dataSources: ['AWSCloudTrail'],
      query: `AWSCloudTrail
| where TimeGenerated > ago({{lookback}})
| where EventName in ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateUser",
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "UpdateAssumeRolePolicy",
        "PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock", "PutPublicAccessBlock",
        "StopLogging", "DeleteTrail")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, UserAgent,
          AWSRegion, ErrorCode, RequestParameters
| order by TimeGenerated asc`,
      placeholders: [PH.lookback('7d')],
      keyFields: [{ name: 'ErrorCode', meaning: 'Empty means the call succeeded.' }, { name: 'RequestParameters', meaning: 'Target user, policy ARN, or bucket.' }],
      positive: 'Each row is a sensitive change to match with a change record.',
      negative: 'Accounts or regions without a trail are not covered; an empty result may be a logging gap.',
      prerequisites: 'CloudTrail management events ingested for all accounts and regions.',
      schemaNotes: 'Column names follow the Sentinel AWSCloudTrail table. Extend the event list for your services.',
      example: 'lookback = 7d',
    },
    {
      id: 'kql-cloud-actor-baseline',
      title: '30-day baseline for a cloud identity',
      language: 'kql',
      platform: 'Microsoft Sentinel (AWS connector)',
      purpose: 'Summarizes where and how an identity normally makes API calls.',
      dataSources: ['AWSCloudTrail'],
      query: `AWSCloudTrail
| where TimeGenerated > ago({{lookback}})
| where UserIdentityArn == "{{actor_arn}}"
| summarize Calls = count(), Errors = countif(isnotempty(ErrorCode)),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Services = make_set(EventSource, 20)
            by SourceIpAddress, UserAgent, AWSRegion
| order by FirstSeen asc`,
      placeholders: [PH.lookback('30d'), ACTOR],
      keyFields: [{ name: 'FirstSeen', meaning: 'Rows first seen near the alert are new behavior.' }],
      positive: 'New IPs, tools, or regions are anomalies to explain.',
      negative: 'Assumed-role sessions have per-session ARNs; search the role ARN prefix as well.',
      prerequisites: 'CloudTrail in Sentinel with 30 days retention.',
      schemaNotes: 'Use has or startswith instead of == for assumed-role session ARNs.',
      example: 'actor_arn = arn:aws:iam::111122223333:user/demo.user',
    },
    {
      id: 'spl-cloudtrail-sensitive',
      title: 'Sensitive identity and storage changes in AWS',
      language: 'spl',
      platform: 'Splunk Enterprise (Splunk Add-on for AWS)',
      purpose: 'Lists credential, policy, bucket-exposure, and logging changes.',
      dataSources: ['sourcetype aws:cloudtrail'],
      query: `index="{{index}}" sourcetype="aws:cloudtrail" earliest=-{{lookback}}
    eventName IN ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateUser",
      "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutBucketPolicy", "PutBucketAcl",
      "DeletePublicAccessBlock", "StopLogging", "DeleteTrail")
| table _time eventName userIdentity.arn sourceIPAddress userAgent awsRegion errorCode
| sort _time`,
      placeholders: [{ name: 'index', kind: 'string', description: 'Index holding CloudTrail events.', example: 'aws' }, PH.lookback('7d')],
      keyFields: [{ name: 'errorCode', meaning: 'Absent when the call succeeded.' }],
      positive: 'Sensitive changes to verify.',
      negative: 'Only accounts and regions sending CloudTrail to Splunk are covered.',
      prerequisites: 'CloudTrail ingested with the Splunk Add-on for AWS.',
      schemaNotes: 'Field names follow CloudTrail JSON.',
      example: 'index = aws',
    },
    esql(
      'esql-cloudtrail-sensitive',
      'Sensitive identity and storage changes in AWS',
      'Lists credential, policy, bucket-exposure, and logging changes over the last 7 days.',
      ['logs-aws.cloudtrail-*'],
      `FROM logs-aws.cloudtrail-*
| WHERE @timestamp > NOW() - 7 days
| WHERE event.action IN ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateUser",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutBucketPolicy", "PutBucketAcl",
    "DeletePublicAccessBlock", "StopLogging", "DeleteTrail")
| KEEP @timestamp, event.action, event.outcome, aws.cloudtrail.user_identity.arn, source.ip, user_agent.original, cloud.region
| SORT @timestamp ASC
| LIMIT 500`,
      [],
      'Each row is a sensitive change to match with a change record.',
      'Accounts or regions without a trail are not covered.',
    ),
    genericProcedure('generic-cloud-key', 'Generic cloud credential and exposure procedure', `1. List identity, policy, storage-exposure, and logging API calls by the acting identity, with results.
2. Baseline the identity for 30 days: source IPs, tools, regions, services.
3. Confirm with the owner or platform team; look for a ticket, pull request, or pipeline run.
4. Search for use of any new key or user, and for external access to exposed storage.
5. Scope: other changes by the same identity or source (roles, trust policies, logging, compute).
Azure and Google Cloud have equivalent audit events (Azure Activity / Entra audit, Cloud Audit Logs).`),
  ],
  detectionConsiderations: ['Baseline deployment roles and CI addresses; most legitimate changes come from them.', 'Record access key IDs, never secret keys.'],
  visibilityGaps: ['Object-level reads need data events, which are often off.', 'Accounts outside the organization trail are invisible.'],
  relatedTechniques: [
    { id: 'T1098.003', reason: 'Additional roles or policies are attached for privilege.' },
    { id: 'T1136.003', reason: 'New cloud users are created for persistence.' },
    { id: 'T1580', reason: 'Cloud infrastructure discovery usually precedes the changes.' },
    { id: 'T1537', reason: 'Data can be copied to an attacker-controlled cloud account.' },
    { id: 'T1552.001', reason: 'Access keys are often stolen from files and repositories.' },
  ],
  references: [attackRef('T1098.001', 'Additional Cloud Credentials'), attackRef('T1530', 'Data from Cloud Storage'), { title: 'AWS CloudTrail User Guide', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html' }],
  assumptions: ['Key revocation and bucket lockdown are performed by the cloud platform team through escalation.', 'This playbook uses AWS event names; adapt for Azure and Google Cloud.'],
  review: starterReview(),
  updatedAt: STARTER_DATE,
};

import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
export const SOURCES = [
 ["nist","NIST SP 800-61 Rev. 3","https://csrc.nist.gov/pubs/sp/800/61/r3/final","Shared response governance and risk management."],
 ["cisa","CISA incident response playbooks","https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf","Phase checklists and coordination. Federal notification deadlines are not adopted."],
 ["cacao","OASIS CACAO 2.0","https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html","Explicit transitions and failure paths. This graph is not a CACAO implementation."],
 ["ransom","CISA StopRansomware Guide","https://www.cisa.gov/stopransomware/ransomware-guide","Ransomware coordination, isolation, evidence and protected recovery."],
 ["ms-ir","Microsoft response playbooks","https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks","Investigation prerequisites and scenario-specific response."],
 ["phish","Microsoft phishing investigation","https://learn.microsoft.com/en-us/security/zero-trust/security-operations-playbook-phishing","Email evidence, recipient scope, interaction and follow-on investigation."],
 ["spray","Microsoft password spray investigation","https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray","Separate attempted authentication from successful access."],
 ["consent","Microsoft app consent investigation","https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent","Investigate permissions and consent; restrict malicious application access."],
 ["revoke","Microsoft revoke user access","https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access","Revocation depends on token and application session behavior."],
 ["mailbox","Microsoft compromised email account response","https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account","Mailbox rules, forwarding and account access."],
 ["4662","Microsoft Windows event 4662","https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662","Audit prerequisites, object access properties and subject logon identifier."],
 ["sysmon","Microsoft Sysmon","https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon","Process creation and access evidence with contextual analysis."],
 ["sync","Microsoft synchronization permissions","https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/user-prov-sync/pwd-hash-sync-stops-work","Approved synchronization services can legitimately hold replication rights."],
 ["krbtgt","Microsoft forest recovery: reset krbtgt","https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password","Two-reset recovery depends on configured ticket lifetime and directory recovery conditions."],
 ["cisco","Cisco mailbox auto remediation","https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_13-0/b_ESA_Admin_Guide_ces_13-0/b_ESA_Admin_Guide_ces_12_0_chapter_010100.html","AsyncOS 13.0 capability reference: mailbox remediation differs from gateway quarantine. Verify deployed version and integration."],
 ["forti","FortiMail product capabilities","https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/FortiMail.pdf","Post-delivery clawback capability; verify deployment, integration and permissions."],
 ["forti-quarantine","FortiMail quarantine administration","https://docs.fortinet.com/document/fortimail/latest/administration-guide/907026/managing-the-quarantines","Gateway quarantine does not establish recipient mailbox deletion."],
 ["aws-framework","AWS customer playbook framework","https://github.com/aws-samples/aws-customer-playbook-framework","Cloud scenario structure. Documentation CC BY-SA 4.0; code separately licensed. Linked, not imported."],
 ["aws-iam","AWS compromised credentials playbook","https://github.com/aws-samples/aws-customer-playbook-framework/blob/main/docs/Compromised_IAM_Credentials.md","Cloud identity scope and response reference. No text or code imported."],
 ["aws-revoke","AWS revoke role sessions","https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html","Session cutoff and identity-type limitations."],
 ["aws-key","AWS access key management","https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys-admin-managed.html","Deactivate compromised long-term keys; investigate temporary sessions separately."],
 ["s3","AWS S3 CloudTrail events","https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html","Object data events are not collected by default or in CloudTrail Event history."],
 ["azure-storage","Azure Blob Storage monitoring","https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage","Storage resource logging and collection configuration."],
 ["gcp-response","Google Cloud threat investigation","https://docs.cloud.google.com/security-command-center/docs/how-to-investigate-threats","Finding-specific investigations and resource context."],
 ["gcp-token","Google Cloud token mitigation","https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens","Address service account keys and previously issued tokens separately."],
 ["gcp-storage","Google Cloud Storage audit logs","https://docs.cloud.google.com/storage/docs/audit-logging","Data Access audit records and required permissions."],
 ["gcp-usage","Google Cloud Storage usage logs","https://docs.cloud.google.com/storage/docs/access-logs","Public access and byte visibility may require usage logs."],
 ["sigma","Sigma detection library","https://github.com/SigmaHQ/sigma","Detection metadata and lifecycle reference. No rules imported; review rule licensing before reuse."],
 ["elastic","Elastic detection rules","https://github.com/elastic/detection-rules","Investigations and exception reference. Elastic License 2.0 rules not imported."],
 ["splunk","Splunk analytic stories","https://research.splunk.com/stories/","Related detection context; queries remain platform specific."],
 ["attack-detections","MITRE detection strategies","https://attack.mitre.org/detectionstrategies/","Behavioral detection reference; mapping is not proof of local coverage."],
 ["cert-irm","CERT Societe Generale IR methodologies","https://github.com/certsocietegenerale/IRM","Historical checklist comparison; not authority for current product commands."]
].map(([id,title,url,applicability])=>({id,title,url,applicability,type:"authoritative",accessed_at:"2026-09-08"}));
const S=(title,action,fields,decision)=>({title,action,fields_or_artifacts:fields.split("|"),decision,
 owner:"Assigned analyst; the case owner remains accountable",
 evidence_required:"Retain the query, UTC interval, source record identifiers, result and analyst interpretation.",
 on_failure:"Record missing evidence or failed action; keep the case open and assign a next check and escalation owner."});
const A=(title,action,verification,rollback)=>({title,action,
 preconditions:"Identify the affected entity, preserve available evidence and confirm control access and service dependencies.",
 approval:"Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.",
 evidence_preservation:"Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.",
 business_impact:"Record affected users and dependencies; apply the smallest effective restriction.",verification,rollback,
 contraindications:"Do not apply broad isolation, disablement or data deletion from an alert score alone.",
 on_failure:"Record actual control state and use an approved alternative while reassessing scope."});
const Q=(name,query,fields,tests)=>({name,query,required_fields:fields.split("|"),platform:"Vendor-neutral normalized correlation",language:"pseudocode",adaptation_required:true,
 prerequisites:"Map fields and identity scope to the deployed schema. Confirm collection, time, retention, parsing and deduplication.",
 validation_status:"planned",test_cases:tests,limitations:"Investigation candidate; syntax and effectiveness require local SIEM validation."});
export const PROFILES = {};

PROFILES["T1003"]={
 sources:["4662","sysmon","sync","krbtgt"],
 urgency:"Active credential theft or privileged access at risk?",
 authorized:"Exact replication or diagnostic activity authorized?",
 confirmed:"Unauthorized credential access corroborated?",
 recovered:"Credential exposure and access paths addressed?",
 summaries:{triage:"Separate LSASS, local stores and directory replication evidence.",analysis:"Correlate actor, source, target, rights and subsequent use.",containment:"Restrict the confirmed path and plan credential rotation.",eradication:"Remove persistence and resolve credential exposure.",recovery:"Verify directory services and restored host trust."},
 triage:[
 S("Identify the credential access path","Distinguish LSASS access, SAM/SECURITY material, NTDS backup access and directory replication. Preserve the original event before assuming extraction succeeded.","host|process GUID|principal SID|target|access mask|UTC","Route replication to identity response and process access to endpoint response."),
 S("Validate telemetry and authorization","Check Sysmon process-access configuration or Directory Service Access auditing and the relevant SACL for 4662. Match diagnostics, backup or synchronization to the exact owner, source, identity, target and time.","collection policy|SACL|change record","Missing events indicate a gap. A process name or non-DC source alone does not prove maliciousness."),
 S("Assess urgent exposure","Identify privileged identities and services reachable by the actor. Escalate credible ongoing theft while a second analyst builds the timeline.","asset role|privilege|recent sessions","Use proportionate containment under incident authority.")
 ],
 investigation:[
 S("Reconstruct LSASS access","Correlate process creation, parent, path, signer/hash, user, access rights and subsequent file/network activity. Evaluate allowed security software by full identity and behavior, not basename exclusions.","process GUID|parent GUID|SourceImage|TargetImage|GrantedAccess|hash","An access event does not prove extraction of usable credentials."),
 S("Attribute directory replication","Inspect 4662 replication properties and SubjectLogonId on the receiving DC; correlate with that DC's 4624 and network/endpoint evidence. Compare principal-source-target with approved DC and synchronization inventory.","DC|SubjectLogonId|SubjectUserSid|Properties|source address","4662 does not provide a complete inventory of stolen secrets."),
 S("Find use and persistence","Hunt affected identities and source hosts for new sessions, directory permission changes and persistence before and after the signal. Separate confirmed from plausible exposure.","identity|host|session|directory changes","Uncertain secret scope needs an explicit identity recovery decision.")
 ],
 scoping:[S("Bound exposure","Record earliest observed activity, retained-log boundary, affected stores, privileged sessions and downstream services. Search behavior as well as tool hashes.","timeline|credential store|dependencies","Record unknown scope instead of declaring patient zero proven.")],
 containment:[
 A("Restrict the access path","Contain a confirmed compromised endpoint or restrict the implicated replication principal/source with the identity owner. Check DC, synchronization and service dependencies.","Verify the path is denied and legitimate directory operations remain available.","Remove temporary restrictions only after owner approval; do not restore compromised credentials."),
 A("Plan credential recovery","Rotate exposed credentials in dependency order. Refer credible krbtgt/domain compromise to directory recovery; one anomalous replication event is not sufficient for a forest-wide reset.","Verify replication health and reset completion. If two krbtgt resets are required, use Microsoft's configured-ticket-lifetime guidance and the recovery lead's plan.","Maintain tested service recovery and emergency access; never roll back to exposed secrets.")
 ],
 eradication:[S("Remove the access mechanism","Remove persistence and unauthorized directory permissions. Preserve dump artifacts securely before approved deletion. Rebuild hosts whose integrity cannot be established.","forensic reference|ACL baseline|host baseline","New credential use or persistence reopens scope.")],
 recovery:[S("Verify trust and dependencies","Confirm approved credentials work, exposed access is denied, replication is healthy and restored endpoints report telemetry. Set a monitoring interval based on exposure.","authentication tests|replication health|EDR health","Require identity and service-owner acceptance before lifting restrictions.")],
 closure:["Exposure and uncertainty are documented and accepted by the identity lead.","Credential recovery and legitimate service operation have independent verification."],
 queries:[
 Q("LSASS access candidate with contextual exceptions","FROM process_access\nWHERE target_image_basename = 'lsass.exe' AND access_includes_process_memory_read\nENRICH source_process_guid WITH process_creation, signer, hash, full_path, actor, parent\nCOMPARE WITH approved_process_identity_and_behavior\nEMIT candidate WITH raw_access_mask, exception_evidence, related_file_and_network_activity","source_process_guid|target_image_basename|raw_access_mask|timestamp",["Unapproved LSASS reads yield a candidate.","A renamed binary is not excluded by basename.","Approved EDR activity retains auditable exception evidence."]),
 Q("Directory replication requiring attribution","FROM windows_security\nWHERE event_id = 4662 AND access_includes_control_access\n AND properties HAS_ANY (replication_get_changes, replication_get_changes_all, replication_get_changes_filtered_set)\nCORRELATE receiving_dc, subject_logon_id WITH same_dc_logon_events\nENRICH principal_sid, source_host, directory_target WITH approved_replication_inventory\nEMIT unexpected_or_unresolved_combinations FOR review","event_id|receiving_dc|subject_logon_id|principal_sid|properties|timestamp",["Approved synchronization matches its exact inventory entry.","Absent source attribution stays unresolved.","Missing 4662 collection is a visibility gap."])
 ]
};
PROFILES["T1078"]={
 sources:["spray","revoke","consent","mailbox","aws-iam","aws-revoke","aws-key","gcp-token"],
 urgency:"Privileged or harmful account use continuing?",
 authorized:"Access matches a verified user or workload task?",
 confirmed:"Unauthorized access or session use corroborated?",
 recovered:"Compromised access blocked and legitimate use verified?",
 summaries:{triage:"Identify human, service, federated or workload identity.",analysis:"Separate attempts, issued sessions and resource actions.",containment:"Restrict new access and existing sessions by platform.",eradication:"Remove malicious grants, credentials and identity persistence.",recovery:"Test trusted access and monitor resources."},
 triage:[
 S("Identify the authentication path","Record tenant/account/project, immutable principal ID, identity type and authentication source. Separate password attempts, MFA-blocked attempts, successful sign-ins and resource actions.","principal ID|identity type|auth result|session ID|tenant","Correct password followed by blocked MFA is not equivalent to resource access."),
 S("Validate the anomaly","Check travel, VPN/proxy, automation and approved activity through a trusted owner channel. Treat geolocation and additive risk scores as leads.","source IP|device|auth method|owner confirmation","Close only on positive benign evidence.")
 ],
 investigation:[
 S("Join authentication to actions","Build an identity and resource timeline. Include sessions, device context, MFA changes, credentials, roles, app consent and mailbox rules where applicable.","session|resource audit|grants|MFA methods","Resource actions establish demonstrated scope."),
 S("Scope derived access","For AWS follow access key IDs and role issuers; for Entra distinguish user sessions and app grants; for GCP distinguish keys, impersonation and issued tokens.","key ID|session issuer|app ID|service account","Changing the original credential does not prove derived access stopped.")
 ],
 scoping:[S("Map identity dependencies","Find other principals, accounts/projects/subscriptions, mailboxes and workloads reached. Identify dependencies before disabling shared identities.","principal relationships|owners|trust policy","Escalate cross-boundary access and privileged persistence.")],
 containment:[
 A("Block new compromised access","Restrict the identity or credential using the provider's control. Coordinate a clean replacement and continuity for workload identities.","Verify compromised requests are denied using control state and subsequent resource logs.","Restore services with fresh credentials; do not reactivate exposed keys."),
 A("Address existing and alternate access","Apply provider session controls and inspect grants, MFA, trust and new credentials. AWS role revocation has cutoff and identity-type limits; Entra app sessions may require separate action; GCP key deletion alone does not invalidate issued tokens.","Check post-action resource use and document remaining token/session exposure.","Restore legitimate sessions after repairing the access path.")
 ],
 eradication:[S("Remove identity persistence","Preserve then remove unauthorized methods, keys, grants, forwarding/delegation and role changes. Repair the initial theft path.","before/after config|case artifacts","New principals or applications reopen scope.")],
 recovery:[S("Prove trusted access","Validate required access from a trusted device/workload. Confirm logging, monitoring end time and recurrence triggers.","controlled sign-in|resource access|monitoring plan","Reopen on unexplained access or malicious grants.")],
 closure:["New and existing access paths are evaluated separately.","Identity owner accepts remaining session exposure and scope; workloads pass recovery tests."],
 queries:[
 Q("Unexplained successful access","FROM authentication\nWHERE final_result = 'success'\nENRICH tenant, principal_id WITH identity_inventory, known_devices, approved_tasks\nCORRELATE session_id AND principal_id WITH resource_actions\nEMIT unexplained_access WITH authentication_factors, device_context, resource_scope\nDO NOT classify compromise from IP novelty or travel speed alone","tenant|principal_id|final_result|session_id|timestamp",["MFA-blocked attempts are not successful access.","VPN egress provides context, not blanket exclusion.","Anomalous access with role changes is prioritized."]),
 Q("Interactive use of inventoried service identities","FROM windows_security\nWHERE event_id = 4624 AND logon_type IN (2,10,11)\n AND (principal_sid IN service_identity_inventory)\nCOMPARE host, principal_sid, logon_type, timestamp WITH approved_interactive_exceptions\nEMIT unexplained_matches","event_id|logon_type|principal_sid|host|timestamp",["Name prefix alone does not establish identity type.","OR precedence cannot include non-4624 events.","Maintenance exceptions are time and host bounded."])
 ]
};

PROFILES["PB-PHISH-001"]={
 sources:["phish","cisco","forti","forti-quarantine","revoke","consent","mailbox"],
 urgency:"Malicious execution or account misuse underway?",
 authorized:"Message and activity independently verified benign?",
 confirmed:"Malicious message or follow-on compromise supported?",
 recovered:"Delivered copies and follow-on exposure resolved?",
 summaries:{triage:"Track actual delivery for each recipient.",analysis:"Separate delivery, click, credentials, consent and execution.",containment:"Remove delivered copies and contain observed compromise.",eradication:"Remove payloads, mailbox persistence and malicious grants.",recovery:"Verify removal and endpoint and identity controls."},
 triage:[
 S("Resolve recipient delivery state","Preserve message and headers in approved storage. Correlate Cisco appliance plus MID or FortiMail appliance plus session ID with time, sender and recipient. IDs can change across systems or be reused. Record delivery for each recipient.","appliance|MID/session ID|message ID|recipient|UTC|delivery outcome","A retrospective verdict does not prove delivery; gateway quarantine does not prove mailbox removal."),
 S("Classify interaction","Separate no known interaction, click, download, credential entry, OAuth consent and observed execution. Correlate user reports with endpoint, proxy and identity evidence.","recipient|URL|hash|device|sign-in|consent","Click alone does not justify host isolation; active host compromise may."),
 S("Set incident priority","Assess privilege, payment requests, execution and continuing account abuse. Assign endpoint, identity or fraud responders to the observed path.","privilege|business request|execution evidence","Urgent harm reduction proceeds alongside recipient scoping.")
 ],
 investigation:[
 S("Reconstruct delivery and verdict history","Use gateway tracking and mail trace to distinguish rejected, quarantined, delivered and remediated outcomes; retain original and retrospective verdict times.","message trace|gateway tracking|verdict timeline","Failed or pending remediation leaves delivery exposure unresolved."),
 S("Investigate the payload path","Inspect files and expanded URLs in approved systems. Correlate process lineage, downloads and network activity. Do not upload sensitive email or token-bearing URLs to public services without authorization.","hash|process tree|URL|proxy records","Malicious content is distinct from execution."),
 S("Investigate identity and business impact","For credential entry or consent inspect sign-ins, resource access, permissions, mailbox rules and forwarding. Route payment changes through the established fraud verification process.","app ID|grants|sign-in|mailbox audit|payment record","Resetting passwords does not remove malicious consent or all application sessions.")
 ],
 scoping:[S("Enumerate the campaign","Search message IDs and hashes, then sender/reply-to, URL patterns and behavior. Reconcile delivered copies, interactions and follow-on status per recipient, including forwarding where visible.","recipient ledger|campaign indicators|mailbox outcomes","Record gaps and unresolved recipients explicitly.")],
 containment:[
 A("Remove delivered malicious messages","Use the mailbox platform or configured Cisco/FortiMail post-delivery integration. Verify deployed version, permissions, search scope and preview results. Manage gateway quarantine separately.","Record per-recipient success/failure/unavailable status; independently recheck affected mailboxes.","Retain evidence and a supported false-positive restoration route; permanent deletion may not be reversible."),
 A("Contain observed compromise","For execution use endpoint containment; for credential theft restrict identity access and sessions; for malicious consent disable application access and remediate grants. Check shared infrastructure before indicator blocks.","Verify isolation or resource-access denial independently; check alternate access.","Restore trusted services with owner approval; retire broad temporary blocks.")
 ],
 eradication:[S("Remove follow-on persistence","Preserve then remove confirmed endpoint persistence, malicious mailbox rules/delegation and grants. Inspect gateway allowlists and transport rules for attacker changes.","EDR|mailbox audit|app configuration|gateway config","Unexpected persistence returns to investigation.")],
 recovery:[S("Reconcile all recipients","Verify delivered copies removed or exposure explicitly accepted. Validate affected accounts/devices and set monitoring ownership, interval and recurrence triggers.","recipient ledger|control checks|owner acceptance","Unresolved actions need a named owner and decision.")],
 closure:["Delivery, interaction and compromise are recorded independently per recipient.","Mailbox, endpoint and identity action outcomes have verification evidence."],
 queries:[
 Q("Cisco retrospective verdict and delivery reconciliation","FROM email_events\nWHERE vendor = 'Cisco' AND retrospective_verdict = 'malicious'\nJOIN tracking ON appliance_id, message_tracking_id, recipient WITH bounded_event_time\nRETURN initial_verdict_time, revised_verdict_time, delivery_outcome, remediation_outcome\nLEFT CORRELATE recipient, attachment_hash WITH endpoint_execution\nEMIT candidate even when delivery is unknown","vendor|appliance_id|message_tracking_id|recipient|timestamp|retrospective_verdict",["Quarantine does not become delivered.","Reused IDs cannot join across appliances.","Delivery and removal remain separate outcomes."]),
 Q("FortiMail verdict or quarantined malware","FROM email_events\nWHERE vendor = 'FortiMail'\n AND ((event_type = 'sandbox' AND normalized_verdict = 'malicious')\n   OR (event_type = 'history' AND classifier = 'virus' AND action = 'quarantine'))\nJOIN tracking ON appliance_id, session_id, recipient WITH bounded_event_time\nRETURN delivery_outcome, verdict_time, remediation_outcome\nNOTE: map local verdict values; do not infer quarantine from severity","vendor|event_type|normalized_verdict|classifier|action|appliance_id|session_id|recipient",["Another vendor cannot pass the OR branch.","High severity with delivered outcome remains delivered.","Unmapped verdicts create a parsing gap."]),
 Q("Campaign and recipient interaction","FROM delivered_messages\nLEFT JOIN interactions ON recipient_identity AND normalized_url_or_attachment WITH configurable_time_window\nLEFT JOIN endpoint_and_identity_activity ON recipient_identity, device_or_session WITH configurable_time_window\nRETURN per_recipient(delivery, click, download, credential_report, consent, execution, access)\nNOTE: absent telemetry means unknown interaction","recipient_identity|message_id|delivery_time|artifact|interaction_type|timestamp",["Click is not execution.","Later interaction prompts a wider window.","Shared proxy IP alone cannot identify a recipient."])
 ]
};
PROFILES["PB-RANSOM-001"]={
 sources:["ransom","krbtgt","nist"],
 urgency:"Encryption, destruction or spread active?",
 authorized:"Activity matches verified maintenance?",
 confirmed:"Malicious encryption or extortion supported?",
 recovered:"Trusted restore and monitoring checks passed?",
 summaries:{triage:"Establish active harm, critical services and incident command.",analysis:"Investigate initial access, spread, identity and data theft.",containment:"Coordinate isolation and protect recovery assets.",eradication:"Remove attacker access before reconnecting.",recovery:"Restore by dependency and prove business and security health."},
 triage:[
 S("Coordinate active harm","Record encryption/destruction, affected services and safety impact. Establish incident command and trusted communications. Begin coordinated isolation under emergency authority.","commander|services|EDR evidence|ransom note","Do not wait for family attribution or complete forensics to reduce active harm."),
 S("Protect recovery capability","Identify backup management, storage and privileged identities at risk. Have backup/infrastructure owners protect clean recovery assets and control-plane evidence.","backup dependencies|admin identities|management logs","Do not disable the recovery path without an alternative.")
 ],
 investigation:[
 S("Build the compromise timeline","Investigate entry, privilege, movement, persistence and encryption across endpoint, identity and network data. Assess data theft separately from encryption.","process tree|sessions|remote access|data movement","Record earliest observed activity and retention boundaries."),
 S("Assess administration and backup trust","Determine whether directory, cloud, hypervisor, backup or security administration was affected. Test backups in isolation and inspect admin changes.","control-plane audit|backup versions|test restore","A completed backup job does not prove clean recovery.")
 ],
 scoping:[S("Map affected services","Maintain hosts, identities, segments, storage, third parties, data and critical dependencies with state and owner. Mark unobserved assets.","asset ledger|dependency map|data inventory","Expand command across business/provider boundaries.")],
 containment:[
 A("Coordinate isolation","Isolate affected hosts/segments and restrict confirmed attacker access. For DCs, hypervisors, backup servers and safety-critical services use a responder/service-owner plan preserving essential dependencies.","Check encryption/spread and isolation state; use alternate controls if EDR is unavailable.","Reconnect only after integrity and access checks under incident command."),
 A("Restrict compromised administration","Protect recovery infrastructure and restrict compromised privileged identities. Refer suspected domain-key compromise to identity recovery and current krbtgt guidance, not a fixed-hour reset schedule.","Verify blocked paths, replication health, emergency access and backup administration.","Recover administration from clean systems and fresh credentials in dependency order.")
 ],
 eradication:[S("Remove attacker access before restore","Close initial access, remove persistence, repair administration and rotate exposed secrets. Rebuild where integrity cannot be shown; preserve evidence before disposal.","root cause|clean build|persistence checks","New malicious activity returns to scope and containment.")],
 recovery:[
 S("Restore with acceptance gates","Restore in isolation by service dependency. Validate backup integrity, data correctness, identity, endpoint controls, logging and a business transaction before production reconnection.","restore evidence|business test|security test","Stop rollout on failed checks."),
 S("Monitor and decide residual risk","Assign queries, owners, end time and recurrence triggers. Legal/privacy and management evaluate theft/extortion and communications under applicable requirements.","monitoring plan|exposure assessment|decision log","No new encryption does not establish absence of stolen data.")
 ],
 closure:["Business restoration and security acceptance are signed off separately.","Theft assessment, unknown scope and communication decisions have accountable owners."],
 queries:[Q("Correlated destructive behavior","FROM endpoint_and_storage_events\nGROUP BY stable_host_id, process_entity_id OVER configurable_short_window\nFIND rapid_unexplained_file_rewrites OR mass_rename_or_delete\nCORRELATE WITH ransom_note_artifacts, recovery_inhibition, suspicious_process_lineage\nCOMPARE WITH approved_backup_encryption_and_maintenance\nEMIT candidate WITH impacted_files, event_count, confidence_evidence\nDO NOT auto-isolate from an arbitrary additive score","stable_host_id|process_entity_id|timestamp|file_action|file_path",["Approved encryption needs exact authorization.","Mass modification plus ransom notes is urgent.","Sensor loss is a gap, not proof of containment."])]
};

PROFILES["PB-SCAN-001"]={
 sources:["nist","attack-detections"],
 urgency:"Scanning with exploitation or disruption?",
 authorized:"Actor, targets and time match an approved scan?",
 confirmed:"Unauthorized activity established?",
 recovered:"Scan path resolved and compromise assessed?",
 summaries:{triage:"Identify direction, actual source and affected zone.",analysis:"Check authority, fan-out, target responses and follow-on activity.",containment:"Use narrow controls; assess source compromise.",eradication:"Resolve demonstrated compromise or scanner scope.",recovery:"Verify services and monitor recurrence."},
 triage:[
 S("Establish network context","Identify direction, NAT/VPN translation, source ownership, destination zone and sensor location. Separate attempts from successful sessions.","source|destination|port|action|zone|NAT|UTC","Internal source IP is not proof of compromise."),
 S("Check authorization","Match source asset/identity, targets, tool, time and change record with the scanning owner.","scanner inventory|change record|target scope","Allowlisted scanners outside approved scope remain reviewable.")
 ],
 investigation:[
 S("Measure behavior","Count distinct destinations and ports over explicit windows per source and zone. Compare role-specific baselines; use longer windows for slow activity and link distributed sources only with evidence.","source identity|destination|port|time|bytes|connection state","Avoid universal thresholds or merging IPs across tenants/zones."),
 S("Look for consequences","Inspect target service/authentication logs and IDS evidence for exploit attempts, successful access or impact. Correlate internal source processes and sessions.","IDS|service log|auth outcome|process tree","Unauthorized scanning can be a policy event without host compromise.")
 ],
 scoping:[S("Map targets and access","Record targeted services, exposed vulnerable systems and successful sessions. Distinguish scanned from compromised assets.","target ledger|service role|session outcome","Hand demonstrated exploitation to the matching incident owner.")],
 containment:[
 A("Restrict the scan path","Use a bounded block/rate limit where justified. Check NAT/shared egress and management dependencies; denied external scans may warrant monitoring or exposure reduction.","Verify traffic reduction and legitimate service tests.","Expire/review temporary rules; retain original configuration."),
 A("Contain demonstrated source compromise","Isolate a host only when compromise or active harm supports it. Otherwise work with the source owner to stop unauthorized scanning.","Verify originating activity stops and inspect alternate paths.","Restore approved scanning after correcting scope and schedule.")
 ],
 eradication:[S("Resolve the actual cause","For demonstrated compromise use the related host response. Otherwise correct scan scope, policy violations or exposed services without inventing an infection.","host evidence|scanner config|service config","Keep scan and compromise dispositions distinct.")],
 recovery:[S("Verify service and recurrence","Test legitimate access, record rule ownership/expiry and compare behavior with the agreed baseline.","service tests|rule expiry|monitoring query","Exploitation evidence requires resolution or accepted handoff.")],
 closure:["Approved scan, unauthorized scan, external reconnaissance and compromise are separate dispositions.","Exploitation and service impact have an accepted owner or resolution."],
 queries:[Q("Source and zone scan aggregation","FROM network_connections\nGROUP BY tenant, source_zone, resolved_source_identity, bin(timestamp, configured_window)\nCALCULATE distinct_destination_count, distinct_destination_port_pairs, accepted_count, denied_count\nCOMPARE WITH calibrated_baseline_for_source_role\nJOIN approved_scan_scope ON source_identity, targets, time_window\nEMIT unexplained_fanout WITH action_breakdown\nRUN separate longer-window aggregation for low-rate scans","tenant|source_zone|resolved_source_identity|destination_ip|destination_port|timestamp|action",["Same IP in two zones is not merged.","Denied probes are not successful sessions.","Approved scanner outside target scope is reviewed."])]
};
PROFILES["T1530"]={
 sources:["s3","azure-storage","gcp-storage","gcp-usage","gcp-response","aws-iam","aws-revoke","aws-key","gcp-token"],
 urgency:"Sensitive reads or bulk transfer continuing?",
 authorized:"Principal, data and transfer match an approved job?",
 confirmed:"Unauthorized access or exposure established?",
 recovered:"Access repaired and disclosure assessed?",
 summaries:{triage:"Identify provider, store, principal and log coverage.",analysis:"Separate listing, reads, public exposure and transfer.",containment:"Restrict access paths and derived credentials.",eradication:"Repair unauthorized grants and exposed secrets.",recovery:"Validate approved data access and logging."},
 triage:[
 S("Identify resource and credential","Record AWS account/bucket, Azure subscription/storage account/container or GCP project/bucket, object scope and principal. Distinguish users, roles, workloads, shared keys, signed URLs/SAS and anonymous access.","provider|resource ID|object|principal|credential type|UTC","Signed/shared credentials may not identify the human actor."),
 S("Check read visibility","Verify object-read collection and time coverage. AWS S3 object data events are not present by default in CloudTrail Event history. Check Azure storage diagnostic logs and GCP Data Access settings and permissions.","logging config|retention|ingestion delay|sample read","Missing reads are a visibility gap, not proof of no disclosure.")
 ],
 investigation:[
 S("Reconstruct object access","Join successful/failed object operations with identity sessions and permission changes. Separate listing from reads, and request counts from measured bytes.","operation|status|object|principal|request ID|bytes","A List operation or object count is not verified exfiltration volume."),
 S("Evaluate exposure and alternatives","Compare principal, data, schedule, network and transfer with approved backup/ETL jobs. Inspect public/cross-account access, temporary sessions and credential issuance. Assess GCP usage logs for public/byte visibility as well as audit logs.","job record|policy|session issuer|classification","Legitimate cross-account jobs are not automatically exfiltration."),
 S("Assess affected data","Build an object/version manifest and sensitivity assessment. Separate confirmed reads, reachable data, unavailable logs and defensible transfer estimates.","manifest|versions|classification|coverage interval","Escalate plausible disclosure without unsupported byte totals.")
 ],
 scoping:[S("Search related resources","Pivot across accounts/subscriptions/projects and stores reached by the principal or credential. Include grants, new keys, links and logging changes.","organization scope|credential ID|policy changes","Record boundary blind spots and accepted handoffs.")],
 containment:[
 A("Restrict the resource path","With the service/data owner restrict the unauthorized principal, public grant, link or credential using the provider mechanism. Preserve policy/logs and check production job dependencies.","Use safe access tests and resource logs to verify denial and required job health.","Restore reviewed permissions; replace exposed credentials."),
 A("Address derived access","Investigate temporary sessions after AWS key restriction, GCP tokens after key deletion, and the applicable Azure credential/SAS revocation mechanism. Record residual validity and compensating resource restrictions.","Check post-action data access and control state, not only API mutation success.","Recover with a tested replacement identity and clean secret distribution.")
 ],
 eradication:[S("Repair permissions and secret exposure","Remove unauthorized grants/credentials, fix leaks or compromised workloads and protect evidence. Do not delete data to stop a read-only exposure.","policy baseline|secret distribution|workload integrity","Continuing reads return to containment.")],
 recovery:[S("Verify data service","Run approved read/write tests, verify least privilege and logging, reconcile disclosure, and set monitoring ownership and recurrence triggers.","controlled transactions|audit records|data owner decision","Unresolved disclosure scope requires explicit acceptance.")],
 closure:["Observed reads, potential exposure and missing evidence are separately documented.","Controls pass safe tests; the data owner accepts remaining disclosure uncertainty."],
 queries:[
 Q("Unexplained object access across providers","FROM normalized_object_access\nWHERE operation_class = 'object_read' AND outcome = 'success'\nGROUP BY provider, tenant_or_project, resource_id, principal_or_credential_id OVER configured_window\nCALCULATE object_count, request_count, bytes_if_measured\nCOMPARE WITH approved_job_and_role_baselines\nCORRELATE permission_changes, new_credentials, source_network\nEMIT evidence_manifest WITH coverage_and_attribution_limitations","provider|tenant_or_project|resource_id|principal_or_credential_id|operation_class|outcome|timestamp",["Listing is not counted as reads.","Cross-account backup needs a scoped job record.","Missing bytes stay unknown, not replaced with object sizes."]),
 Q("Public or cross-boundary exposure","FROM storage_permission_changes AND object_access\nFIND newly_public_grant OR newly_external_principal OR unexplained_signed_access\nENRICH resource WITH data_classification, owner, approved_sharing\nRETURN reachable_scope, observed_successful_reads, missing_logging_intervals\nCLASSIFY exposure separately FROM observed_unauthorized_reads","resource_id|permission_change|principal|timestamp|owner|access_outcome",["Public grant alone is exposure, not proven theft.","Missing logs preserve unknown disclosure.","Approved sharing matches resource and principal."])
 ]
};

const N=(id,kind,row,title,items=[],column="spine")=>({id,kind,row,column,title,items});
const E=(from,to,label="",kind="main")=>({from,to,label,kind});
export function makeWorkflow(p,profile) {
 const r=p.response, summaries=profile?.summaries||{};
 const count=k=>Array.isArray(r[k])?r[k].length:Object.values(r[k]||{}).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0);
 const phase=(id,row,title,key,summary)=>N(id,"phase",row,title,[
 summary||summaries[id]||"Use the technique-specific evidence and actions in the full procedures.",
 "Full procedures: "+key.replaceAll("_"," ")+" ("+count(key)+" steps)."]);
 const nodes=[
 N("start","start",0,"Alert: "+p.id,[p.name]),
 phase("triage",1,"Triage and assign owner","triage"),
 N("escalation","escalation",1,"Escalation and handoff",["Select by trigger; owner remains accountable until acceptance.",...r.escalation.map(e=>typeof e==="string"?e:e.destination),"Full criteria and urgency: escalation matrix."],"branch"),
 N("urgency","decision",2,profile?.urgency||"Ongoing activity risks material harm?"),
 N("urgent-action","branch",2,"Immediate harm reduction",["Use approved containment. Preserve feasible evidence and verify the action while investigation continues."],"branch"),
 phase("analysis",3,"Investigate and scope","investigation",(summaries.analysis||"Correlate evidence, authority, actor and affected resources.")+" Full scoping: "+count("scoping")+" steps."),
 N("authorized","decision",4,profile?.authorized||"Evidence establishes authorized benign activity?"),
 N("close-benign","end",4,"Close as benign",["Record positive benign evidence, reviewer and bounded tuning. Missing evidence cannot use this exit."],"branch"),
 N("confirmed","decision",5,profile?.confirmed||"Unauthorized or malicious activity supported?"),
 N("evidence-gap","branch",5,"Unresolved evidence",["Keep suspicious status. Name next source, owner and review time; escalate failed collection."],"branch"),
 phase("containment",6,"Contain and verify","containment"),
 N("contained","decision",7,"Containment effective and scope accounted for?"),
 N("revise-containment","branch",7,"Revise containment",["Check failure, impact and alternate paths. Coordinate an approved alternative and verify it."],"branch"),
 phase("eradication",8,"Resolve cause and persistence","eradication"),
 N("remediated","decision",9,"Removal and integrity checks pass?"),
 N("specialist","branch",9,"Resolve failed checks",["Assign a DFIR/service specialist. Reassess scope and rebuild or repair where justified."],"branch"),
 phase("recovery",10,"Restore and validate","recovery"),
 N("closure-ready","decision",11,profile?.recovered||"Recovery and closure evidence complete?"),
 N("follow-up","branch",11,"Keep incident open",["Resolve failed checks or missing evidence. Re-scope recurrence and obtain owner acceptance."],"branch"),
 phase("post-incident",12,"Learning and acceptance","post_incident"),
 N("closure","end",13,"Close incident",["All "+count("closure_criteria")+" closure criteria evidenced or explicitly not applicable with reviewer approval. Record monitoring and residual-risk decisions."])
 ];
 return {version:1,scope:(profile?"Scenario-specific decision flow.":"Shared response flow; technique-specific procedures still require validation.")+" Follow labeled arrows; alternate actions rejoin the response. Phase cards summarize full procedures containing evidence, authority, rollback and the escalation matrix.",
 nodes,edges:[
 E("start","triage"),E("triage","urgency"),E("triage","escalation","when","branch"),E("escalation","urgency","","return"),
 E("urgency","analysis","no"),E("urgency","urgent-action","yes","branch"),E("urgent-action","analysis","","return"),
 E("analysis","authorized"),E("authorized","confirmed","no"),E("authorized","close-benign","yes","branch"),
 E("confirmed","containment","yes"),E("confirmed","evidence-gap","no","branch"),E("evidence-gap","analysis","","return"),
 E("containment","contained"),E("contained","eradication","yes"),E("contained","revise-containment","no","branch"),E("revise-containment","containment","","return"),
 E("eradication","remediated"),E("remediated","recovery","yes"),E("remediated","specialist","no","branch"),E("specialist","analysis","","return"),
 E("recovery","closure-ready"),E("closure-ready","post-incident","yes"),E("closure-ready","follow-up","no","branch"),E("follow-up","analysis","","return"),
 E("post-incident","closure")
 ]};
}
export function improveResponses(data) {
 for(const p of data.playbooks){
 const profile=PROFILES[p.id],r=p.response;
 // Repair machine-generated labels without discarding action text.
 for(const value of Object.values(r)) if(Array.isArray(value)) for(const s of value) if(s&&typeof s==="object"&&s.action&&s.title) s.title=s.action;
 if(profile){
 for(const key of ["triage","investigation","scoping","eradication","recovery"]) r[key]=profile[key].map((s,i)=>({...s,id:key+"-"+(i+1)}));
 r.containment={immediate:profile.containment.map((a,i)=>({...a,id:"contain-"+(i+1)})),
 short_term:[A("Re-scope after action","Reconcile affected entities, actual control outcomes and new evidence after each action.","Independently confirm outcome from available telemetry.","Adjust restrictions only through the incident owner.")],
 long_term:[A("Replace temporary controls","Resolve the root weakness and assign durable changes with owners and validation dates.","Verify with an approved simulation and expected benign activity.","Retain the previous reviewed configuration for controlled rollback.")]};
 r.post_incident=[
 S("Review gaps and decisions","Review delays, incorrect assumptions and missing data. Assign control, parser, query and playbook changes with owners and due dates.","timeline|decisions|backlog","Test malicious, benign and missing-telemetry cases before declaring effectiveness."),
 S("Complete owner acceptance","Record restoration, residual risk and monitoring handoff. Legal/privacy and authorized management decide external communications under applicable requirements.","acceptance|monitoring handoff|notification decision","Unaccepted handoffs stay with the case owner.")];
 r.closure_criteria=[...profile.closure,"Evidence, query intervals, coverage, decisions and action outcomes are retained.","Recovery tests and monitoring are complete, or residual risk has explicit accountable acceptance.","Notification decisions and improvements have owners."].map((criterion,i)=>({id:"closure-"+(i+1),criterion,evidence_required:"Linked case evidence and named reviewer acceptance.",required:true}));
 p.queries=profile.queries.map((q,i)=>({...q,id:p.id.toLowerCase()+"-q"+(i+1)}));
 p.content_sections=p.content_sections.filter(s=>!/(detection.logic|incident.response|automation.opportunities)/i.test(s.id+" "+s.title));
 p.detection={...p.detection,strategies:profile.queries.map((q,i)=>({id:"strategy-"+(i+1),name:q.name,logic:q.query})),
 triage_fields:[...new Set([...profile.triage,...profile.investigation].flatMap(s=>s.fields_or_artifacts))],
 false_positives:[{cause:"Approved activity matching actor, target, time and purpose.",distinguishing_evidence:"Use the exact authorization evidence described in the scenario. Names, source location and verdicts alone are insufficient."}]};
 }
 if(profile){
 p.detection.pseudocode=profile.queries.map(q=>q.name+"\n"+q.query).join("\n\n");
 p.detection.hypothesis="Unauthorized activity is supported by the scenario-specific evidence, scope and outcomes after checking exact approved explanations. Missing telemetry remains unknown."; 
 p.detection.strategy={...p.detection.strategy,primary_logic:profile.queries.map(q=>q.query),supporting_signals:profile.investigation.map(s=>s.action),window:"Calibrate per source latency, scenario and retained history; document the chosen interval.",aggregation:"Use each query\u0027s explicit entity keys and window; preserve raw evidence and deduplication context."};
 p.detection.tuning={...p.detection.tuning,guidance:["Validate scoped exceptions using approved benign examples and attacker-like variants. No measured false-positive rate is asserted."]};
 p.detection.severity={default:p.severity,confidence:"medium",fidelity:"unvalidated",telemetry_confidence:"requires local validation",escalation_conditions:[profile.urgency],rationale:"Authored priority guidance; actual severity depends on evidence and business impact."};
 p.validation.negative_tests=profile.queries.flatMap(q=>q.test_cases);
 p.validation.expected_detection=["A reviewable candidate with the query\u0027s explicit entity keys, source coverage, matched conditions, raw evidence and observed outcome; alert grouping must be tested locally."];
}
const sourceIds=["nist","cisa","cacao",...(profile?.sources||[])];
 const refs=SOURCES.filter(s=>sourceIds.includes(s.id));
 p.references=[...(p.references||[]).filter(ref=>!SOURCES.some(s=>s.url===ref.url)),...refs];
 r.source_review={reviewed_at:"2026-09-08",scope:profile?"Representative scenario rewritten; shared flow reviewed":"Shared flow reviewed; inherited technique procedures not independently rewritten",
 validation:"Content/design review only. Local telemetry, queries, permissions, thresholds and recovery actions require validation.",source_ids:[...new Set(sourceIds)]};
 r.operating_contract={
 case_record:"Record case ID, UTC bounds, source freshness, raw evidence links, immutable entity IDs, owner, severity rationale and next review time.",
 dispositions:["Benign with positive evidence","Suspicious or unresolved","Unauthorized policy activity without demonstrated compromise","Confirmed compromise"],
 action_record:"Record target, reason, authority, impact, preservation, rollback/non-reversibility, outcome and independent verification.",
 timeboxes:"Owner sets evidence and response deadlines by severity and impact. Missed deadlines escalate; they never silently close a case.",
 handoff:"Originating owner remains accountable until receiver accepts scope, evidence, outstanding actions and next check.",
 query_readiness:"Untested queries and pseudocode are candidates. Calibrate with deployed schemas, positive/negative examples and missing-telemetry cases.",
 recurrence:"Unexplained recurrence returns to scope. Failed containment needs an alternative and verification.",
 precedence:"Inherited steps must satisfy this contract's evidence, authority, dependency and verification requirements before execution."};
 r.workflow=makeWorkflow(p,profile);
 r.decision_tree=r.workflow.nodes.filter(n=>n.kind==="decision").map(n=>({id:n.id,condition:n.title,
 if_true:r.workflow.edges.find(e=>e.from===n.id&&e.label==="yes").to,
 if_false:r.workflow.edges.find(e=>e.from===n.id&&e.label==="no").to}));
 }
 return data;
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
 const root=new URL("../",import.meta.url);
 const data=improveResponses(JSON.parse(await readFile(new URL("data/playbooks.json",root),"utf8")));
 await writeFile(new URL("data/playbooks.json",root),JSON.stringify(data)+"\n");
 await writeFile(new URL("data/response-sources.json",root),JSON.stringify({reviewed_at:"2026-09-08",method:"Targeted primary-source review; not an exhaustive internet survey.",sources:SOURCES},null,2)+"\n");
 console.log("Updated "+data.playbooks.length+" shared workflows and "+Object.keys(PROFILES).length+" scenarios; "+SOURCES.length+" references.");
}

# PB-PHISH-001 — Phishing Alert Triage (Cisco ESA & FortiMail)

Representative scenario rewritten; shared flow reviewed. Content/design review only. Local telemetry, queries, permissions, thresholds and recovery actions require validation.

## triage

### 1. Resolve recipient delivery state

**action:** Preserve message and headers in approved storage. Correlate Cisco appliance plus MID or FortiMail appliance plus session ID with time, sender and recipient. IDs can change across systems or be reused. Record delivery for each recipient.

**fields or artifacts:** appliance; MID/session ID; message ID; recipient; UTC; delivery outcome

**decision:** A retrospective verdict does not prove delivery; gateway quarantine does not prove mailbox removal.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Classify interaction

**action:** Separate no known interaction, click, download, credential entry, OAuth consent and observed execution. Correlate user reports with endpoint, proxy and identity evidence.

**fields or artifacts:** recipient; URL; hash; device; sign-in; consent

**decision:** Click alone does not justify host isolation; active host compromise may.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 3. Set incident priority

**action:** Assess privilege, payment requests, execution and continuing account abuse. Assign endpoint, identity or fraud responders to the observed path.

**fields or artifacts:** privilege; business request; execution evidence

**decision:** Urgent harm reduction proceeds alongside recipient scoping.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## investigation

### 1. Reconstruct delivery and verdict history

**action:** Use gateway tracking and mail trace to distinguish rejected, quarantined, delivered and remediated outcomes; retain original and retrospective verdict times.

**fields or artifacts:** message trace; gateway tracking; verdict timeline

**decision:** Failed or pending remediation leaves delivery exposure unresolved.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Investigate the payload path

**action:** Inspect files and expanded URLs in approved systems. Correlate process lineage, downloads and network activity. Do not upload sensitive email or token-bearing URLs to public services without authorization.

**fields or artifacts:** hash; process tree; URL; proxy records

**decision:** Malicious content is distinct from execution.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 3. Investigate identity and business impact

**action:** For credential entry or consent inspect sign-ins, resource access, permissions, mailbox rules and forwarding. Route payment changes through the established fraud verification process.

**fields or artifacts:** app ID; grants; sign-in; mailbox audit; payment record

**decision:** Resetting passwords does not remove malicious consent or all application sessions.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## scoping

### 1. Enumerate the campaign

**action:** Search message IDs and hashes, then sender/reply-to, URL patterns and behavior. Reconcile delivered copies, interactions and follow-on status per recipient, including forwarding where visible.

**fields or artifacts:** recipient ledger; campaign indicators; mailbox outcomes

**decision:** Record gaps and unresolved recipients explicitly.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## containment

### 1. Remove delivered malicious messages

**action:** Use the mailbox platform or configured Cisco/FortiMail post-delivery integration. Verify deployed version, permissions, search scope and preview results. Manage gateway quarantine separately.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Record per-recipient success/failure/unavailable status; independently recheck affected mailboxes.

**rollback:** Retain evidence and a supported false-positive restoration route; permanent deletion may not be reversible.

**contraindications:** Do not apply broad isolation, disablement or data deletion from an alert score alone.

**on failure:** Record actual control state and use an approved alternative while reassessing scope.

### 2. Contain observed compromise

**action:** For execution use endpoint containment; for credential theft restrict identity access and sessions; for malicious consent disable application access and remediate grants. Check shared infrastructure before indicator blocks.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Verify isolation or resource-access denial independently; check alternate access.

**rollback:** Restore trusted services with owner approval; retire broad temporary blocks.

**contraindications:** Do not apply broad isolation, disablement or data deletion from an alert score alone.

**on failure:** Record actual control state and use an approved alternative while reassessing scope.

### 3. Re-scope after action

**action:** Reconcile affected entities, actual control outcomes and new evidence after each action.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Independently confirm outcome from available telemetry.

**rollback:** Adjust restrictions only through the incident owner.

**contraindications:** Do not apply broad isolation, disablement or data deletion from an alert score alone.

**on failure:** Record actual control state and use an approved alternative while reassessing scope.

### 4. Replace temporary controls

**action:** Resolve the root weakness and assign durable changes with owners and validation dates.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Verify with an approved simulation and expected benign activity.

**rollback:** Retain the previous reviewed configuration for controlled rollback.

**contraindications:** Do not apply broad isolation, disablement or data deletion from an alert score alone.

**on failure:** Record actual control state and use an approved alternative while reassessing scope.

## eradication

### 1. Remove follow-on persistence

**action:** Preserve then remove confirmed endpoint persistence, malicious mailbox rules/delegation and grants. Inspect gateway allowlists and transport rules for attacker changes.

**fields or artifacts:** EDR; mailbox audit; app configuration; gateway config

**decision:** Unexpected persistence returns to investigation.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## recovery

### 1. Reconcile all recipients

**action:** Verify delivered copies removed or exposure explicitly accepted. Validate affected accounts/devices and set monitoring ownership, interval and recurrence triggers.

**fields or artifacts:** recipient ledger; control checks; owner acceptance

**decision:** Unresolved actions need a named owner and decision.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## post incident

### 1. Review gaps and decisions

**action:** Review delays, incorrect assumptions and missing data. Assign control, parser, query and playbook changes with owners and due dates.

**fields or artifacts:** timeline; decisions; backlog

**decision:** Test malicious, benign and missing-telemetry cases before declaring effectiveness.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Complete owner acceptance

**action:** Record restoration, residual risk and monitoring handoff. Legal/privacy and authorized management decide external communications under applicable requirements.

**fields or artifacts:** acceptance; monitoring handoff; notification decision

**decision:** Unaccepted handoffs stay with the case owner.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## closure criteria

### 1. Delivery, interaction and compromise are recorded independently per recipient.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

### 2. Mailbox, endpoint and identity action outcomes have verification evidence.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

### 3. Evidence, query intervals, coverage, decisions and action outcomes are retained.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

### 4. Recovery tests and monitoring are complete, or residual risk has explicit accountable acceptance.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

### 5. Notification decisions and improvements have owners.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

## Query candidates

### Cisco retrospective verdict and delivery reconciliation

Investigation candidate; syntax and effectiveness require local SIEM validation.

Map fields and identity scope to the deployed schema. Confirm collection, time, retention, parsing and deduplication.

Required normalized fields: vendor, appliance_id, message_tracking_id, recipient, timestamp, retrospective_verdict

~~~text
FROM email_events
WHERE vendor = 'Cisco' AND retrospective_verdict = 'malicious'
JOIN tracking ON appliance_id, message_tracking_id, recipient WITH bounded_event_time
RETURN initial_verdict_time, revised_verdict_time, delivery_outcome, remediation_outcome
LEFT CORRELATE recipient, attachment_hash WITH endpoint_execution
EMIT candidate even when delivery is unknown
~~~

Test specifications:

- Quarantine does not become delivered.
- Reused IDs cannot join across appliances.
- Delivery and removal remain separate outcomes.

### FortiMail verdict or quarantined malware

Investigation candidate; syntax and effectiveness require local SIEM validation.

Map fields and identity scope to the deployed schema. Confirm collection, time, retention, parsing and deduplication.

Required normalized fields: vendor, event_type, normalized_verdict, classifier, action, appliance_id, session_id, recipient

~~~text
FROM email_events
WHERE vendor = 'FortiMail'
 AND ((event_type = 'sandbox' AND normalized_verdict = 'malicious')
   OR (event_type = 'history' AND classifier = 'virus' AND action = 'quarantine'))
JOIN tracking ON appliance_id, session_id, recipient WITH bounded_event_time
RETURN delivery_outcome, verdict_time, remediation_outcome
NOTE: map local verdict values; do not infer quarantine from severity
~~~

Test specifications:

- Another vendor cannot pass the OR branch.
- High severity with delivered outcome remains delivered.
- Unmapped verdicts create a parsing gap.

### Campaign and recipient interaction

Investigation candidate; syntax and effectiveness require local SIEM validation.

Map fields and identity scope to the deployed schema. Confirm collection, time, retention, parsing and deduplication.

Required normalized fields: recipient_identity, message_id, delivery_time, artifact, interaction_type, timestamp

~~~text
FROM delivered_messages
LEFT JOIN interactions ON recipient_identity AND normalized_url_or_attachment WITH configurable_time_window
LEFT JOIN endpoint_and_identity_activity ON recipient_identity, device_or_session WITH configurable_time_window
RETURN per_recipient(delivery, click, download, credential_report, consent, execution, access)
NOTE: absent telemetry means unknown interaction
~~~

Test specifications:

- Click is not execution.
- Later interaction prompts a wider window.
- Shared proxy IP alone cannot identify a recipient.

## Sources

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — Shared response governance and risk management.
- [CISA incident response playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf) — Phase checklists and coordination. Federal notification deadlines are not adopted.
- [OASIS CACAO 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html) — Explicit transitions and failure paths. This graph is not a CACAO implementation.
- [Microsoft phishing investigation](https://learn.microsoft.com/en-us/security/zero-trust/security-operations-playbook-phishing) — Email evidence, recipient scope, interaction and follow-on investigation.
- [Microsoft app consent investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent) — Investigate permissions and consent; restrict malicious application access.
- [Microsoft revoke user access](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access) — Revocation depends on token and application session behavior.
- [Microsoft compromised email account response](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account) — Mailbox rules, forwarding and account access.
- [Cisco mailbox auto remediation](https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_13-0/b_ESA_Admin_Guide_ces_13-0/b_ESA_Admin_Guide_ces_12_0_chapter_010100.html) — AsyncOS 13.0 capability reference: mailbox remediation differs from gateway quarantine. Verify deployed version and integration.
- [FortiMail product capabilities](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/FortiMail.pdf) — Post-delivery clawback capability; verify deployment, integration and permissions.
- [FortiMail quarantine administration](https://docs.fortinet.com/document/fortimail/latest/administration-guide/907026/managing-the-quarantines) — Gateway quarantine does not establish recipient mailbox deletion.

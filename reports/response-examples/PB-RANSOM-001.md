# PB-RANSOM-001 — Ransomware Operations (Full Kill-Chain)

Representative scenario rewritten; shared flow reviewed. Content/design review only. Local telemetry, queries, permissions, thresholds and recovery actions require validation.

## triage

### 1. Coordinate active harm

**action:** Record encryption/destruction, affected services and safety impact. Establish incident command and trusted communications. Begin coordinated isolation under emergency authority.

**fields or artifacts:** commander; services; EDR evidence; ransom note

**decision:** Do not wait for family attribution or complete forensics to reduce active harm.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Protect recovery capability

**action:** Identify backup management, storage and privileged identities at risk. Have backup/infrastructure owners protect clean recovery assets and control-plane evidence.

**fields or artifacts:** backup dependencies; admin identities; management logs

**decision:** Do not disable the recovery path without an alternative.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## investigation

### 1. Build the compromise timeline

**action:** Investigate entry, privilege, movement, persistence and encryption across endpoint, identity and network data. Assess data theft separately from encryption.

**fields or artifacts:** process tree; sessions; remote access; data movement

**decision:** Record earliest observed activity and retention boundaries.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Assess administration and backup trust

**action:** Determine whether directory, cloud, hypervisor, backup or security administration was affected. Test backups in isolation and inspect admin changes.

**fields or artifacts:** control-plane audit; backup versions; test restore

**decision:** A completed backup job does not prove clean recovery.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## scoping

### 1. Map affected services

**action:** Maintain hosts, identities, segments, storage, third parties, data and critical dependencies with state and owner. Mark unobserved assets.

**fields or artifacts:** asset ledger; dependency map; data inventory

**decision:** Expand command across business/provider boundaries.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## containment

### 1. Coordinate isolation

**action:** Isolate affected hosts/segments and restrict confirmed attacker access. For DCs, hypervisors, backup servers and safety-critical services use a responder/service-owner plan preserving essential dependencies.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Check encryption/spread and isolation state; use alternate controls if EDR is unavailable.

**rollback:** Reconnect only after integrity and access checks under incident command.

**contraindications:** Do not apply broad isolation, disablement or data deletion from an alert score alone.

**on failure:** Record actual control state and use an approved alternative while reassessing scope.

### 2. Restrict compromised administration

**action:** Protect recovery infrastructure and restrict compromised privileged identities. Refer suspected domain-key compromise to identity recovery and current krbtgt guidance, not a fixed-hour reset schedule.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Verify blocked paths, replication health, emergency access and backup administration.

**rollback:** Recover administration from clean systems and fresh credentials in dependency order.

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

### 1. Remove attacker access before restore

**action:** Close initial access, remove persistence, repair administration and rotate exposed secrets. Rebuild where integrity cannot be shown; preserve evidence before disposal.

**fields or artifacts:** root cause; clean build; persistence checks

**decision:** New malicious activity returns to scope and containment.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## recovery

### 1. Restore with acceptance gates

**action:** Restore in isolation by service dependency. Validate backup integrity, data correctness, identity, endpoint controls, logging and a business transaction before production reconnection.

**fields or artifacts:** restore evidence; business test; security test

**decision:** Stop rollout on failed checks.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Monitor and decide residual risk

**action:** Assign queries, owners, end time and recurrence triggers. Legal/privacy and management evaluate theft/extortion and communications under applicable requirements.

**fields or artifacts:** monitoring plan; exposure assessment; decision log

**decision:** No new encryption does not establish absence of stolen data.

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

### 1. Business restoration and security acceptance are signed off separately.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

### 2. Theft assessment, unknown scope and communication decisions have accountable owners.

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

### Correlated destructive behavior

Investigation candidate; syntax and effectiveness require local SIEM validation.

Map fields and identity scope to the deployed schema. Confirm collection, time, retention, parsing and deduplication.

Required normalized fields: stable_host_id, process_entity_id, timestamp, file_action, file_path

~~~text
FROM endpoint_and_storage_events
GROUP BY stable_host_id, process_entity_id OVER configurable_short_window
FIND rapid_unexplained_file_rewrites OR mass_rename_or_delete
CORRELATE WITH ransom_note_artifacts, recovery_inhibition, suspicious_process_lineage
COMPARE WITH approved_backup_encryption_and_maintenance
EMIT candidate WITH impacted_files, event_count, confidence_evidence
DO NOT auto-isolate from an arbitrary additive score
~~~

Test specifications:

- Approved encryption needs exact authorization.
- Mass modification plus ransom notes is urgent.
- Sensor loss is a gap, not proof of containment.

## Sources

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — Shared response governance and risk management.
- [CISA incident response playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf) — Phase checklists and coordination. Federal notification deadlines are not adopted.
- [OASIS CACAO 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html) — Explicit transitions and failure paths. This graph is not a CACAO implementation.
- [CISA StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) — Ransomware coordination, isolation, evidence and protected recovery.
- [Microsoft forest recovery: reset krbtgt](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password) — Two-reset recovery depends on configured ticket lifetime and directory recovery conditions.

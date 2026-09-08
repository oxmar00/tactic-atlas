# PB-SCAN-001 — Network Scanning (External and Internal)

Representative scenario rewritten; shared flow reviewed. Content/design review only. Local telemetry, queries, permissions, thresholds and recovery actions require validation.

## triage

### 1. Establish network context

**action:** Identify direction, NAT/VPN translation, source ownership, destination zone and sensor location. Separate attempts from successful sessions.

**fields or artifacts:** source; destination; port; action; zone; NAT; UTC

**decision:** Internal source IP is not proof of compromise.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Check authorization

**action:** Match source asset/identity, targets, tool, time and change record with the scanning owner.

**fields or artifacts:** scanner inventory; change record; target scope

**decision:** Allowlisted scanners outside approved scope remain reviewable.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## investigation

### 1. Measure behavior

**action:** Count distinct destinations and ports over explicit windows per source and zone. Compare role-specific baselines; use longer windows for slow activity and link distributed sources only with evidence.

**fields or artifacts:** source identity; destination; port; time; bytes; connection state

**decision:** Avoid universal thresholds or merging IPs across tenants/zones.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

### 2. Look for consequences

**action:** Inspect target service/authentication logs and IDS evidence for exploit attempts, successful access or impact. Correlate internal source processes and sessions.

**fields or artifacts:** IDS; service log; auth outcome; process tree

**decision:** Unauthorized scanning can be a policy event without host compromise.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## scoping

### 1. Map targets and access

**action:** Record targeted services, exposed vulnerable systems and successful sessions. Distinguish scanned from compromised assets.

**fields or artifacts:** target ledger; service role; session outcome

**decision:** Hand demonstrated exploitation to the matching incident owner.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## containment

### 1. Restrict the scan path

**action:** Use a bounded block/rate limit where justified. Check NAT/shared egress and management dependencies; denied external scans may warrant monitoring or exposure reduction.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Verify traffic reduction and legitimate service tests.

**rollback:** Expire/review temporary rules; retain original configuration.

**contraindications:** Do not apply broad isolation, disablement or data deletion from an alert score alone.

**on failure:** Record actual control state and use an approved alternative while reassessing scope.

### 2. Contain demonstrated source compromise

**action:** Isolate a host only when compromise or active harm supports it. Otherwise work with the source owner to stop unauthorized scanning.

**preconditions:** Identify the affected entity, preserve available evidence and confirm control access and service dependencies.

**approval:** Use documented incident authority; obtain the service owner's decision for disruptive action unless emergency authority applies.

**evidence preservation:** Retain relevant logs and configuration where feasible; urgent harm reduction must not wait for complete forensic collection.

**business impact:** Record affected users and dependencies; apply the smallest effective restriction.

**verification:** Verify originating activity stops and inspect alternate paths.

**rollback:** Restore approved scanning after correcting scope and schedule.

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

### 1. Resolve the actual cause

**action:** For demonstrated compromise use the related host response. Otherwise correct scan scope, policy violations or exposed services without inventing an infection.

**fields or artifacts:** host evidence; scanner config; service config

**decision:** Keep scan and compromise dispositions distinct.

**owner:** Assigned analyst; the case owner remains accountable

**evidence required:** Retain the query, UTC interval, source record identifiers, result and analyst interpretation.

**on failure:** Record missing evidence or failed action; keep the case open and assign a next check and escalation owner.

## recovery

### 1. Verify service and recurrence

**action:** Test legitimate access, record rule ownership/expiry and compare behavior with the agreed baseline.

**fields or artifacts:** service tests; rule expiry; monitoring query

**decision:** Exploitation evidence requires resolution or accepted handoff.

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

### 1. Approved scan, unauthorized scan, external reconnaissance and compromise are separate dispositions.

**evidence required:** Linked case evidence and named reviewer acceptance.

**required:** true

### 2. Exploitation and service impact have an accepted owner or resolution.

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

### Source and zone scan aggregation

Investigation candidate; syntax and effectiveness require local SIEM validation.

Map fields and identity scope to the deployed schema. Confirm collection, time, retention, parsing and deduplication.

Required normalized fields: tenant, source_zone, resolved_source_identity, destination_ip, destination_port, timestamp, action

~~~text
FROM network_connections
GROUP BY tenant, source_zone, resolved_source_identity, bin(timestamp, configured_window)
CALCULATE distinct_destination_count, distinct_destination_port_pairs, accepted_count, denied_count
COMPARE WITH calibrated_baseline_for_source_role
JOIN approved_scan_scope ON source_identity, targets, time_window
EMIT unexplained_fanout WITH action_breakdown
RUN separate longer-window aggregation for low-rate scans
~~~

Test specifications:

- Same IP in two zones is not merged.
- Denied probes are not successful sessions.
- Approved scanner outside target scope is reviewed.

## Sources

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — Shared response governance and risk management.
- [CISA incident response playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf) — Phase checklists and coordination. Federal notification deadlines are not adopted.
- [OASIS CACAO 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html) — Explicit transitions and failure paths. This graph is not a CACAO implementation.
- [MITRE detection strategies](https://attack.mitre.org/detectionstrategies/) — Behavioral detection reference; mapping is not proof of local coverage.

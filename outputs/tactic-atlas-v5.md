# TacticAtlas v5: Investigation Workspace

## Problem Statement

How might TacticAtlas help any security analyst move from an alert to a defensible next action while clearly separating sourced facts, local validation, and analyst judgment?

## Recommended Direction

Turn the existing playbook library into an offline investigation workspace. An analyst starts with alert text, reviews evidence-based playbook suggestions, selects relevant techniques, records entities and findings, works through a generated checklist, and exports a case record. The same structured playbooks remain the source of guidance.

Technical trust is the product constraint. Suggestions must state why they appeared. The interface must distinguish corpus completeness, ATT&CK-backed mappings, verified event identifiers, environment fit, planned validation, and validation performed by the current user. It must never imply that local evidence or a detection query has been verified automatically.

## Key Assumptions to Validate

- [ ] Analysts will start a case from raw alert text when suggestions include visible matching evidence. Test with representative alerts and measure accepted versus rejected suggestions.
- [ ] A local-only investigation is useful without SIEM integration. Test whether analysts can complete triage and export a useful handoff record.
- [ ] Guided and expert presentation modes can serve mixed experience levels without creating separate content sets. Test time-to-first-action and comprehension with both groups.
- [ ] Environment profiles improve relevance enough to justify setup. Measure how often unavailable telemetry is hidden or flagged.
- [ ] Analysts will record query validation outcomes when those outcomes remain clearly local and do not alter corpus claims.

## MVP Scope

- One locally stored active investigation
- Alert intake with ranked playbook suggestions and explicit match reasons
- Add and remove playbooks from the case
- Entity capture for hosts, users, processes, IP addresses, and domains
- Generated triage and evidence checklist
- Compact evidence graph linking the alert, entities, and selected techniques
- Local environment profile and per-playbook telemetry fit
- Guided and expert display modes
- Separate completeness, provenance, freshness, and validation indicators
- Local query validation status and notes
- Markdown case export

## Not Doing (and Why)

- Direct SIEM, EDR, or ticketing integrations: they would break the zero-configuration offline model and add credential risk before the workflow is proven.
- Automatic incident verdicts: the library does not observe the user environment and cannot honestly confirm malicious activity.
- Automatic query execution: vendor syntax, field mappings, permissions, and data volume require environment-specific controls.
- Multi-user collaboration: a backend and identity model are unnecessary for validating the core workflow.
- Multiple simultaneous cases: one bounded local case tests the investigation model with less storage and interface complexity.
- Automatic evidence ingestion: pasted alert text and analyst-entered entities keep the first version inspectable and safe.

## Open Questions

- Which alert formats should receive dedicated parsers after the generic intake is proven?
- Should exported cases include the full playbook guidance or only analyst-selected findings and source references?
- What evidence is required before a locally validated query can be proposed for inclusion in the shared corpus?

# TacticAtlas response review and applied improvements

Reviewed 8 September 2026. Baseline: 95275d3907187d3afeea1e0afc71c0e69f0e4e9e. Local branch: codex/source-backed-playbooks.

TacticAtlas has useful breadth and an effective offline delivery model. Its main response weakness was the decision logic: the same generic four gates appeared across the entire library, and alternate outcomes stopped without an accepted handoff or return. The local revision addresses the shared graph and rewrites six representative scenarios. Production readiness still depends on local evidence.

## Coverage and evidence

| Review area | Scope | Result |
|---|---|---|
| Original source and diagram model | All 231 records: 224 techniques, 3 operational and 4 platform playbooks | Graph/content audit recorded per playbook |
| Original rendering | All 231 diagrams; 53 matched against actual application SVGs | No node/text boundary defects, but 162 diagrams contained truncated labels |
| Revised shared workflow | All 231 records | Explicit urgency, benign, unresolved, verified containment, recovery and closure routes |
| Representative content rewrites | T1003, T1078, PB-PHISH-001, PB-RANSOM-001, PB-SCAN-001, T1530 | New procedures, evidence requirements, queries and scenario decision questions |
| Revised rendering | All 231 diagrams | Automated rendered geometry checks; see response-verification.json |
| Actual application | Six rewritten scenarios plus the longest platform title | Source links, SVG download/open, light theme and 390px viewport checked |
| Live security platforms | None | Queries, actions and telemetry effectiveness remain unvalidated |

Rendering all diagrams is not equivalent to manually inspecting every pixel or testing every incident path in a live SOC. The detailed original evidence gallery and per-playbook ledger are retained in the local audit archive; they are not runtime dependencies. The repository includes the findings and portable verification summary.

## Findings and changes

1. **Alternate outcomes were dead ends.** All 231 original graphs ended their four No branches and escalation path without explicit continuation: 1,155 non-closure terminal nodes. Revised graphs have exactly two intentional terminal dispositions, benign closure and incident closure; other branches rejoin response.
2. **Technique occurrence was treated as compromise.** The revision separates positive benign evidence, unresolved suspicion, unauthorized policy activity and confirmed compromise. The six rewritten examples ask scenario-specific questions.
3. **Urgency came after investigation.** An early harm gate now permits immediate, proportionate action while investigation continues.
4. **Escalation was incomplete.** The original diagram showed only the first of eight escalation entries. Revised diagrams show all destinations and direct analysts to the full trigger matrix. Ownership continues until handoff acceptance.
5. **Action labels lost meaning.** Migration split titles at periods/colons, producing labels such as EXTERNAL or Validate. Titles now preserve the action; diagrams use authored summaries and full-procedure step counts.
6. **Execution had no failure gate.** Containment and remediation verification now have explicit retry or investigation paths. Rewritten actions include authority, dependencies, preservation, verification and rollback/non-reversibility.
7. **Duplicated instructions could conflict.** The six rewrites remove duplicated legacy detection/response/automation sections from the active presentation and reconcile structured detection projections. Raw legacy provenance remains archived in the data.
8. **Tests did not cover real graph semantics.** Strict validation now rejects missing destinations, ambiguous decisions, unreachable nodes, dead ends and graphs with no path to an explicit end. Regression tests cover the entire real library.

## Research adopted

This was a targeted review of 32 public references, emphasizing primary standards and product guidance. It is not an exhaustive survey of the internet. The original writing in this revision applies their concepts to TacticAtlas; external playbook text, rules and executable actions were not bulk-imported.

| Source family | What it contributes | How it is used |
|---|---|---|
| [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) and [CISA playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf) | Response governance, preparation and coordination | Case ownership, evidence, recovery and improvement contract; no imported federal deadlines |
| [OASIS CACAO](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html) | Explicit control-flow concepts | Stable node IDs, explicit transitions and failure paths; no claim of CACAO compliance |
| [Microsoft response playbooks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks) | Investigation by observed scenario | Authentication outcomes, recipient impact, application consent and account persistence |
| [CISA StopRansomware](https://www.cisa.gov/stopransomware/ransomware-guide) | Coordinated response and recovery | Urgent harm reduction, protected backups, dependency-aware restoration and separate theft assessment |
| [AWS playbook framework](https://github.com/aws-samples/aws-customer-playbook-framework) | Cloud response preparation and identity scenarios | Cloud resource and principal scope; provider-specific access controls |
| [Google Cloud threat investigation](https://docs.cloud.google.com/security-command-center/docs/how-to-investigate-threats) | Finding and resource context | Cloud evidence and workload identity distinctions |
| [Sigma](https://github.com/SigmaHQ/sigma), [Elastic](https://github.com/elastic/detection-rules), [Splunk stories](https://research.splunk.com/stories/) and [MITRE](https://attack.mitre.org/detectionstrategies/) | Detection metadata, exceptions and related behavior | Design references; no rule import or unsupported conversion to native SIEM syntax |
| [CERT-SG IRM](https://github.com/certsocietegenerale/IRM) | Earlier incident checklist formats | Historical comparison only |

AWS framework documentation carries CC BY-SA licensing; its sample code has separate licensing. Elastic rules use Elastic License 2.0. Sigma rule licensing requires review before copying. Linking and independently authoring the TacticAtlas procedures avoids silently treating those libraries as MIT-licensed content.

## Representative decisions

| Scenario | Practical correction | Evidence/source |
|---|---|---|
| Credential dumping | LSASS access is not proof of extraction; non-DC replication needs attribution and authorized-service context | [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662), [sync permissions](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/user-prov-sync/pwd-hash-sync-stops-work) |
| Domain recovery | Remove the universal 12-hour krbtgt reset instruction; use the domain recovery lead and configured ticket lifetimes | [Microsoft krbtgt recovery](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password) |
| Valid accounts | Authentication, issued sessions and resource use are separate evidence stages; changing a credential may leave sessions usable | [Entra access revocation](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access), [AWS sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html), [GCP tokens](https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens) |
| Phishing | Reconcile delivery per recipient; click, consent and execution follow different response paths | [Microsoft phishing](https://learn.microsoft.com/en-us/security/zero-trust/security-operations-playbook-phishing), [app consent](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent) |
| Cisco/FortiMail | Gateway quarantine and mailbox removal are different actions; verify deployed integration and action outcomes | [Cisco capability reference](https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_13-0/b_ESA_Admin_Guide_ces_13-0/b_ESA_Admin_Guide_ces_12_0_chapter_010100.html), [FortiMail data sheet](https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/FortiMail.pdf) |
| Scanning | Distinguish approved scanning, unauthorized scanning and evidence of exploitation; group by source identity, zone and explicit interval | Analyst design recommendation informed by [MITRE Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| Cloud storage | Listing, read access, public exposure and measured transfer are separate outcomes; missing data logs cannot disprove exposure | [AWS S3 events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html), [Azure monitoring](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage), [GCP usage logs](https://docs.cloud.google.com/storage/docs/access-logs) |

## What remains before operational adoption

- The other 225 playbooks retain their inherited technique procedures. Their shared flows and operating contract improved; their scenario content has not received the same rewrite as these six.
- All 460 current query entries remain pseudocode candidates requiring adaptation. Eleven queries belong to the six rewritten scenarios. Their test cases are specifications, not successful SIEM test results.
- The existing 92.4 average quality score and maturity values were not increased. They reflect authored content metadata, not measured SOC effectiveness. Validation remains planned with no fabricated evidence.
- Select deployed versions, connectors and normalized field mappings. Assign real owners, authority, service dependencies, response deadlines and monitoring intervals.
- Test representative positive, benign, missing-data and failed-action cases in an authorized lab; retain expected/actual evidence. Pilot with analyst review before enabling disruptive automation.
- Measure time to disposition, independently verified containment, unresolved handoffs, missed telemetry, false positives and recurrence using case evidence. Set targets after establishing a local baseline.

## Reviewing and maintaining this change

Open standalone.html to use the updated offline application. The overview identifies the review scope; Respond contains the new diagram and full procedures; Reference contains clickable sources and applicability.

The changes are maintained on codex/source-backed-playbooks for repository review. Verification results are recorded in [response-verification.json](response-verification.json). Publishing this branch does not deploy the public site; deployment follows the existing main-branch workflow.

Run node scripts/improve-response.mjs after regenerating the source dataset, then node scripts/build-standalone.mjs and node scripts/check.mjs. The authoring step is idempotent; edit its named profiles to maintain the representative content. All original files remain recoverable from Git.

The full source catalog is in data/response-sources.json. Complete rewritten procedures are linked below.

- [T1003 — OS Credential Dumping](response-examples/T1003.md)
- [T1078 — Valid Accounts](response-examples/T1078.md)
- [T1530 — Data from Cloud Storage](response-examples/T1530.md)
- [PB-PHISH-001 — Phishing Alert Triage (Cisco ESA & FortiMail)](response-examples/PB-PHISH-001.md)
- [PB-RANSOM-001 — Ransomware Operations (Full Kill-Chain)](response-examples/PB-RANSOM-001.md)
- [PB-SCAN-001 — Network Scanning (External and Internal)](response-examples/PB-SCAN-001.md)

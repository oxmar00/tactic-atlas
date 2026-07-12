# Changelog

## 4.0.0 — Structured production console

### Content and ATT&CK alignment

- Migrated all 231 supplied playbooks from runtime HTML to validated, text-only structured JSON.
- Aligned tactic ordering and verified canonical/deprecated technique redirects to MITRE ATT&CK Enterprise v19.1, while preserving review-required split mappings with explicit provenance instead of presenting inference as fact.
- Added structured telemetry requirements, detection specifications, 469 vendor-neutral query examples, safe validation plans, complete incident-response phases, lifecycle ownership, coverage fields, and quality scoring.
- Added deterministic quality and coverage artifacts in JSON, Markdown, and CSV formats.

### Product and UI

- Rebuilt the console as an offline-first detection engineering workspace with ranked full-content search, fuzzy matching, eight facets, tactic filtering, individually removable filter chips, and saved/recent playbooks.
- Added matrix, compact list, coverage table, and readiness dashboard views with shareable URL state and deep links.
- Added a structured, lazy-rendered playbook reader, command palette, adjacent-playbook navigation, appearance controls, safe exports, print layout, responsive phone layouts, and accessible native dialogs.
- Refined dashboard hierarchy, metric status cues, keyboard focus, touch targets, reduced-motion support, and compact/comfortable/wide reading modes.
- Corrected wide-matrix header geometry so tactic headings and the first playbook row remain consistently aligned without overlap.

### Security, resilience, and delivery

- Removed all runtime third-party dependencies and unsafe legacy HTML rendering.
- Added strict CSPs, safe DOM construction, CSV formula hardening, external-link isolation, bounded browser storage, deterministic standalone generation, and a hardened service worker.
- Added schema/application validation, unit tests, content auditing, deterministic build drift checks, PWA assets, GitHub Pages CI, security guidance, and a single-file air-gapped edition.
- Compacted the runtime JSON payload while retaining human-readable audit reports.

## 3.0.0 — Maximum-depth operational content

- Expanded Log Source Mapping in all 231 playbooks with technique-aware collection objectives, authoritative sources, source-specific normalized fields, correlation keys, time and identity requirements, retention guidance, visibility gaps, and seven measurable readiness gates.
- Expanded Detection Logic in all 231 playbooks with tactic-aware signal models, entity keys, evaluation windows, entity-aware severity, alert evidence contracts, bounded suppression rules, blind spots, correlation pseudocode, detection-as-code acceptance gates, and five analyst triage pivots.
- Expanded Incident Response in all 231 playbooks with ownership, response targets, scoping statements, evidence standards, escalation criteria, first-15-minute actions, entity-ledger guidance, containment decisions, independent action verification, and recovery and closure gates.
- Added specialized profiles for all 14 ATT&CK tactics plus operational and security-platform playbooks.
- Added source-aware field catalogs for endpoint, Windows, PowerShell, identity, cloud, network, DNS, proxy, email, Linux, macOS, containers, files, databases, vulnerabilities, and SIEM/SOAR telemetry.
- Added sticky in-panel section navigation for the substantially expanded content.
- Added automated minimum-depth and enrichment-completeness checks to prevent regression.

## 2.0.0 — Enhanced release

### Product and UX

- Added full-playbook content search, type filters, sorting, filter reset, and live result counts.
- Added persistent saved playbooks and a dedicated Saved view.
- Added shareable searches, view state, filters, and playbook deep links.
- Made list view unique rather than repeating multi-tactic techniques.
- Added previous/next case navigation, link copying, platform tags, and light/dark themes.
- Improved responsive behavior for phones, tablets, wide matrices, and printable playbooks.

### Accessibility

- Replaced clickable generic elements with semantic buttons and sections.
- Added skip navigation, labels, status announcements, strong focus indicators, and larger touch targets.
- Added modal focus trapping, focus restoration, body scroll locking, Escape support, and reduced-motion handling.

### Security and privacy

- Removed third-party font requests and all other runtime dependencies.
- Added strict runtime sanitization for embedded playbook HTML.
- Limited external links to safe HTTPS targets with opener isolation.
- Added data validation for unsafe markup, IDs, URLs, duplicates, kinds, tactics, and metadata counts.

### Performance and resilience

- Precomputed normalized search indexes and batched rendering with animation frames.
- Added an offline cache for the hosted app and retained a single-file air-gapped edition.
- Added clear load-error states and support for blocked local storage or clipboard access.

### Engineering and delivery

- Added reproducible zero-dependency validation and standalone build scripts.
- Added GitHub Actions validation before Pages deployment.
- Expanded project documentation, data-model guidance, security notes, and maintenance commands.
- Added standalone syntax and embedded-data verification to prevent build-time corruption.

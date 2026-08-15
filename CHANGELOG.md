# Changelog

## 4.5.0 — Brand mark and ATT&CK analytics data layer

- Replaced the generic shield icon with a distinct TacticAtlas mark: a 4x4 ATT&CK matrix with an escalating path traced across tactic columns. Content sits inside the maskable safe zone so platform cropping cannot clip it.
- Added the mark to the header as inline, token-themed SVG (follows dark/light) and added a favicon, which the app previously lacked entirely. Both are inline/data-URI so the single-file `standalone.html` build still resolves with no `assets/` reference.
- Added `data/attack-analytics.json`: the authoritative technique-to-telemetry mapping for all 697 Enterprise techniques (652 with telemetry, 4,109 log-source references, 1,858 event IDs), generated from ATT&CK detection strategies and analytics via `npm run build-attack-analytics`.
- Added `data/event-catalog.json`: curated Event ID metadata (fields, use_for, investigation steps, policy caveats) for Windows Security, System, PowerShell, and Sysmon events. ATT&CK does not publish per-event field lists, so these are hand-authored from vendor documentation and events outside the catalog render without fields rather than with invented ones.
- Fixed event-code parsing: ATT&CK packs several codes into one channel (`EventCode=4103, 4104, 4105, 4106`) and the previous single-match regex dropped 561 of 1,871 identifiers.
- Fixed Event ID search precision: numeric tokens no longer fuzzy-match, so `4104` returns 32 playbooks instead of colliding with 4103/4105/4106 and matching all 231.
- Flagged 3 ATT&CK citations that attach Windows log sources to techniques with no Windows platform, rather than silently presenting them as applicable.

## 4.4.0 — Analyst workflow reader

- Restructured the playbook reader around the analyst workflow — **Overview → Detect → Hunt → Validate → Respond → Reference** — replacing a flat list of 12 collapsible sections that mixed legacy prose with structured records.
- Added an **Analyst brief** that opens first: detection objective, first triage moves, required telemetry, and a readiness line (telemetry sources, queries, ATT&CK-verified event IDs, validation status, known threat groups).
- Added a **Hunt** stage assembled from data that already existed but was buried in nested records: hypothesis, leads, investigation pivots, scoping steps, and expected benign activity.
- Cut rendered DOM from **4,809 nodes to 27–141 per stage** by rendering only the active stage; a full playbook previously rendered ~121,700 characters at once.
- Added copy-to-clipboard buttons to every query and code block, plus an "Adapt before use" marker on queries that require environment-specific changes.
- Deferred search-index construction to idle time (built on demand if a search lands first), removing a ~1.6s block from first paint.
- Renamed structured sections to signal depth (`Telemetry — full requirements`, `Detection — full specification`, `Response — full procedures`) so the summary-then-detail hierarchy is legible.
- Print now renders every stage and restores the analyst's place afterwards.

## 4.3.0 — Per-technique incident response flowcharts

- Added a generated incident-response flowchart to every one of the 231 playbooks, laid out from each record's own `response` workflow: start, triage, four decision gates with yes/no branching, the phase each gate's positive outcome leads into, an escalation exit, and closure.
- Added `PlaybookCore.buildFlowchart()` and `PlaybookCore.wrapText()` — pure, DOM-free layout functions that compute deterministic node and edge geometry with no graph-layout dependency.
- Rendered the diagram as inline SVG built with `createElementNS`, preserving the no-`innerHTML`, no-runtime-dependency, strict-CSP security model; the chart works offline and inside `standalone.html`.
- Added a self-contained `.svg` export action that inlines resolved theme colours, and print rules so the diagram appears in single-playbook print output.
- Verified layout across all 231 generated charts for text overflow, node collisions, off-canvas nodes, and dangling edges; added unit tests covering wrapping, determinism, geometry bounds, and graceful degradation when a record has no structured decision tree.

## 4.2.0 — MITRE-verified telemetry and log-source enrichment

- Cross-verified telemetry event identifiers against MITRE ATT&CK's official detection-strategy and analytic STIX objects (699 detection strategies, 1,758 analytics): 211 previously `legacy-authored-unverified` event identifiers were confirmed and upgraded to `attack-v19.1-verified`, and 411 new verified event identifiers were added across 338 merged telemetry entries.
- Added an `attack_analytics` array to enriched telemetry entries citing the specific MITRE analytic id, detection strategy id/name/URL, and log source/channel that grounds the entry.
- Added 677 new telemetry entries across 213 playbooks for log-source categories (e.g. macOS, Linux auditd, cloud audit, container runtime) that MITRE's analytics indicate apply to a technique but the playbook previously had no entry for, using this dataset's own established per-source field templates plus technique-specific event identifiers and relevance text.
- Extended `data/playbooks.schema.json` and `scripts/validate.mjs` to document and validate the new `event_ids[].provenance` convention and `attack_analytics` structure.
- Added `scripts/enhance-telemetry.mjs` (`npm run enhance-telemetry`) to regenerate this enrichment from a newer ATT&CK STIX snapshot.

## 4.1.0 — ATT&CK threat-group mapping

- Added a `threat_groups` field to every playbook, listing the ATT&CK group IDs (`Gxxxx`) directly observed using that technique, sourced from official MITRE ATT&CK STIX group-to-technique `uses` relationships (172 groups, 3,251 playbook-group mappings across 194 of 231 playbooks).
- Added a top-level `groups` directory (id, name, aliases, ATT&CK reference URL) to `data/playbooks.json` so group metadata is stored once and resolved by reference, keeping the dataset compact.
- Added a "Threat group" filter facet, clickable threat-group badges (linking to attack.mitre.org) in the playbook reader, a "Threat groups" table column, group-aware full-text search (including aliases), and a "Threat-actor mapped" dashboard metric.
- Added `scripts/add-threat-groups.mjs` (`npm run add-threat-groups`) to regenerate the mapping from a newer ATT&CK STIX snapshot.
- Extended `data/playbooks.schema.json` and `scripts/validate.mjs` to require and cross-validate the new field and directory.

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

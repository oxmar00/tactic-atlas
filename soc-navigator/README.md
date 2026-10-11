# SOC Navigator - MITRE ATT&CK Tier 1 Investigation Guide

SOC Navigator turns the MITRE ATT&CK Enterprise matrix into an investigation workflow for Tier 1 (L1) SOC analysts. For every alert it helps answer four questions:

1. **What might be happening?** - official ATT&CK technique context in plain SOC language.
2. **What evidence should I check?** - step-by-step playbooks, log-source guidance, and copyable KQL/SPL query templates.
3. **How should I interpret the findings?** - suspicious vs. legitimate indicators per step and an interactive Yes / No / Cannot-determine decision tree.
4. **When should I escalate?** - explicit Tier 2 and immediate-escalation criteria, and a structured Tier 2 handoff report.

It runs entirely in the browser: no backend, no paid API, no SIEM credentials, and no external AI service. It never executes queries and never claims to have done so.

> All 15 starter playbooks are **AI-assisted Draft content**. They must be reviewed and adapted by an authorized person before being treated as operational procedure. The UI labels Draft, Reviewed, and Approved content everywhere it appears.

## Quick start

```bash
cd soc-navigator
npm ci                 # Node.js 20+ (CI uses Node 22)
npm run dev            # http://localhost:5173 (development server)

npm run build          # production build in dist/ (typecheck + Vite build, CSP injected)
npm run preview        # serve dist/ at http://localhost:4173
```

The built site uses relative paths and hash routing, so `dist/` can be hosted under any sub-path (the repository workflow publishes it at `/soc-navigator/` on GitHub Pages). It must be served over HTTP(S); browsers block module scripts and `fetch` from `file://`.

## Features

| Area | What it does |
| --- | --- |
| Dashboard | ATT&CK counts, playbook count and review status, active investigations, investigations awaiting escalation, recent activity, recently opened playbooks, popular techniques (this browser), and playbook coverage per tactic (chart + table view). Demo data is labeled. |
| ATT&CK Enterprise Matrix | All 15 tactics, 222 techniques, and 475 sub-techniques from ATT&CK v19.2 in a Navigator-style layout. Search by ID/name/keyword/description/official telemetry, filter by tactic, platform, data component, and playbook availability, expand sub-techniques, deep links (`#/matrix?t=T1059.001`), revoked-ID explanations (e.g. T1562 -> T1685), selection mode, and ATT&CK Navigator layer export (selection or playbook coverage). Coverage is shown with labels and a legend, not color alone. |
| Technique details panel | Official description (rendered safely), tactics, platforms, parent/sub-techniques, data components and log sources from official MITRE detection strategies/analytics, associated playbooks, detection considerations, visibility gaps, MITRE link, and **Start Investigation**. Techniques without a playbook show clearly labeled *general* tactic guidance. |
| Investigation playbooks | Overview, alert context, mandatory vs. helpful prerequisites, numbered steps (what / why / where / fields / suspicious / legitimate / next), decision tree, evidence checklist, escalation criteria, query templates, detection notes, references, assumptions, and review history. |
| Active investigations | Workspace with step checkboxes and notes, persisted decision path with an explicit "apply outcome" action, evidence checklist, findings (supporting / contradicting / observation), timeline, suspicion + confidence, related techniques (validated IDs), missing information, open questions, disposition, escalation details, notes, and a local activity log. Statuses: New, In Progress, Awaiting Information, Escalation Recommended, Escalated, Resolved. Reset and JSON export. |
| Detection and log reference | 18 log sources (EDR, Defender for Endpoint, Windows Security, Sysmon, PowerShell, Task Scheduler, WMI, AV, Entra sign-in/audit, Microsoft 365 audit, email security, DNS, firewall, proxy, VPN, cloud audit, backup) with key events, fields, Sentinel tables, Splunk sources, prerequisites, and gaps; searchable query library; Windows event ID reference; glossary. |
| Query templates | 86 templates (39 KQL, 32 SPL, 15 generic procedures). Each states the platform, purpose, required data sources, placeholders, key fields, what positive and negative results do and do not establish, permissions/telemetry dependencies, schema notes, and a safe example. Placeholders can be filled (and are pre-filled from recorded evidence) with context-aware escaping; copy to clipboard. |
| Reports and escalations | Tier 2 handoff with executive summary, alert context, affected users/assets, timeline, steps completed, evidence, ATT&CK hypotheses, benign explanations, suspicious indicators, missing telemetry and limitations, next steps, escalation reason, and outstanding questions. Preview, edit (fields or full Markdown), export Markdown/JSON, print / save as PDF, mark escalated or resolved. |
| Playbook authoring and review | Create, duplicate, edit (overview, techniques, tactics, log sources, prerequisites, steps, decision branches, evidence fields, escalation criteria, queries and placeholders, references, assumptions), analyst-view preview, semantic version bump, Draft -> Reviewed -> Approved workflow with reviewer, notes, and history, import/export JSON with validation. Editing a starter playbook creates a local revision; content edits reset approval to Draft. |
| Optional assistant | Offline rule-based assistant (default): evidence summary, missing steps, log-source suggestions, timeline summary, related techniques, handoff draft. Output is split into facts / hypotheses / recommendations and flags instruction-like text embedded in alert data. An optional remote LLM provider is supported only through a same-origin backend proxy with explicit consent (see `docs/AI-ASSISTANT.md`). |
| Settings and data sources | Analyst identifier, demo role, default query language, ATT&CK dataset metadata (version, publication date, source URL, SHA-256, last successful update), in-browser update check/apply/revert, integration status (none configured), assistant configuration, storage usage, backup export, demo data, and resets. |

## Project structure

```text
soc-navigator/
├── index.html                    # app shell (CSP is injected at build time)
├── public/
│   ├── data/attack-enterprise.json   # normalized ATT&CK Enterprise v19.2 snapshot (generated)
│   └── favicon.svg
├── scripts/update-attack.ts      # repeatable ATT&CK refresh / verification
├── src/
│   ├── App.tsx, main.tsx, index.css
│   ├── state/AppState.tsx        # app state, persistence wiring
│   ├── components/               # layout, technique drawer, playbook reader parts, UI primitives
│   ├── pages/                    # dashboard, matrix, playbooks, editor, workspace, reports, reference, settings
│   ├── data/
│   │   ├── playbooks/            # 15 starter playbooks (organization-authored content)
│   │   ├── logSources.ts         # log source catalog and Windows event reference
│   │   ├── generalGuidance.ts    # tactic-level guidance for techniques without a playbook
│   │   └── glossary.ts
│   └── lib/
│       ├── attack/               # STIX normalizer, loader + fallback, index/search, layer export, safe text tokenizer
│       ├── playbooks/            # zod schema, outcomes, library (coverage, import/export, versioning)
│       ├── investigations/       # investigation state model (pure functions)
│       ├── assistant/            # local assistant + optional proxy client with guardrails
│       ├── report.ts             # Tier 2 handoff builder + Markdown/JSON export
│       ├── queries.ts            # placeholder validation, escaping, evidence pre-fill
│       ├── storage.ts, idb.ts    # replaceable persistence adapters
│       ├── settings.ts, demo.ts
├── tests/                        # Vitest unit tests (139)
├── e2e/                          # Playwright end-to-end tests
└── docs/                         # PRODUCTION.md, AI-ASSISTANT.md
```

Data and authored guidance are deliberately separate: `public/data/attack-enterprise.json` contains only MITRE content; playbooks reference techniques by ID and read names/descriptions from the dataset at runtime. Refreshing ATT&CK never touches playbooks.

## ATT&CK data

- **Source:** official STIX 2.1 bundle from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (`enterprise-attack-19.2.json`, collection modified 2026-08-05). The SHA-256 of the raw bundle is stored in the snapshot metadata.
- **Normalization (`src/lib/attack/normalize.ts`):** enterprise objects only; tactic order from the official `x-mitre-matrix`; revoked and deprecated objects excluded from the active view but kept in `retired` with their `revoked-by` replacement; sub-technique links from `subtechnique-of`; telemetry only from official detection strategies -> analytics -> log-source references; STIX citation markers stripped. Nothing is invented.
- **Fallback chain at runtime:** a newer release the analyst downloaded in Settings (IndexedDB, validated) -> the bundled snapshot -> an error state with retry. Playbooks, investigations, and reports keep working without ATT&CK data.

### Updating ATT&CK data

```bash
npm run attack:update                          # latest Enterprise release from MITRE's index.json
npm run attack:update -- --version 19.2        # a specific release
npm run attack:update -- --file ./enterprise-attack.json   # offline / air-gapped bundle
npm run attack:verify                          # validate the committed snapshot
npm test                                       # confirms every playbook technique ID is still active
```

The script downloads only from `raw.githubusercontent.com/mitre-attack/attack-stix-data`, validates before writing, writes atomically, refuses downgrades unless `--allow-downgrade`, leaves the existing snapshot untouched on any failure, and prints added/removed technique IDs. If a starter playbook references a technique that MITRE revoked, `npm test` fails and names it - update the playbook to the replacement ID and re-review it.

Analysts can also check for and apply a newer release from **Settings and Data Sources**; this request is made only on click, sends no investigation data, and is stored in this browser only.

## Starter playbooks

All IDs were verified active in ATT&CK v19.2 (unit-tested).

| ID | Investigation area | Techniques |
| --- | --- | --- |
| PB-PHISH-001 | Reported or detected phishing email | T1566, .001, .002 |
| PB-USEREXEC-001 | User execution of a suspicious file or link (incl. paste-and-run lures) | T1204, .001, .002, .004 |
| PB-PWSH-001 | Suspicious PowerShell / command interpreter activity | T1059, .001, .003 |
| PB-SCHTASK-001 | Suspicious scheduled task | T1053, .005 |
| PB-WMI-001 | Suspicious WMI activity and event subscriptions | T1047, T1546.003 |
| PB-CREDDUMP-001 | Credential dumping (LSASS, SAM, NTDS, DCSync) | T1003, .001, .002, .003, .006 |
| PB-BRUTE-001 | Brute force / password spraying | T1110, .001, .003, .004 |
| PB-VALIDACCT-001 | Suspicious use of a valid account | T1078, .002, .004 |
| PB-RUNKEY-001 | Registry Run key / Startup folder persistence | T1547, .001 |
| PB-LATMOVE-001 | Remote services and possible lateral movement | T1021, .001, .002, .006 |
| PB-INGRESS-001 | Ingress tool transfer | T1105 |
| PB-INJECT-001 | Suspicious process injection | T1055, .001, .002, .012 |
| PB-C2-001 | Potential command-and-control communication | T1071, .001, .004 |
| PB-EXFIL-001 | Potential data exfiltration | T1041, T1048, T1567, .002 |
| PB-RANSOM-001 | Ransomware and data encryption for impact | T1486, T1490, T1489 |

Each has 5-7 technique-specific steps, 3-6 decision questions, 11-16 evidence fields, Tier 2 / immediate / benign-closure criteria, and 5-7 KQL, SPL, and generic query templates. Unit tests enforce that step titles and queries are not duplicated across playbooks.

## Testing

```bash
npm run typecheck   # strict TypeScript
npm test            # Vitest unit tests
npm run test:e2e    # Playwright: builds, serves, and drives the main workflow in Chromium
# In this repository's cloud dev container Chromium is pre-installed:
PW_CHROMIUM_PATH=/opt/pw-browsers/chromium npm run test:e2e
```

- **Unit tests (139):** STIX normalization (ordering, retired objects, sub-technique links, telemetry derivation, citation stripping, rejection of non-Enterprise input), the committed snapshot, search, layer export, safe description tokenizing, playbook schema and content rules (active IDs, Draft status for AI content, decision-tree reachability, no duplicated steps), library import/export, investigation state transitions and persistence (corruption handling, prototype-pollution keys, size cap), report generation and Markdown neutralization, query escaping and validation, assistant guardrails and the proxy client.
- **End-to-end (3):** matrix search -> technique panel -> start investigation -> steps, notes, evidence, decision outcome -> reload persistence -> query copy (pre-filled from evidence) -> handoff report export -> mark escalated -> authoring (duplicate, edit, save, preview, export); every primary view renders with **no console errors or CSP violations**; graceful degradation when ATT&CK data is unavailable.

## Security model (demo build)

- Strict Content Security Policy in the built `index.html`: scripts, styles, and data only from the same origin; `connect-src` adds `raw.githubusercontent.com` solely for the analyst-initiated ATT&CK update check. No inline scripts.
- No `dangerouslySetInnerHTML`. Official ATT&CK text is tokenized and rendered as React text; only `https://` links are rendered, with `rel="noopener noreferrer"`.
- All persisted and imported data is validated with zod schemas and size limits; corrupted records are set aside, not silently dropped; keys that could pollute prototypes are rejected.
- Query placeholders: string values are escaped for the target language; unquoted kinds (datetime, timespan, number) must match strict patterns.
- Exported Markdown neutralizes raw HTML and fences untrusted command lines.
- Demo data uses documentation IP ranges (RFC 5737) and example domains, and is labeled DEMO everywhere.
- No secrets in the bundle; no network calls except the explicit ATT&CK update check and, if configured and consented, a same-origin assistant proxy.

See `docs/PRODUCTION.md` for what a production deployment must add (authentication, authorization, audit logging, retention, encrypted server-side storage, security headers).

## Known limitations

- **Persistence is browser-local** (localStorage + IndexedDB for downloaded ATT&CK data). It is unencrypted, single-user, and lost when site data is cleared. The demo role switch is not access control.
- **No live integrations.** Queries are templates; table names, sourcetypes, and fields follow documented defaults but vary by connector, add-on version, and normalization - each template says so. They have not been executed against a live Sentinel or Splunk instance in this project.
- **Starter content is Draft and AI-assisted.** Escalation thresholds (e.g. campaign size) are placeholders for your policy.
- **Coverage is playbook coverage**, not detection coverage.
- The in-browser ATT&CK update downloads ~50 MB and parses it on the main thread (a few seconds); the CLI script is the recommended path.
- Tested in Chromium. The layout targets desktop and laptop resolutions; the matrix scrolls horizontally on narrow screens.
- "Popular techniques" and "recently opened" reflect usage in the current browser only.

## Next steps for production (prioritized)

1. Replace `StorageAdapter` with an authenticated backend API (SSO/OIDC, per-case authorization, server-side validation, encryption at rest, retention policy, immutable audit log).
2. Enforce playbook governance server-side: role-based authoring and approval, two-person review, signed versions in a Git-backed repository.
3. Review and approve each starter playbook against local telemetry, escalation policy, and tooling; validate every query against your schemas and record results.
4. Server-side SIEM connectors (Sentinel, Splunk, Defender, Elastic) with least-privilege service identities, query allow-listing, cost limits, and result provenance.
5. Ticketing / SOAR integration for escalations (no autonomous containment).
6. Optional assistant proxy with authentication, logging, data minimization, and model output review (see `docs/AI-ASSISTANT.md`).
7. Scheduled ATT&CK refresh in CI with review of added/removed IDs; move the in-browser STIX parsing into a Web Worker.
8. Accessibility audit with assistive technology, and cross-browser testing (Firefox, Safari, Edge).

## License and attribution

MIT (see repository `LICENSE`). MITRE ATT&CK® is a registered trademark of The MITRE Corporation; ATT&CK content is used under MITRE's terms of use. This project is not affiliated with or endorsed by MITRE.

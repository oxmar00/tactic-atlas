# TacticAtlas

TacticAtlas is a static, offline-capable detection engineering, threat-hunting, and incident-response library. It ships 231 structured playbooks for SOC analysts, detection engineers, DFIR teams, incident responders, and security-platform owners without requiring a backend, account, remote API, or runtime dependency.

Version 4 replaces executable content markup with a versioned JSON model. The browser constructs every playbook with DOM APIs and text nodes; legacy HTML is converted during migration and is not rendered at runtime.

## Capabilities

- ATT&CK matrix, compact list, sortable table, and source-backed coverage dashboard views.
- Ranked, normalized full-text search across IDs, technique names, fields, event IDs, processes, paths, telemetry, queries, and response actions.
- Filters for tactic, technique, platform, telemetry source, severity, detection maturity, lifecycle status, saved items, and recently viewed playbooks.
- Structured telemetry requirements, detection strategies, query examples, safe validation procedures, and full incident-response phases in every record.
- Saved and recently viewed playbooks, shareable URL state, browser history, deep links, previous/next navigation, and a keyboard command palette.
- JSON, Markdown, and formula-safe CSV exports; print-friendly single-playbook output.
- Dark/light themes, adjustable text and reading width, accessible dialogs, reduced-motion support, and responsive layouts.
- Offline access after first load, an explicit update prompt, and a fully self-contained `standalone.html` edition.
- Transparent per-playbook quality scores and project-wide coverage/content-quality reports.


## Project structure

```text
.
├── index.html
├── standalone.html                 # generated
├── manifest.webmanifest
├── service-worker.js
├── assets/
│   ├── app.js                      # browser orchestration and DOM rendering
│   ├── core.js                     # pure search/filter/routing/export functions
│   ├── icon.svg
│   └── style.css
├── data/
│   ├── playbooks.json              # v4 structured source of truth
│   └── playbooks.schema.json
├── reports/
│   ├── content-quality.json
│   ├── content-quality.md
│   └── coverage.csv
├── scripts/
│   ├── audit-content.mjs
│   ├── build-standalone.mjs
│   ├── check.mjs
│   ├── migrate-v4.mjs
│   └── validate.mjs
├── tests/
├── .github/workflows/deploy.yml
├── CHANGELOG.md
├── IMPLEMENTATION-REPORT.md
└── SECURITY.md
```

## Version 4 data model

Each playbook contains structured fields rather than trusted HTML:

```jsonc
{
  "schema_version": "4.0.0",
  "id": "T1059",
  "name": "Command and Scripting Interpreter",
  "kind": "technique",
  "description": "…",
  "tactics": ["Execution"],
  "tactic_mappings": [{ "tactic": "Execution", "provenance": "attack-v19.1" }],
  "techniques": [{ "id": "T1059", "name": "Command and Scripting Interpreter" }],
  "subtechniques": [],
  "platforms": ["Windows", "Linux", "macOS"],
  "telemetry_requirements": [],
  "detection": {},
  "queries": [],
  "validation": {},
  "response": {},
  "lifecycle": {},
  "quality_score": 0,
  "quality_breakdown": {},
  "coverage": {},
  "content_sections": []
}
```

The complete machine-readable contract is in `data/playbooks.schema.json`. `content_sections` is a safe rendering projection; canonical telemetry, detection, validation, response, and lifecycle objects remain available for automation and export.

### Telemetry requirements

Every telemetry entry distinguishes required, recommended, optional, or compensating coverage and records event types, verified or explicitly unverified event identifiers, raw/normalized fields, mappings, correlation keys, retention, latency, collection prerequisites, blind spots, quality gates, health monitoring, example products, and detection/investigation/evidence relevance.

### Detection and response

Detection objects include the objective, hypothesis, behavioral strategy, maturity levels, correlation/risk model, pseudocode, false positives, tuning boundaries, severity, dependencies, and query metadata. Query examples are labeled when environment adaptation or validation is required.

Response objects contain triage, investigation, scoping, immediate/short-term/long-term containment, eradication, recovery, post-incident actions, escalation, analyst decisions, and evidence-backed closure criteria. Disruptive steps retain prerequisites, approval, evidence, business-impact, rollback, and contraindication context.


## ATT&CK updates

ATT&CK mappings must be reviewed whenever MITRE publishes a new release. Update the metadata snapshot/version first, reconcile revoked or replaced objects using official change relationships, then update tactic, technique, sub-technique, platform, and reference fields. Never silently replace a legacy ID; retain a deprecated record or explicit migration relationship when it matters to historical cases.

## Security model

- The normal application makes no third-party runtime requests and uses a strict self-only Content Security Policy.
- Playbook content is structured JSON and rendered with element creation and `textContent`; `innerHTML` is not used for dataset content.
- URLs are parsed and restricted before assignment. External references require HTTPS and opener isolation.
- URL state, storage, clipboard fallbacks, JSON input, prototype-mutating keys, and exports are bounded and validated.
- CSV exports neutralize spreadsheet formula prefixes.
- The service worker caches only known successful same-origin application resources, scopes cache cleanup to this application, and uses a navigation-only HTML fallback.
- The standalone build uses generated content hashes for inline scripts and styles and rejects unresolved local runtime dependencies.

See `SECURITY.md` for reporting and deployment guidance.

## GitHub Pages

The workflow verifies pull requests and deploys only a successful `main` build. It installs from the lockfile, validates data and application assets, runs tests and the content audit, regenerates the standalone artifact, rejects drift, performs a dependency audit, and uploads only runtime files.

In repository settings, choose **GitHub Actions** as the Pages source. The public site is designed for `https://oxmar00.github.io/tactic-atlas/`.

## Troubleshooting

- **Data cannot be loaded:** Serve the folder over HTTP or open `standalone.html`; browsers block `fetch` from some `file:` pages.
- **Standalone is stale:** Run `npm run build`, then `npm run build:check`.
- **A schema error names a record path:** Correct the source record; do not weaken the validator or add filler text.
- **Offline content is old:** Use the visible update prompt while online. If deployment paths changed, clear this application’s site data and reload once.
- **A query does not run in your SIEM:** Check its `adaptation_required`, assumptions, source table, and normalized-field contract. Example queries are not automatically production-certified.
- **No results after filtering:** Use **Clear all filters**; URL state may intentionally preserve multiple filters and selected tactics.

## Compatibility

The application targets current stable Chrome, Microsoft Edge, Firefox, Safari, and mobile browsers. It uses progressive enhancement for service workers, clipboard access, printing, and installation.

## License and attribution

Code and project-authored content are released under the [MIT License](LICENSE). MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

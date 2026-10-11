# Production deployment requirements

The repository ships a **demo build**: a static single-page application with browser-local
persistence. It is suitable for evaluation, training, and individual use with non-sensitive data.
Before SOC Navigator holds real incident data, a deployment must add the controls below. The
application code isolates every one of these concerns behind a replaceable boundary.

## 1. Authentication

- Put the application and every API behind your identity provider (OIDC/SAML SSO) with MFA.
- Use short-lived sessions; revoke sessions on role change or offboarding.
- Never place API keys, SIEM credentials, or model keys in the frontend bundle or browser storage.

## 2. Authorization

The demo "role" selector in Settings is a UI convenience, **not** access control. Enforce on the server:

| Capability | Suggested role |
| --- | --- |
| Read playbooks, matrix, reference | All SOC staff |
| Create/edit own investigations | Tier 1+ |
| View other analysts' investigations | Same team / case assignment |
| Author or edit playbooks | Playbook authors |
| Mark playbooks Reviewed / Approved | Designated reviewers; approver must differ from author (two-person rule) |
| Export / delete investigations | Per retention policy; deletion should be soft-delete with audit |

## 3. Persistence and encrypted storage

- Replace `src/lib/storage.ts` (`StorageAdapter`) and the `AppState` persistence effects with an API client.
- Store investigations and playbooks in a database encrypted at rest (KMS-managed keys), with TLS 1.2+ in transit.
- Re-validate every write server-side with the same zod schemas (`src/lib/investigations/model.ts`, `src/lib/playbooks/schema.ts`) - client validation is not a security control.
- Keep playbooks in a version-controlled repository (Git) so every change is reviewable; publish approved versions to the application.

## 4. Audit logging

- Log, immutably and centrally: sign-ins, investigation create/update/status change/export/delete, report exports, playbook edits and status transitions, ATT&CK dataset changes, and assistant requests (metadata, not content, unless policy requires).
- The in-app "Activity log" is a convenience for analysts and is not tamper-proof.

## 5. Retention

- Define retention per data class (investigation records, evidence text, exported reports, assistant logs) aligned with legal and regulatory requirements; implement automated deletion.
- Minimize collected evidence: record only what the investigation needs; prefer references (alert IDs, SIEM links) over copies of raw data.

## 6. HTTP security headers

The build injects a strict CSP `<meta>` tag. Serve these headers as well (some directives cannot be set via `<meta>`):

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://raw.githubusercontent.com; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

Remove `https://raw.githubusercontent.com` from `connect-src` if ATT&CK updates are delivered only through the build pipeline (recommended).

## 7. ATT&CK data management

- Run `npm run attack:update` in CI on a schedule (or on MITRE release), review the printed added/removed IDs, run tests, and deploy through normal change control.
- Pin the reviewed snapshot (its SHA-256 is recorded in `meta.sha256`).
- Consider disabling the in-browser update in production so all analysts use the same reviewed release.

## 8. Integrations (future)

SIEM/EDR connectors (Microsoft Sentinel, Splunk, Defender for Endpoint, Elastic) must run server-side with least-privilege service identities, query allow-lists or review, rate and cost limits, and result provenance (which data source, time range, and query produced each result). Results shown to analysts must be labeled with that provenance. No connector should perform containment actions without a separately designed, authorized, and audited workflow.

## 9. Operational readiness checklist

- [ ] SSO + MFA in front of the app and APIs
- [ ] Server-side authorization matrix implemented and tested
- [ ] Encrypted database + backups + restore test
- [ ] Immutable audit logging wired to the SIEM
- [ ] Retention jobs configured
- [ ] Security headers verified (e.g. with an external scanner)
- [ ] All starter playbooks reviewed, adapted, and Approved (or removed)
- [ ] Queries validated against your schemas; results recorded
- [ ] Incident escalation contacts and thresholds configured in the playbooks
- [ ] Accessibility and cross-browser testing completed

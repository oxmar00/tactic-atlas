# Security policy

## Reporting a vulnerability

Do not open a public issue containing exploit details, sensitive logs, customer data, or credentials. Contact the repository owner through the private security-reporting channel configured for the repository. Include the affected version, reproduction conditions, impact, and the smallest safe proof needed to validate the report.

## Supported release

Only the latest tagged release receives security fixes. Deployments should retain the visible data/application version and monitor service-worker update failures.

## Deployment checklist

- Run `npm run check` and regenerate `standalone.html` from reviewed sources.
- Deploy only the documented runtime allowlist; never publish incident evidence, credentials, private indicators, or local fixtures.
- Keep the supplied Content Security Policy and HTTPS hosting controls intact.
- Review all added external references and query/export content.
- Treat telemetry gaps, parser failures, and stale playbook review dates as operational security findings.
- Revalidate example queries and response approvals against the target environment before enabling alerts or automation.

The repository contains defensive guidance. Validation procedures must remain non-destructive, authorized, bounded to an isolated test environment, and paired with cleanup and safety warnings.

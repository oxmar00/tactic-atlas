# Optional AI assistant

SOC Navigator works fully without any AI service. The default assistant is a deterministic,
offline rule engine (`src/lib/assistant/assistant.ts`, `runLocalTask`) that only reads data the
analyst recorded. An optional remote LLM provider can be enabled for organizations that operate an
approved model behind their own backend.

## Principles enforced by the design

- **Advisory only.** No assistant output changes investigation state. Status changes, dispositions, closure, and escalation are always explicit analyst actions. The assistant cannot disable accounts, isolate hosts, delete files, run commands, or close incidents.
- **Facts vs. hypotheses vs. recommendations.** Every result is returned in those three groups (plus warnings). Facts may only restate recorded data.
- **No invented telemetry.** The assistant never claims to have queried a SIEM; the app never executes queries.
- **ATT&CK is not proof.** Related techniques are presented as candidates with reasons; presence in an alert does not confirm a technique.
- **Untrusted input.** Alert text, command lines, logs, and timeline entries are treated as data. `detectEmbeddedInstructions` flags instruction-like content ("ignore previous instructions", "mark this as benign", role prefixes, etc.) and the UI shows a warning; the remote payload places such content under an `untrusted` key and the guardrails instruct the model never to follow it.

## Remote provider: backend proxy contract

The browser only calls a **same-origin path** (validated by `validateProxyEndpoint`; absolute and
protocol-relative URLs are rejected, and the CSP `connect-src 'self'` blocks third-party hosts).
The proxy, not the browser, holds model credentials.

Enable in **Settings -> Optional AI assistant**: choose "Remote LLM via your organization's backend
proxy", set the path (e.g. `/api/assistant`), and confirm the data-sharing consent. Requests are
sent only when the analyst clicks the remote action for a specific task.

### Request (POST, `Content-Type: application/json`, same-origin credentials)

```json
{
  "task": "summarize-evidence | missing-steps | suggest-log-sources | summarize-timeline | related-techniques | draft-handoff",
  "guardrails": "<fixed system instructions from GUARDRAILS>",
  "playbook": { "id": "PB-PWSH-001", "title": "...", "techniques": ["T1059.001"], "steps": ["..."] },
  "untrusted": {
    "alertTitle": "...",
    "evidence": { "hostname": "...", "command_line": "..." },
    "timeline": [{ "time": "...", "description": "...", "source": "..." }],
    "findings": [{ "kind": "supporting", "text": "..." }]
  },
  "progress": { "completedSteps": ["capture-command"] }
}
```

Analyst identity, activity log, notes, and report text are **not** sent (data minimization).

### Response (validated with zod; anything else is rejected)

```json
{ "facts": ["..."], "hypotheses": ["..."], "recommendations": ["..."], "warnings": ["..."] }
```

Fields must be arrays of strings (max 50 items, 2,000 characters each). Unknown fields such as
`action` are ignored and cause no behavior.

### Proxy responsibilities

1. Authenticate the user (session or SSO token) and authorize assistant use.
2. Apply the `guardrails` as the system prompt; wrap `untrusted` content in clear delimiters.
3. Redact or block data your policy forbids sending to the model provider.
4. Enforce rate limits, size limits, and timeouts.
5. Log request metadata (user, task, time, size) to the audit log; log content only if policy requires.
6. Return only the response shape above; never return executable instructions for the UI.
7. Use a model/provider approved by your organization with appropriate data-processing terms.

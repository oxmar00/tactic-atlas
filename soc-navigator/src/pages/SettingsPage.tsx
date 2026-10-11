import { useState } from 'react';
import { CloudDownload, Database, PlugZap, RefreshCw, RotateCcw, Settings as SettingsIcon, Trash2 } from 'lucide-react';
import { Badge, Button, Callout, Card, DeferredInput, Field, PageHeader, downloadFile, formatDate } from '../components/ui';
import { validateProxyEndpoint } from '../lib/assistant/assistant';
import { checkLatestRelease, compareVersions, downloadAndApplyRelease, revertToBundled } from '../lib/attack/loader';
import type { ReleaseInfo } from '../lib/attack/loader';
import { QUERY_LANGUAGES } from '../lib/playbooks/schema';
import { LANGUAGE_LABEL } from '../lib/queries';
import { DEFAULT_SETTINGS, ROLES, ROLE_LABEL } from '../lib/settings';
import type { Role } from '../lib/settings';
import { KEYS } from '../lib/storage';
import { useApp } from '../state/AppState';

const INTEGRATIONS = [
  ['Microsoft Sentinel', 'Planned connector: run saved KQL via Log Analytics query API through a backend with managed identity.'],
  ['Splunk', 'Planned connector: run SPL via the Splunk REST search API through a backend service account.'],
  ['Microsoft Defender for Endpoint', 'Planned connector: advanced hunting API through a backend app registration.'],
  ['Elastic Security', 'Planned connector: Elasticsearch/ES|QL query API through a backend API key.'],
] as const;

export function SettingsPage() {
  const app = useApp();
  const { settings, updateSettings, attack, notify } = app;
  const [release, setRelease] = useState<ReleaseInfo | null>(null);
  const [busy, setBusy] = useState<'check' | 'apply' | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const meta = attack.index?.dataset.meta;
  const endpointError = settings.assistant.mode === 'remote-proxy' ? validateProxyEndpoint(settings.assistant.endpoint) : null;

  const check = async () => {
    setBusy('check');
    setUpdateError(null);
    try {
      setRelease(await checkLatestRelease());
    } catch (e) {
      setUpdateError(`${e instanceof Error ? e.message : 'Check failed.'} The current dataset remains active.`);
    } finally {
      setBusy(null);
    }
  };
  const apply = async () => {
    if (!release) return;
    setBusy('apply');
    setUpdateError(null);
    try {
      const ds = await downloadAndApplyRelease(release);
      app.applyDataset(ds, 'browser-update');
      notify(`ATT&CK Enterprise ${ds.meta.version} applied in this browser.`, 'success');
    } catch (e) {
      setUpdateError(`${e instanceof Error ? e.message : 'Update failed.'} The previous dataset remains active.`);
    } finally {
      setBusy(null);
    }
  };

  const exportAll = () =>
    downloadFile(
      'soc-navigator-backup.json',
      `${JSON.stringify({ format: 'soc-navigator-backup', exportedAt: new Date().toISOString(), settings, investigations: app.investigations, localPlaybooks: app.localPlaybooks }, null, 2)}\n`,
      'application/json',
    );

  return (
    <div className="space-y-5">
      <PageHeader icon={<SettingsIcon className="h-5 w-5 text-accent" aria-hidden />} title="Settings and Data Sources" subtitle="Analyst profile, ATT&CK dataset, integrations, the optional assistant, and local storage." />

      <Card title="Analyst profile and preferences">
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="Analyst identifier" htmlFor="s-name" hint="Recorded on new investigations. Use your SOC handle, not personal data.">
            <DeferredInput id="s-name" value={settings.analystName} maxLength={100} onCommit={(v) => updateSettings({ analystName: v.trim().slice(0, 100) || 'demo.analyst' })} />
          </Field>
          <Field label="Role (demo)" htmlFor="s-role" hint="Controls authoring and approval buttons in this demo. Not an access control.">
            <select id="s-role" className="input" value={settings.role} onChange={(e) => updateSettings({ role: e.target.value as Role })}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Default query language" htmlFor="s-lang">
            <select id="s-lang" className="input" value={settings.defaultLanguage} onChange={(e) => updateSettings({ defaultLanguage: e.target.value as (typeof QUERY_LANGUAGES)[number] })}>
              {QUERY_LANGUAGES.map((l) => (
                <option key={l} value={l}>
                  {LANGUAGE_LABEL[l]}
                </option>
              ))}
            </select>
          </Field>
        </div>
      </Card>

      <Card
        title={
          <span className="flex items-center gap-2">
            <Database className="h-4 w-4" aria-hidden /> MITRE ATT&amp;CK dataset
          </span>
        }
        actions={
          <Button size="sm" icon={<RefreshCw className="h-3.5 w-3.5" aria-hidden />} onClick={app.reloadAttack}>
            Reload
          </Button>
        }
      >
        {attack.status === 'error' && (
          <Callout tone="danger" title="Dataset unavailable" className="mb-3">
            {attack.error}
          </Callout>
        )}
        {attack.warnings.map((w) => (
          <Callout key={w} tone="warning" className="mb-3">
            {w}
          </Callout>
        ))}
        {meta && (
          <dl className="grid gap-x-4 gap-y-1.5 text-sm md:grid-cols-[14rem_1fr]">
            <dt className="text-muted">Domain / release</dt>
            <dd>
              Enterprise ATT&amp;CK <strong>v{meta.version}</strong> (STIX spec {meta.attackSpecVersion ?? 'n/a'})
            </dd>
            <dt className="text-muted">MITRE publication date</dt>
            <dd>{formatDate(meta.modified)}</dd>
            <dt className="text-muted">Active source</dt>
            <dd>
              {attack.source === 'browser-update' ? <Badge tone="info">Downloaded in this browser</Badge> : <Badge>Bundled snapshot</Badge>}
            </dd>
            <dt className="text-muted">Retrieved from</dt>
            <dd className="font-mono text-xs break-all">{meta.sourceUrl}</dd>
            <dt className="text-muted">Bundle SHA-256</dt>
            <dd className="font-mono text-xs break-all">{meta.sha256 ?? 'not computed (browser update)'}</dd>
            <dt className="text-muted">Last successful update</dt>
            <dd>{formatDate(meta.retrievedAt)}</dd>
            <dt className="text-muted">Contents</dt>
            <dd>
              {meta.counts.tactics} tactics, {meta.counts.techniques} techniques, {meta.counts.subtechniques} sub-techniques active; {meta.counts.revoked} revoked and {meta.counts.deprecated} deprecated objects excluded from the default view;{' '}
              {meta.counts.detectionStrategies} detection strategies, {meta.counts.analytics} analytics.
            </dd>
          </dl>
        )}
        <div className="mt-4 space-y-2 rounded-md border border-line bg-panel-2 p-3 text-sm">
          <p className="font-semibold text-fg-strong">Check for a newer release</p>
          <p className="text-muted">
            Contacts <span className="font-mono text-xs">raw.githubusercontent.com/mitre-attack/attack-stix-data</span> only when you click. No investigation data is sent. The download is about 50 MB and is normalized and validated in your browser before use; on any failure the current data stays active.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" icon={<CloudDownload className="h-3.5 w-3.5" aria-hidden />} disabled={busy !== null} onClick={() => void check()}>
              {busy === 'check' ? 'Checking...' : 'Check MITRE for updates'}
            </Button>
            {release && meta && (
              <>
                <span>
                  Latest published: <strong>v{release.version}</strong>
                  {compareVersions(release.version, meta.version) <= 0 ? ' - you are up to date.' : ' - newer than the active dataset.'}
                </span>
                {compareVersions(release.version, meta.version) > 0 && (
                  <Button size="sm" variant="primary" disabled={busy !== null} onClick={() => void apply()}>
                    {busy === 'apply' ? 'Downloading and validating...' : `Download and apply v${release.version}`}
                  </Button>
                )}
              </>
            )}
            {attack.source === 'browser-update' && (
              <Button
                size="sm"
                variant="danger"
                icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden />}
                onClick={async () => {
                  await revertToBundled().catch(() => undefined);
                  app.reloadAttack();
                  notify('Reverted to the bundled ATT&CK snapshot.', 'success');
                }}
              >
                Revert to bundled snapshot
              </Button>
            )}
          </div>
          {updateError && (
            <p role="alert" className="text-sm text-bad">
              {updateError}
            </p>
          )}
          <p className="text-xs text-faint">
            Repeatable refresh for the deployed build: <span className="font-mono">npm run attack:update</span> (or <span className="font-mono">-- --file enterprise-attack.json</span> offline), then <span className="font-mono">npm test</span> and redeploy. Playbooks are never modified by a refresh.
          </p>
        </div>
      </Card>

      <Card
        title={
          <span className="flex items-center gap-2">
            <PlugZap className="h-4 w-4" aria-hidden /> Integrations
          </span>
        }
      >
        <Callout tone="info" className="mb-3" title="No live integrations in this build">
          SOC Navigator does not connect to any SIEM, EDR, or ticketing system and never executes queries. All query templates are copied and run by the analyst. Connectors must be implemented server-side so credentials never reach the browser.
        </Callout>
        <ul className="grid gap-2 md:grid-cols-2">
          {INTEGRATIONS.map(([name, plan]) => (
            <li key={name} className="rounded-md border border-line bg-panel-2 p-3 text-sm">
              <p className="flex items-center gap-2 font-medium text-fg-strong">
                {name} <Badge>Not configured</Badge>
              </p>
              <p className="mt-0.5 text-xs text-muted">{plan}</p>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Optional AI assistant">
        <fieldset className="space-y-2 text-sm">
          <legend className="sr-only">Assistant provider</legend>
          <label className="flex items-start gap-2">
            <input type="radio" name="assistant-mode" className="mt-1" checked={settings.assistant.mode === 'local'} onChange={() => updateSettings({ assistant: { ...settings.assistant, mode: 'local' } })} />
            <span>
              <span className="font-medium text-fg-strong">Local rule-based assistant (default, offline)</span>
              <span className="block text-xs text-muted">Summaries, gap checks, and drafts computed in the browser from recorded data. No network calls.</span>
            </span>
          </label>
          <label className="flex items-start gap-2">
            <input type="radio" name="assistant-mode" className="mt-1" checked={settings.assistant.mode === 'remote-proxy'} onChange={() => updateSettings({ assistant: { ...settings.assistant, mode: 'remote-proxy' } })} />
            <span>
              <span className="font-medium text-fg-strong">Remote LLM via your organization&apos;s backend proxy</span>
              <span className="block text-xs text-muted">The browser calls a same-origin endpoint only; the proxy holds API keys, enforces authentication, logging, and data-handling policy. See docs/AI-ASSISTANT.md.</span>
            </span>
          </label>
        </fieldset>
        {settings.assistant.mode === 'remote-proxy' && (
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <Field label="Proxy endpoint (same-origin path)" htmlFor="s-endpoint" hint={endpointError ?? 'Valid.'}>
              <DeferredInput id="s-endpoint" value={settings.assistant.endpoint} maxLength={200} placeholder="/api/assistant" aria-invalid={!!endpointError} onCommit={(v) => updateSettings({ assistant: { ...settings.assistant, endpoint: v.trim() } })} />
            </Field>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={settings.assistant.consent} onChange={(e) => updateSettings({ assistant: { ...settings.assistant, consent: e.target.checked } })} />
              <span>
                I confirm my organization approved sending minimized investigation data (evidence, timeline, findings) to this proxy for assistant requests. Requests are only sent when I click a remote action.
              </span>
            </label>
          </div>
        )}
        <p className="mt-3 text-xs text-faint">The assistant is advisory: it cannot change status, close incidents, disable accounts, isolate hosts, or run commands. Alert and log text is treated as untrusted data.</p>
      </Card>

      <Card title="Data and storage">
        <Callout tone="warning" title="Browser storage limitations" className="mb-3">
          Investigations, local playbooks, and preferences are stored unencrypted in this browser&apos;s localStorage (~{Math.round(app.storage.usage() / 1024)} KB used of a typical 5 MB quota). They are not shared, not backed up, readable by scripts on this origin, and lost if site data is cleared. Do not store credentials or unnecessary sensitive incident data. Production deployments must use the secured backend described in docs/PRODUCTION.md.
        </Callout>
        <p className="mb-2 text-xs text-muted">
          Keys: {Object.values(KEYS).join(', ')}. Records that fail validation on load are set aside under a <span className="font-mono">.rejected</span> key instead of being deleted.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={exportAll}>
            Export backup (JSON)
          </Button>
          <Button size="sm" onClick={() => { app.loadDemoData(); notify('Demo investigations loaded (marked DEMO).', 'success'); }}>
            Load demo data
          </Button>
          <Button size="sm" onClick={() => { app.removeDemoData(); notify('Demo investigations removed.', 'success'); }} disabled={!app.investigations.some((i) => i.demo)}>
            Remove demo data
          </Button>
          <Button
            size="sm"
            variant="danger"
            icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />}
            onClick={() => {
              if (window.confirm('Delete ALL investigations in this browser? Export a backup first if needed.')) {
                app.replaceInvestigations([]);
                notify('All investigations deleted.', 'warning');
              }
            }}
          >
            Delete all investigations
          </Button>
          <Button
            size="sm"
            variant="danger"
            onClick={() => {
              if (window.confirm('Delete all locally authored playbooks and revisions? Starter playbooks remain.')) {
                app.replaceLocalPlaybooks([]);
                notify('Local playbooks removed.', 'warning');
              }
            }}
          >
            Reset local playbooks
          </Button>
          <Button
            size="sm"
            variant="danger"
            onClick={async () => {
              if (!window.confirm('Reset everything (investigations, local playbooks, settings, downloaded ATT&CK update) and reload?')) return;
              for (const k of Object.values(KEYS)) {
                app.storage.remove(k);
                app.storage.remove(`${k}.rejected`);
              }
              app.storage.write(KEYS.settings, JSON.stringify({ ...DEFAULT_SETTINGS, demoSeeded: true }));
              await revertToBundled().catch(() => undefined);
              window.location.reload();
            }}
          >
            Reset everything
          </Button>
        </div>
      </Card>
    </div>
  );
}

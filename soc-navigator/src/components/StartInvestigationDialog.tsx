import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { PlayCircle } from 'lucide-react';
import { parseAlert } from '../lib/alertParse';
import type { ParsedAlert } from '../lib/alertParse';
import { SEVERITIES, setEvidence } from '../lib/investigations/model';
import type { Severity } from '../lib/investigations/model';
import { useApp } from '../state/AppState';
import { PlaybookStatusBadge } from './badges';
import { Button, Callout, Dialog, Field } from './ui';

export function StartInvestigationDialog({ open, onClose, playbookId }: { open: boolean; onClose: () => void; playbookId?: string }) {
  const { library, playbookById, createInvestigation, updateInvestigation, settings, notify } = useApp();
  const [raw, setRaw] = useState('');
  const [parsed, setParsed] = useState<ParsedAlert | null>(null);
  const navigate = useNavigate();
  const [pbId, setPbId] = useState(playbookId ?? library[0]?.playbook.id ?? '');
  const [alertRef, setAlertRef] = useState('');
  const [title, setTitle] = useState('');
  const [source, setSource] = useState('');
  const [severity, setSeverity] = useState<Severity>('Medium');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setPbId(playbookId ?? library[0]?.playbook.id ?? '');
      setAlertRef('');
      setTitle('');
      setSource('');
      setSeverity('Medium');
      setError(null);
      setRaw('');
      setParsed(null);
    }
  }, [open, playbookId, library]);

  const pb = playbookById.get(pbId);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pb) return setError('Choose a playbook.');
    if (!alertRef.trim()) return setError('Enter the alert or ticket reference so the investigation can be traced.');
    const inv = createInvestigation({ playbook: pb, alertRef, title, alertSource: source, severity, analyst: settings.analystName });
    if (parsed) {
      const fields = new Set(pb.evidence.map((e) => e.id));
      const usable = Object.entries(parsed.evidence).filter(([k]) => fields.has(k));
      if (usable.length) updateInvestigation(inv.id, (i) => usable.reduce((acc, [k, v]) => setEvidence(acc, k, v), i));
    }
    notify(`Investigation ${inv.id} started.`, 'success');
    onClose();
    navigate(`/investigations/${inv.id}`);
  };

  const readAlert = () => {
    const p = parseAlert(raw, library.map((e) => e.playbook));
    setParsed(p);
    if (p.alertRef && !alertRef) setAlertRef(p.alertRef);
    if (p.title && !title) setTitle(p.title);
    if (p.source && !source) setSource(p.source);
    if (p.severity) setSeverity(p.severity);
    if (!playbookId && p.suggestions[0]) setPbId(p.suggestions[0].playbookId);
  };

  return (
    <Dialog open={open} onClose={onClose} title="Start an investigation" wide>
      <form onSubmit={submit} className="space-y-3" noValidate>
        <details className="rounded-md border border-line bg-panel-2 p-3">
          <summary className="cursor-pointer text-sm font-medium text-fg-strong">Paste the alert to pre-fill (optional)</summary>
          <div className="mt-2 space-y-2">
            <label htmlFor="si-raw" className="sr-only">
              Alert JSON or text
            </label>
            <textarea id="si-raw" className="input font-mono text-xs" rows={5} value={raw} onChange={(e) => setRaw(e.target.value)} placeholder="Paste alert JSON or key: value text from your SIEM/EDR. It is read in your browser only and treated as untrusted data." />
            <Button size="sm" onClick={readAlert} disabled={!raw.trim()}>
              Read alert
            </Button>
            {parsed && (
              <div className="space-y-1 text-xs" aria-live="polite">
                {parsed.warnings.map((w) => (
                  <p key={w} className="text-warn">
                    {w}
                  </p>
                ))}
                <p className="text-muted">
                  Recognized {Object.keys(parsed.evidence).length} field(s){Object.keys(parsed.evidence).length ? `: ${Object.keys(parsed.evidence).join(', ')}` : ''}. Fields the chosen playbook uses are copied into its evidence checklist - check them before relying on them.
                </p>
                {parsed.suggestions.length > 0 && (
                  <ul className="space-y-0.5">
                    {parsed.suggestions.map((s) => (
                      <li key={s.playbookId}>
                        <button type="button" className="text-accent hover:underline" onClick={() => setPbId(s.playbookId)}>
                          Suggested: {playbookById.get(s.playbookId)?.title ?? s.playbookId}
                        </button>{' '}
                        <span className="text-faint">({s.reasons.join('; ')})</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </details>
        <Field label="Playbook" htmlFor="si-playbook" required>
          <select id="si-playbook" className="input" value={pbId} onChange={(e) => setPbId(e.target.value)}>
            {library.map((e) => (
              <option key={e.playbook.id} value={e.playbook.id}>
                {e.playbook.id} - {e.playbook.title} ({e.playbook.status})
              </option>
            ))}
          </select>
        </Field>
        {pb && pb.status !== 'Approved' && (
          <Callout tone="warning" title={<span className="inline-flex items-center gap-2">This playbook is <PlaybookStatusBadge status={pb.status} /></span>}>
            Follow your organization&apos;s procedures where they differ from this guidance.
          </Callout>
        )}
        <Field label="Alert / ticket reference" htmlFor="si-alert" required hint="Copy the alert ID from your SIEM/EDR. Avoid pasting sensitive data you do not need.">
          <input id="si-alert" className="input" maxLength={200} value={alertRef} onChange={(e) => setAlertRef(e.target.value)} autoFocus />
        </Field>
        <Field label="Short title (optional)" htmlFor="si-title">
          <input id="si-title" className="input" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} placeholder={pb?.title} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Alert source" htmlFor="si-source">
            <input id="si-source" className="input" maxLength={200} value={source} onChange={(e) => setSource(e.target.value)} placeholder="e.g. Defender XDR" />
          </Field>
          <Field label="Severity" htmlFor="si-sev">
            <select id="si-sev" className="input" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        </div>
        <p className="text-xs text-faint">Analyst: {settings.analystName}. Progress is stored in this browser only (see Settings).</p>
        {error && (
          <p role="alert" className="text-sm text-bad">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" icon={<PlayCircle className="h-4 w-4" aria-hidden />}>
            Start investigation
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

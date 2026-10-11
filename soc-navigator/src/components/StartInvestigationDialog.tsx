import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { PlayCircle } from 'lucide-react';
import { SEVERITIES } from '../lib/investigations/model';
import type { Severity } from '../lib/investigations/model';
import { useApp } from '../state/AppState';
import { PlaybookStatusBadge } from './badges';
import { Button, Callout, Dialog, Field } from './ui';

export function StartInvestigationDialog({ open, onClose, playbookId }: { open: boolean; onClose: () => void; playbookId?: string }) {
  const { library, playbookById, createInvestigation, settings, notify } = useApp();
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
    }
  }, [open, playbookId, library]);

  const pb = playbookById.get(pbId);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pb) return setError('Choose a playbook.');
    if (!alertRef.trim()) return setError('Enter the alert or ticket reference so the investigation can be traced.');
    const inv = createInvestigation({ playbook: pb, alertRef, title, alertSource: source, severity, analyst: settings.analystName });
    notify(`Investigation ${inv.id} started.`, 'success');
    onClose();
    navigate(`/investigations/${inv.id}`);
  };

  return (
    <Dialog open={open} onClose={onClose} title="Start an investigation">
      <form onSubmit={submit} className="space-y-3" noValidate>
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

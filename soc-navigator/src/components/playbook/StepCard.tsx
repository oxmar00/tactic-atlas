import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { PlaybookStep, QueryTemplate } from '../../lib/playbooks/schema';
import { DeferredTextArea, cx } from '../ui';
import { QueryCard } from './QueryCard';

export interface StepState {
  done: boolean;
  notes: string;
}

/**
 * One numbered investigation step. In reader mode it is read-only; in workspace mode it shows a
 * completion checkbox and notes field that persist to the investigation.
 */
export function StepCard({
  step,
  number,
  queries,
  state,
  onToggle,
  onNotes,
  evidence,
  defaultOpen = false,
  playbookId,
}: {
  step: PlaybookStep;
  number: number;
  queries: QueryTemplate[];
  state?: StepState;
  onToggle?: (done: boolean) => void;
  onNotes?: (notes: string) => void;
  evidence?: Record<string, string>;
  defaultOpen?: boolean;
  playbookId: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const interactive = !!onToggle;
  const checkboxId = `step-${playbookId}-${step.id}`;
  return (
    <li className={cx('rounded-lg border bg-panel', state?.done ? 'border-ok/40' : 'border-line')}>
      <div className="flex items-start gap-3 px-3 py-2.5">
        {interactive ? (
          <input
            id={checkboxId}
            type="checkbox"
            className="mt-1 h-4 w-4 shrink-0 accent-[var(--color-ok)]"
            checked={!!state?.done}
            onChange={(e) => onToggle?.(e.target.checked)}
            aria-label={`Mark step ${number} complete: ${step.title}`}
          />
        ) : (
          <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-panel-3 text-xs font-semibold text-muted">{number}</span>
        )}
        <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-controls={`${checkboxId}-body`}>
          <span className={cx('block font-medium', state?.done ? 'text-muted line-through decoration-ok/60' : 'text-fg-strong')}>
            {interactive && <span className="mr-1 text-faint">Step {number} -</span>}
            {step.title}
          </span>
          <span className="mt-0.5 block text-sm text-muted">{step.action}</span>
        </button>
        <button type="button" onClick={() => setOpen((o) => !o)} className="rounded p-1 text-muted hover:bg-panel-2" aria-label={open ? 'Collapse step details' : 'Expand step details'} aria-expanded={open}>
          {open ? <ChevronDown className="h-4 w-4" aria-hidden /> : <ChevronRight className="h-4 w-4" aria-hidden />}
        </button>
      </div>
      {open && (
        <div id={`${checkboxId}-body`} className="space-y-3 border-t border-line px-3 py-3 text-sm">
          <Detail label="Why this matters">{step.why}</Detail>
          <div className="grid gap-3 md:grid-cols-2">
            <ListDetail label="Where to investigate" items={step.where} />
            {step.fields.length > 0 && <ListDetail label="Fields and events to inspect" items={step.fields} mono />}
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <ListDetail label="Suspicious if" items={step.suspicious} tone="bad" />
            {step.legitimate.length > 0 && <ListDetail label="Possible legitimate explanation" items={step.legitimate} tone="ok" />}
          </div>
          <Detail label="What to do next">{step.next}</Detail>
          {queries.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold tracking-wide text-muted uppercase">Queries for this step</p>
              {queries.map((q) => (
                <QueryCard key={q.id} query={q} evidence={evidence} playbookId={`${playbookId}-${step.id}`} />
              ))}
            </div>
          )}
          {onNotes && (
            <div>
              <label htmlFor={`${checkboxId}-notes`} className="label">
                Step notes (optional)
              </label>
              <DeferredTextArea id={`${checkboxId}-notes`} value={state?.notes ?? ''} onCommit={onNotes} rows={2} maxLength={8000} placeholder="What you checked, where, and what you found." />
            </div>
          )}
        </div>
      )}
    </li>
  );
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold tracking-wide text-muted uppercase">{label}</p>
      <p className="mt-0.5 text-fg">{children}</p>
    </div>
  );
}

function ListDetail({ label, items, tone, mono }: { label: string; items: string[]; tone?: 'ok' | 'bad'; mono?: boolean }) {
  return (
    <div className={cx('rounded-md border p-2', tone === 'bad' ? 'border-bad/30 bg-bad/5' : tone === 'ok' ? 'border-ok/30 bg-ok/5' : 'border-line bg-panel-2')}>
      <p className={cx('text-xs font-semibold tracking-wide uppercase', tone === 'bad' ? 'text-bad' : tone === 'ok' ? 'text-ok' : 'text-muted')}>{label}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-4">
        {items.map((i) => (
          <li key={i} className={cx(mono && 'font-mono text-xs break-words')}>
            {i}
          </li>
        ))}
      </ul>
    </div>
  );
}

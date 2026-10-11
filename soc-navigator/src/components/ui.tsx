import { forwardRef, useEffect, useId, useRef, useState } from 'react';
import type { ButtonHTMLAttributes, KeyboardEvent, ReactNode } from 'react';
import { AlertTriangle, Check, CheckCircle2, ClipboardCopy, Info, ShieldAlert, XCircle } from 'lucide-react';
import { GLOSSARY } from '../data/glossary';

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ');
}

// --- Buttons ---------------------------------------------------------------------------------

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
const VARIANT: Record<Variant, string> = {
  primary: 'bg-accent-strong text-white hover:bg-accent border-transparent',
  secondary: 'bg-panel-2 text-fg hover:bg-panel-3 border-line',
  ghost: 'bg-transparent text-muted hover:text-fg hover:bg-panel-2 border-transparent',
  danger: 'bg-transparent text-bad hover:bg-bad/10 border-bad/40',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: 'sm' | 'md';
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, className, children, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 rounded-md border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm',
        VARIANT[variant],
        className,
      )}
      {...rest}
    >
      {icon}
      {children}
    </button>
  );
});

// --- Badges ----------------------------------------------------------------------------------

export type BadgeTone = 'neutral' | 'accent' | 'ok' | 'warn' | 'bad' | 'info' | 'violet';
const TONE: Record<BadgeTone, string> = {
  neutral: 'bg-panel-3 text-muted border-line',
  accent: 'bg-accent/10 text-accent border-accent/30',
  ok: 'bg-ok/10 text-ok border-ok/30',
  warn: 'bg-warn/10 text-warn border-warn/30',
  bad: 'bg-bad/10 text-bad border-bad/30',
  info: 'bg-info/10 text-info border-info/30',
  violet: 'bg-violet/10 text-violet border-violet/30',
};

export function Badge({ tone = 'neutral', children, className, title }: { tone?: BadgeTone; children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cx('inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] leading-none font-medium whitespace-nowrap', TONE[tone], className)}>
      {children}
    </span>
  );
}

// --- Layout helpers --------------------------------------------------------------------------

export function Card({ children, className, title, actions, id }: { children: ReactNode; className?: string; title?: ReactNode; actions?: ReactNode; id?: string }) {
  return (
    <section id={id} className={cx('rounded-lg border border-line bg-panel', className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          {title && <h2 className="text-sm font-semibold text-fg-strong">{title}</h2>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions, icon }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="flex items-center gap-2 text-xl font-semibold text-fg-strong">
          {icon}
          {title}
        </h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-line px-6 py-10 text-center">
      {icon && <div className="mb-3 text-faint">{icon}</div>}
      <p className="font-medium text-fg-strong">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

const CALLOUT: Record<'info' | 'warning' | 'danger' | 'success', { cls: string; icon: ReactNode }> = {
  info: { cls: 'border-info/30 bg-info/5 text-fg', icon: <Info className="h-4 w-4 shrink-0 text-info" aria-hidden /> },
  warning: { cls: 'border-warn/40 bg-warn/5 text-fg', icon: <AlertTriangle className="h-4 w-4 shrink-0 text-warn" aria-hidden /> },
  danger: { cls: 'border-bad/40 bg-bad/5 text-fg', icon: <ShieldAlert className="h-4 w-4 shrink-0 text-bad" aria-hidden /> },
  success: { cls: 'border-ok/40 bg-ok/5 text-fg', icon: <CheckCircle2 className="h-4 w-4 shrink-0 text-ok" aria-hidden /> },
};

export function Callout({ tone = 'info', title, children, className }: { tone?: keyof typeof CALLOUT; title?: ReactNode; children?: ReactNode; className?: string }) {
  const c = CALLOUT[tone];
  return (
    <div role={tone === 'danger' ? 'alert' : undefined} className={cx('flex gap-2.5 rounded-md border px-3 py-2.5 text-sm', c.cls, className)}>
      {c.icon}
      <div className="min-w-0">
        {title && <p className="font-medium text-fg-strong">{title}</p>}
        {children && <div className={cx(title ? 'mt-0.5' : null, 'text-muted')}>{children}</div>}
      </div>
    </div>
  );
}

export function ProgressBar({ value, label }: { value: number; label: string }) {
  const v = Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel-3" role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
        <div className={cx('h-full rounded-full', v === 100 ? 'bg-ok' : 'bg-accent')} style={{ width: `${v}%` }} />
      </div>
      <span className="w-10 text-right text-xs tabular-nums text-muted">{v}%</span>
    </div>
  );
}

// --- Forms -----------------------------------------------------------------------------------

export function Field({ label, hint, children, htmlFor, required }: { label: ReactNode; hint?: ReactNode; children: ReactNode; htmlFor?: string; required?: boolean }) {
  return (
    <div>
      <label htmlFor={htmlFor} className="label">
        {label}
        {required && (
          <span className="ml-1 text-warn" aria-label="required">
            *
          </span>
        )}
      </label>
      {children}
      {hint && <p className="mt-1 text-xs text-faint">{hint}</p>}
    </div>
  );
}

/** Textarea whose local state commits on blur/debounce to avoid a storage write per keystroke. */
export function DeferredTextArea({
  value,
  onCommit,
  className,
  rows = 3,
  ...rest
}: { value: string; onCommit: (v: string) => void; rows?: number; className?: string } & Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, 'value' | 'onChange'>) {
  const [local, setLocal] = useState(value);
  const timer = useRef<number | undefined>(undefined);
  const latest = useRef(value);
  useEffect(() => {
    if (value !== latest.current) {
      latest.current = value;
      setLocal(value);
    }
  }, [value]);
  const commit = (v: string) => {
    window.clearTimeout(timer.current);
    if (v !== latest.current) {
      latest.current = v;
      onCommit(v);
    }
  };
  return (
    <textarea
      {...rest}
      rows={rows}
      className={cx('input resize-y', className)}
      value={local}
      onChange={(e) => {
        const v = e.target.value;
        setLocal(v);
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => commit(v), 600);
      }}
      onBlur={(e) => commit(e.target.value)}
    />
  );
}

export function DeferredInput({ value, onCommit, className, ...rest }: { value: string; onCommit: (v: string) => void; className?: string } & Omit<React.InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange'>) {
  const [local, setLocal] = useState(value);
  const latest = useRef(value);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (value !== latest.current) {
      latest.current = value;
      setLocal(value);
    }
  }, [value]);
  const commit = (v: string) => {
    window.clearTimeout(timer.current);
    if (v !== latest.current) {
      latest.current = v;
      onCommit(v);
    }
  };
  return (
    <input
      {...rest}
      className={cx('input', className)}
      value={local}
      onChange={(e) => {
        const v = e.target.value;
        setLocal(v);
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => commit(v), 600);
      }}
      onBlur={(e) => commit(e.target.value)}
    />
  );
}

// --- Tabs ------------------------------------------------------------------------------------

export function Tabs<T extends string>({ tabs, value, onChange, label }: { tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (id: T) => void; label: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    let next = i;
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    else return;
    e.preventDefault();
    onChange(tabs[next].id);
    refs.current[next]?.focus();
  };
  return (
    <div role="tablist" aria-label={label} className="flex flex-wrap gap-1 border-b border-line">
      {tabs.map((t, i) => (
        <button
          key={t.id}
          ref={(el) => {
            refs.current[i] = el;
          }}
          role="tab"
          type="button"
          id={`tab-${t.id}`}
          aria-selected={value === t.id}
          aria-controls={`panel-${t.id}`}
          tabIndex={value === t.id ? 0 : -1}
          onKeyDown={(e) => onKey(e, i)}
          onClick={() => onChange(t.id)}
          className={cx(
            '-mb-px border-b-2 px-3 py-2 text-sm font-medium',
            value === t.id ? 'border-accent text-fg-strong' : 'border-transparent text-muted hover:text-fg',
          )}
        >
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 rounded bg-panel-3 px-1.5 text-xs text-muted">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function TabPanel({ id, children, className }: { id: string; children: ReactNode; className?: string }) {
  return (
    <div role="tabpanel" id={`panel-${id}`} aria-labelledby={`tab-${id}`} className={className}>
      {children}
    </div>
  );
}

// --- Copy ------------------------------------------------------------------------------------

export function CopyButton({ text, label = 'Copy', className, onCopied }: { text: string; label?: string; className?: string; onCopied?: () => void }) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle');
  const copy = async () => {
    try {
      if (!navigator.clipboard) throw new Error('no clipboard');
      await navigator.clipboard.writeText(text);
      setState('done');
      onCopied?.();
    } catch {
      setState('failed');
    }
    window.setTimeout(() => setState('idle'), 2000);
  };
  return (
    <Button
      size="sm"
      variant="secondary"
      className={className}
      onClick={copy}
      icon={state === 'done' ? <Check className="h-3.5 w-3.5 text-ok" aria-hidden /> : state === 'failed' ? <XCircle className="h-3.5 w-3.5 text-bad" aria-hidden /> : <ClipboardCopy className="h-3.5 w-3.5" aria-hidden />}
      aria-live="polite"
    >
      {state === 'done' ? 'Copied' : state === 'failed' ? 'Copy blocked - select text manually' : label}
    </Button>
  );
}

// --- Terminology tooltip ---------------------------------------------------------------------

export function Term({ term, children }: { term: string; children?: ReactNode }) {
  const id = useId();
  const def = GLOSSARY[term];
  if (!def) return <>{children ?? term}</>;
  return (
    <span className="group relative inline-block">
      <span tabIndex={0} aria-describedby={id} className="cursor-help border-b border-dotted border-muted">
        {children ?? term}
      </span>
      <span
        role="tooltip"
        id={id}
        className="pointer-events-none invisible absolute bottom-full left-0 z-50 mb-1.5 w-72 rounded-md border border-line-strong bg-panel-3 p-2.5 text-xs leading-relaxed font-normal text-fg normal-case opacity-0 shadow-xl transition-opacity group-focus-within:visible group-focus-within:opacity-100 group-hover:visible group-hover:opacity-100"
      >
        <span className="font-semibold text-fg-strong">{term}: </span>
        {def}
      </span>
    </span>
  );
}

// --- Dialog ----------------------------------------------------------------------------------

export function Dialog({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      aria-labelledby="dialog-title"
      className={cx('m-auto rounded-lg border border-line-strong bg-panel p-0 text-fg shadow-2xl', wide ? 'w-[min(56rem,95vw)]' : 'w-[min(32rem,95vw)]')}
    >
      {open && (
        <div className="p-5">
          <h2 id="dialog-title" className="mb-4 text-lg font-semibold text-fg-strong">
            {title}
          </h2>
          {children}
        </div>
      )}
    </dialog>
  );
}

// --- Misc ------------------------------------------------------------------------------------

export function DemoBadge() {
  return (
    <Badge tone="violet" title="Fictional sample data - not real telemetry">
      DEMO
    </Badge>
  );
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

export function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff)) return iso;
  const m = Math.round(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} d ago`;
}

export function downloadFile(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename.replace(/[^A-Za-z0-9._-]/g, '_');
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

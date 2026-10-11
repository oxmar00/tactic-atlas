import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Terminal } from 'lucide-react';
import type { QueryTemplate } from '../../lib/playbooks/schema';
import { LANGUAGE_LABEL, fillQuery, suggestFromEvidence, validatePlaceholder } from '../../lib/queries';
import { Badge, CopyButton, cx } from '../ui';

/**
 * Query template with placeholder form, live filled preview, and copy. The app never executes
 * queries - analysts copy them into their own SIEM.
 */
export function QueryCard({ query, evidence, defaultOpen = false, playbookId }: { query: QueryTemplate; evidence?: Record<string, string>; defaultOpen?: boolean; playbookId?: string }) {
  const [open, setOpen] = useState(defaultOpen);
  const suggested = useMemo(() => suggestFromEvidence(query.placeholders, evidence ?? {}), [query.placeholders, evidence]);
  const [values, setValues] = useState<Record<string, string>>({});
  const merged = { ...suggested, ...values };
  const filled = fillQuery(query, merged);
  const tone = query.language === 'kql' ? 'accent' : query.language === 'spl' ? 'violet' : 'neutral';
  const panelId = `q-${playbookId ?? 'x'}-${query.id}`;

  return (
    <div className="rounded-md border border-line bg-panel-2">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-controls={panelId} className="flex w-full items-start gap-2 px-3 py-2 text-left">
        {open ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden />}
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone={tone}>{query.language.toUpperCase()}</Badge>
            <span className="font-medium text-fg-strong">{query.title}</span>
          </span>
          <span className="mt-0.5 block text-xs text-muted">{query.platform}</span>
        </span>
      </button>
      {open && (
        <div id={panelId} className="space-y-3 border-t border-line px-3 py-3 text-sm">
          <p>{query.purpose}</p>
          <p className="text-xs text-muted">
            <span className="font-semibold text-fg">Data sources:</span> {query.dataSources.join(', ')}
          </p>
          {query.placeholders.length > 0 && (
            <fieldset className="rounded-md border border-line p-2.5">
              <legend className="px-1 text-xs font-semibold text-muted">Fill placeholders (values are escaped; nothing is sent anywhere)</legend>
              <div className="grid gap-2 sm:grid-cols-2">
                {query.placeholders.map((p) => {
                  const v = merged[p.name] ?? '';
                  const problem = v ? validatePlaceholder(p, v) : null;
                  const id = `${panelId}-${p.name}`;
                  return (
                    <div key={p.name}>
                      <label htmlFor={id} className="mb-0.5 block font-mono text-xs text-accent">
                        {`{{${p.name}}}`}
                        {suggested[p.name] && !values[p.name] && <span className="ml-1 font-sans text-faint">(from evidence)</span>}
                      </label>
                      <input
                        id={id}
                        className={cx('input py-1 text-xs', problem && 'border-bad')}
                        placeholder={`e.g. ${p.example}`}
                        value={v}
                        maxLength={300}
                        aria-invalid={!!problem}
                        aria-describedby={`${id}-help`}
                        onChange={(e) => setValues((s) => ({ ...s, [p.name]: e.target.value }))}
                      />
                      <p id={`${id}-help`} className={cx('mt-0.5 text-[11px]', problem ? 'text-bad' : 'text-faint')}>
                        {problem ?? p.description}
                      </p>
                    </div>
                  );
                })}
              </div>
            </fieldset>
          )}
          <div>
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="flex items-center gap-1 text-xs text-muted">
                <Terminal className="h-3.5 w-3.5" aria-hidden /> {LANGUAGE_LABEL[query.language]}
                {filled.unresolved.length > 0 && <span className="text-warn"> - {filled.unresolved.length} placeholder(s) not filled</span>}
              </span>
              <CopyButton text={filled.text} label={query.language === 'generic' ? 'Copy procedure' : 'Copy query'} />
            </div>
            <pre className="scroll-thin max-h-80 overflow-auto rounded-md border border-line bg-bg p-3 text-[12px] leading-relaxed whitespace-pre text-fg">
              <code>{filled.text}</code>
            </pre>
          </div>
          {query.keyFields.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold text-muted">Important fields</p>
              <dl className="grid gap-x-3 gap-y-1 text-xs sm:grid-cols-[minmax(0,12rem)_1fr]">
                {query.keyFields.map((f) => (
                  <div key={f.name} className="contents">
                    <dt className="font-mono text-accent">{f.name}</dt>
                    <dd className="text-fg">{f.meaning}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="rounded-md border border-ok/30 bg-ok/5 p-2 text-xs">
              <p className="mb-0.5 font-semibold text-ok">If results are returned</p>
              <p>{query.positive}</p>
            </div>
            <div className="rounded-md border border-info/30 bg-info/5 p-2 text-xs">
              <p className="mb-0.5 font-semibold text-info">If nothing is returned</p>
              <p>{query.negative}</p>
            </div>
          </div>
          <p className="text-xs">
            <span className="font-semibold text-muted">Permissions and telemetry: </span>
            {query.prerequisites}
          </p>
          <p className="text-xs">
            <span className="font-semibold text-muted">Schema notes: </span>
            {query.schemaNotes}
          </p>
          {query.example && (
            <p className="text-xs">
              <span className="font-semibold text-muted">Safe example values: </span>
              {query.example}
            </p>
          )}
          <p className="text-[11px] text-faint">Template only - SOC Navigator has not executed this query against any data source.</p>
        </div>
      )}
    </div>
  );
}

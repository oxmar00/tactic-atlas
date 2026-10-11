import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Database } from 'lucide-react';
import { QueryCard } from '../components/playbook/QueryCard';
import { Badge, Callout, EmptyState, PageHeader, TabPanel, Tabs, cx } from '../components/ui';
import { GLOSSARY } from '../data/glossary';
import { LOG_SOURCES, WINDOWS_EVENT_REFERENCE } from '../data/logSources';
import { QUERY_LANGUAGES } from '../lib/playbooks/schema';
import { LANGUAGE_LABEL } from '../lib/queries';
import { useApp } from '../state/AppState';

type RefTab = 'sources' | 'queries' | 'events' | 'glossary';

export function ReferencePage() {
  const [params, setParams] = useSearchParams();
  const initial = (params.get('tab') as RefTab) || 'sources';
  const [tab, setTab] = useState<RefTab>(initial);
  const focusSource = params.get('source');
  useEffect(() => {
    if (focusSource) {
      setTab('sources');
      window.setTimeout(() => document.getElementById(`src-${focusSource}`)?.scrollIntoView({ block: 'start' }), 50);
    }
  }, [focusSource]);

  return (
    <div className="space-y-4">
      <PageHeader
        icon={<Database className="h-5 w-5 text-accent" aria-hidden />}
        title="Detection and Log Reference"
        subtitle="Where evidence lives, what each source records, its common gaps, and query templates for Microsoft Sentinel / Defender XDR (KQL), Splunk (SPL), and platform-neutral procedures."
      />
      <Callout tone="info">
        Table names, sourcetypes, and field names are documented defaults. They vary by collector, add-on version, and normalization (CIM/ASIM) - confirm them in your environment. SOC Navigator does not run queries.
      </Callout>
      <Tabs
        label="Reference sections"
        value={tab}
        onChange={(t) => {
          setTab(t);
          setParams(t === 'sources' ? {} : { tab: t }, { replace: true });
        }}
        tabs={[
          { id: 'sources', label: 'Log sources', count: LOG_SOURCES.length },
          { id: 'queries', label: 'Query library' },
          { id: 'events', label: 'Windows event IDs', count: WINDOWS_EVENT_REFERENCE.length },
          { id: 'glossary', label: 'Glossary', count: Object.keys(GLOSSARY).length },
        ]}
      />
      <TabPanel id={tab}>
        {tab === 'sources' && <Sources focus={focusSource} />}
        {tab === 'queries' && <QueryLibrary />}
        {tab === 'events' && <Events />}
        {tab === 'glossary' && <Glossary />}
      </TabPanel>
    </div>
  );
}

function Sources({ focus }: { focus: string | null }) {
  const { library } = useApp();
  const [cat, setCat] = useState('');
  const cats = [...new Set(LOG_SOURCES.map((s) => s.category))];
  return (
    <div className="space-y-3 pt-2">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by category">
        {['', ...cats].map((c) => (
          <button key={c || 'all'} type="button" onClick={() => setCat(c)} aria-pressed={cat === c} className={cx('rounded-full border px-2.5 py-0.5 text-xs', cat === c ? 'border-accent bg-accent/10 text-fg-strong' : 'border-line text-muted hover:text-fg')}>
            {c || 'All'}
          </button>
        ))}
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        {LOG_SOURCES.filter((s) => !cat || s.category === cat).map((s) => {
          const users = library.filter((e) => e.playbook.logSources.includes(s.id));
          return (
            <section key={s.id} id={`src-${s.id}`} className={cx('scroll-mt-20 rounded-lg border bg-panel p-4 text-sm', focus === s.id ? 'border-accent' : 'border-line')}>
              <header className="mb-2 flex flex-wrap items-center gap-2">
                <h2 className="font-semibold text-fg-strong">{s.name}</h2>
                <Badge>{s.category}</Badge>
              </header>
              <p className="text-muted">{s.description}</p>
              <h3 className="mt-3 mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Key events</h3>
              <ul className="space-y-0.5">
                {s.keyEvents.map((e) => (
                  <li key={e.id}>
                    <span className="font-mono text-xs text-accent">{e.id}</span> - {e.description}
                  </li>
                ))}
              </ul>
              <h3 className="mt-3 mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Key fields</h3>
              <p className="font-mono text-xs break-words">{s.keyFields.join(', ')}</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <div>
                  <h3 className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Microsoft Sentinel / Defender</h3>
                  <ul className="list-disc pl-4 text-xs">
                    {s.sentinel.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3 className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Splunk</h3>
                  <ul className="list-disc pl-4 text-xs">
                    {s.splunk.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <h3 className="mt-3 mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Prerequisites</h3>
              <ul className="list-disc pl-4 text-xs">
                {s.prerequisites.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
              <h3 className="mt-3 mb-1 text-xs font-semibold tracking-wide text-warn uppercase">Common gaps</h3>
              <ul className="list-disc pl-4 text-xs">
                {s.gaps.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
              {users.length > 0 && (
                <p className="mt-3 text-xs text-muted">
                  Used by:{' '}
                  {users.map((u, i) => (
                    <span key={u.playbook.id}>
                      {i > 0 && ', '}
                      <Link to={`/playbooks/${u.playbook.id}`} className="text-accent hover:underline">
                        {u.playbook.title}
                      </Link>
                    </span>
                  ))}
                </p>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}

function QueryLibrary() {
  const { library, settings } = useApp();
  const [lang, setLang] = useState<string>(settings.defaultLanguage);
  const [pbId, setPbId] = useState('');
  const [q, setQ] = useState('');
  const rows = useMemo(() => {
    const lower = q.trim().toLowerCase();
    return library.flatMap(({ playbook: p }) =>
      p.queries
        .filter((x) => (!lang || x.language === lang) && (!pbId || p.id === pbId))
        .filter((x) => !lower || [x.title, x.purpose, x.platform, ...x.dataSources, x.query].join(' ').toLowerCase().includes(lower))
        .map((x) => ({ p, x })),
    );
  }, [library, lang, pbId, q]);
  return (
    <div className="space-y-3 pt-2">
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[12rem] flex-1">
          <label htmlFor="ql-q" className="label">
            Search queries
          </label>
          <input id="ql-q" className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Table, field, event ID, keyword (e.g. SigninLogs, 4698, lsass)" />
        </div>
        <div>
          <label htmlFor="ql-lang" className="label">
            Language
          </label>
          <select id="ql-lang" className="input" value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="">All</option>
            {QUERY_LANGUAGES.map((l) => (
              <option key={l} value={l}>
                {LANGUAGE_LABEL[l]}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="ql-pb" className="label">
            Playbook
          </label>
          <select id="ql-pb" className="input" value={pbId} onChange={(e) => setPbId(e.target.value)}>
            <option value="">All playbooks</option>
            {library.map((e) => (
              <option key={e.playbook.id} value={e.playbook.id}>
                {e.playbook.title}
              </option>
            ))}
          </select>
        </div>
      </div>
      <p className="text-xs text-muted">{rows.length} query templates. The default language comes from Settings.</p>
      {rows.length === 0 ? (
        <EmptyState title="No queries match" />
      ) : (
        <ul className="space-y-2">
          {rows.map(({ p, x }) => (
            <li key={`${p.id}-${x.id}`}>
              <p className="mb-0.5 text-xs text-faint">
                <Link to={`/playbooks/${p.id}`} className="hover:text-accent hover:underline">
                  {p.title}
                </Link>
              </p>
              <QueryCard query={x} playbookId={`lib-${p.id}`} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Events() {
  return (
    <div className="overflow-x-auto pt-2">
      <table className="w-full text-left text-sm">
        <thead className="bg-panel-2 text-xs text-muted">
          <tr>
            <th className="px-3 py-2 font-medium">Event ID</th>
            <th className="px-3 py-2 font-medium">Log / channel</th>
            <th className="px-3 py-2 font-medium">Meaning</th>
            <th className="px-3 py-2 font-medium">Tier 1 notes</th>
          </tr>
        </thead>
        <tbody>
          {WINDOWS_EVENT_REFERENCE.map((e) => (
            <tr key={`${e.id}-${e.log}`} className="border-t border-line align-top">
              <td className="px-3 py-1.5 font-mono text-accent">{e.id}</td>
              <td className="px-3 py-1.5 text-xs">{e.log}</td>
              <td className="px-3 py-1.5">{e.meaning}</td>
              <td className="px-3 py-1.5 text-xs text-muted">{e.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-faint">Many of these events require specific audit policy settings. Absence of an event in your SIEM may mean it is not collected.</p>
    </div>
  );
}

function Glossary() {
  return (
    <dl className="grid gap-3 pt-2 md:grid-cols-2">
      {Object.entries(GLOSSARY).map(([k, v]) => (
        <div key={k} className="rounded-md border border-line bg-panel p-3 text-sm">
          <dt className="font-semibold text-fg-strong">{k}</dt>
          <dd className="mt-0.5 text-muted">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

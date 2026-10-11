import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { ChevronDown, ChevronRight, Download, Grid3x3, ListChecks, RefreshCw, X } from 'lucide-react';
import { CoverageBadge } from '../components/badges';
import { Button, Callout, EmptyState, PageHeader, cx, downloadFile } from '../components/ui';
import { buildLayer } from '../lib/attack/layer';
import type { Technique } from '../lib/attack/types';
import { coverageLevel } from '../lib/playbooks/library';
import type { CoverageLevel } from '../lib/playbooks/library';
import { useApp } from '../state/AppState';

const BORDER: Record<CoverageLevel, string> = {
  direct: 'border-l-ok',
  parent: 'border-l-info',
  sub: 'border-l-accent',
  none: 'border-l-line',
};

type PbFilter = 'all' | 'with' | 'without';

export function MatrixPage() {
  const { attack, coverage, openTechnique, notify, reloadAttack } = useApp();
  const index = attack.index;
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const tactic = params.get('tactic') ?? '';
  const platform = params.get('platform') ?? '';
  const dc = params.get('dc') ?? '';
  const pb = (params.get('pb') as PbFilter) || 'all';
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [expandAll, setExpandAll] = useState(false);
  const [selectMode, setSelectMode] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Deep link: /matrix?t=T1059.001 opens the details panel and expands the parent.
  useEffect(() => {
    const t = params.get('t');
    if (t && index?.get(t)) {
      openTechnique(t);
      const tech = index.get(t)!;
      if (tech.parentId) setExpanded((s) => new Set(s).add(tech.parentId!));
      const next = new URLSearchParams(params);
      next.delete('t');
      setParams(next, { replace: true });
    }
  }, [params, index, openTechnique, setParams]);

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const searchIds = useMemo(() => (index && q.trim() ? new Set(index.search(q, 2000).map((h) => h.technique.id)) : null), [index, q]);
  const filtersActive = !!(searchIds || platform || dc || pb !== 'all');

  const matches = useMemo(() => {
    if (!index) return (_t: Technique) => true;
    return (t: Technique) => {
      if (searchIds && !searchIds.has(t.id)) return false;
      if (platform && !t.platforms.includes(platform)) return false;
      if (dc && !t.dataComponents.includes(dc)) return false;
      if (pb !== 'all') {
        const level = coverageLevel(coverage?.get(t.id));
        const has = level === 'direct';
        if (pb === 'with' ? !has : has) return false;
      }
      return true;
    };
  }, [index, searchIds, platform, dc, pb, coverage]);

  const columns = useMemo(() => {
    if (!index) return [];
    return index.tactics
      .filter((t) => !tactic || t.shortname === tactic)
      .map((t) => {
        const rows = index
          .column(t.shortname)
          .map((parent) => {
            const subs = index.subtechniques(parent.id);
            const matchingSubs = subs.filter(matches);
            const selfMatch = matches(parent);
            return { parent, subs, matchingSubs, selfMatch, visible: selfMatch || matchingSubs.length > 0 };
          })
          .filter((r) => r.visible);
        return { tactic: t, rows };
      });
  }, [index, tactic, matches]);

  const visibleCount = columns.reduce((n, c) => n + c.rows.length, 0);

  if (attack.status === 'loading') return <p className="text-muted">Loading ATT&amp;CK Enterprise data...</p>;
  if (!index) {
    return (
      <div className="space-y-4">
        <PageHeader title="ATT&CK Enterprise Matrix" icon={<Grid3x3 className="h-5 w-5 text-accent" aria-hidden />} />
        <Callout tone="danger" title="ATT&CK data could not be loaded">
          <p>{attack.error}</p>
          <p className="mt-1">If you opened the built files directly from disk, serve them over HTTP (npm run preview). Playbooks and investigations remain available.</p>
        </Callout>
        <Button icon={<RefreshCw className="h-4 w-4" aria-hidden />} onClick={reloadAttack}>
          Retry
        </Button>
      </div>
    );
  }

  const toggleSelect = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const exportSelection = () => {
    const layer = buildLayer(index, 'SOC Navigator selection', `Techniques selected in SOC Navigator (${selected.size}).`, [...selected].map((id) => ({ id, score: 1, color: '#66b1ff' })));
    downloadFile('soc-navigator-selection-layer.json', JSON.stringify(layer, null, 2), 'application/json');
    notify(`Exported ${selected.size} technique(s) as an ATT&CK Navigator layer.`, 'success');
  };
  const exportCoverage = () => {
    const entries = index.dataset.techniques
      .map((t) => ({ t, level: coverageLevel(coverage?.get(t.id)) }))
      .filter((x) => x.level === 'direct' || x.level === 'parent')
      .map(({ t, level }) => ({
        id: t.id,
        score: level === 'direct' ? 1 : 0.5,
        color: level === 'direct' ? '#3fcf8e' : '#8fa8ff',
        comment: (level === 'direct' ? coverage?.get(t.id)?.direct : coverage?.get(t.id)?.viaParent)?.map((p) => `${p.id} (${p.status})`).join(', '),
      }));
    const layer = buildLayer(index, 'SOC Navigator playbook coverage', 'Techniques with an investigation playbook (green) or a parent-technique playbook (blue). Not detection coverage.', entries, [
      { label: 'Playbook available', color: '#3fcf8e' },
      { label: 'Parent-technique playbook', color: '#8fa8ff' },
    ]);
    downloadFile('soc-navigator-playbook-coverage-layer.json', JSON.stringify(layer, null, 2), 'application/json');
    notify('Exported playbook coverage as an ATT&CK Navigator layer.', 'success');
  };

  return (
    <div className="space-y-3">
      <PageHeader
        icon={<Grid3x3 className="h-5 w-5 text-accent" aria-hidden />}
        title="ATT&CK Enterprise Matrix"
        subtitle={`Official MITRE ATT&CK Enterprise v${index.dataset.meta.version}: ${index.dataset.meta.counts.tactics} tactics, ${index.dataset.meta.counts.techniques} techniques, ${index.dataset.meta.counts.subtechniques} sub-techniques. Select a technique for details and investigation guidance.`}
        actions={
          <>
            <Button size="sm" icon={<ListChecks className="h-4 w-4" aria-hidden />} onClick={() => setSelectMode((s) => !s)} aria-pressed={selectMode}>
              {selectMode ? 'Done selecting' : 'Select techniques'}
            </Button>
            {selectMode && (
              <Button size="sm" variant="primary" icon={<Download className="h-4 w-4" aria-hidden />} disabled={selected.size === 0} onClick={exportSelection}>
                Export selection layer ({selected.size})
              </Button>
            )}
            <Button size="sm" icon={<Download className="h-4 w-4" aria-hidden />} onClick={exportCoverage}>
              Export coverage layer
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap items-end gap-2 rounded-lg border border-line bg-panel p-3">
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="m-q" className="label">
            Search
          </label>
          <input id="m-q" className="input" placeholder="ID, name, keyword, or behavior (e.g. lsass, 4104, scheduled)" value={q} onChange={(e) => setParam('q', e.target.value)} />
        </div>
        <Select id="m-tactic" label="Tactic" value={tactic} onChange={(v) => setParam('tactic', v)} options={index.tactics.map((t) => [t.shortname, t.name])} />
        <Select id="m-platform" label="Platform" value={platform} onChange={(v) => setParam('platform', v)} options={index.platforms.map((p) => [p, p])} />
        <Select id="m-dc" label="Data source (component)" value={dc} onChange={(v) => setParam('dc', v)} options={index.dataComponents.map((d) => [d, d])} />
        <Select
          id="m-pb"
          label="Playbook"
          value={pb === 'all' ? '' : pb}
          onChange={(v) => setParam('pb', v)}
          allLabel="Any"
          options={[
            ['with', 'Has a playbook'],
            ['without', 'No direct playbook'],
          ]}
        />
        <Button size="sm" variant="ghost" onClick={() => setExpandAll((e) => !e)} aria-pressed={expandAll}>
          {expandAll ? 'Collapse sub-techniques' : 'Expand all sub-techniques'}
        </Button>
        {(filtersActive || tactic) && (
          <Button size="sm" variant="ghost" icon={<X className="h-3.5 w-3.5" aria-hidden />} onClick={() => setParams({}, { replace: true })}>
            Clear filters
          </Button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3 text-xs text-muted" aria-label="Legend">
        <span className="font-semibold">Legend:</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-1 rounded bg-ok" aria-hidden /><CoverageBadge level="direct" compact /> playbook for this technique</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-1 rounded bg-info" aria-hidden /><CoverageBadge level="parent" compact /> parent technique has a playbook</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-1 rounded bg-accent" aria-hidden /><CoverageBadge level="sub" compact /> a sub-technique has a playbook</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-1 rounded bg-line" aria-hidden />no playbook</span>
        <span className="ml-auto" title="A technique appears once under every tactic it belongs to.">{filtersActive ? `${visibleCount} matching cells` : `${visibleCount} technique cells`}</span>
      </div>

      {index.retiredMatch(q) && (
        <Callout tone="warning" title={`${q.toUpperCase()} is ${index.retiredMatch(q)!.status} in this ATT&CK release`}>
          {index.retiredMatch(q)!.replacedBy ? (
            <>
              It was replaced by{' '}
              <button type="button" className="text-accent hover:underline" onClick={() => openTechnique(index.retiredMatch(q)!.replacedBy!)}>
                {index.label(index.retiredMatch(q)!.replacedBy!)}
              </button>
              .
            </>
          ) : (
            'MITRE did not publish a replacement.'
          )}
        </Callout>
      )}

      {visibleCount === 0 ? (
        <EmptyState title="No techniques match these filters" action={<Button onClick={() => setParams({}, { replace: true })}>Clear filters</Button>}>
          Try a broader search term or remove a filter.
        </EmptyState>
      ) : (
        <div className="scroll-thin overflow-x-auto pb-3">
          <div className="flex min-w-max gap-2">
            {columns
              .filter((c) => c.rows.length > 0)
              .map(({ tactic: t, rows }) => (
                <section key={t.id} aria-labelledby={`col-${t.id}`} className="w-[11.5rem] shrink-0">
                  <header className="sticky top-0 mb-1.5 rounded-md border border-line bg-panel-2 px-2 py-1.5">
                    <h2 id={`col-${t.id}`} className="text-[13px] leading-tight font-semibold text-fg-strong">
                      <a href={t.url} target="_blank" rel="noopener noreferrer" className="hover:underline" title={`${t.id}: ${t.description.slice(0, 160)}`}>
                        {t.name}
                      </a>
                    </h2>
                    <p className="text-[11px] text-faint">
                      {t.id} - {rows.length} techniques
                    </p>
                  </header>
                  <ul className="space-y-1">
                    {rows.map(({ parent, subs, matchingSubs, selfMatch }) => {
                      const isOpen = expandAll || expanded.has(parent.id) || (filtersActive && matchingSubs.length > 0 && !selfMatch);
                      const shownSubs = isOpen ? (filtersActive ? matchingSubs : subs) : [];
                      return (
                        <li key={parent.id}>
                          <Cell t={parent} level={coverageLevel(coverage?.get(parent.id))} dim={filtersActive && !selfMatch} selectMode={selectMode} selected={selected.has(parent.id)} onSelect={toggleSelect} onOpen={openTechnique}>
                            {subs.length > 0 && (
                              <button
                                type="button"
                                onClick={() =>
                                  setExpanded((s) => {
                                    const n = new Set(s);
                                    if (n.has(parent.id)) n.delete(parent.id);
                                    else n.add(parent.id);
                                    return n;
                                  })
                                }
                                className="flex items-center gap-0.5 rounded px-1 text-[11px] text-muted hover:bg-panel-3 hover:text-fg"
                                aria-expanded={isOpen}
                                aria-label={`${isOpen ? 'Hide' : 'Show'} ${subs.length} sub-techniques of ${parent.name}`}
                              >
                                {isOpen ? <ChevronDown className="h-3 w-3" aria-hidden /> : <ChevronRight className="h-3 w-3" aria-hidden />}
                                {subs.length}
                              </button>
                            )}
                          </Cell>
                          {shownSubs.length > 0 && (
                            <ul className="mt-1 ml-2 space-y-1 border-l border-line pl-1.5">
                              {shownSubs.map((s) => (
                                <li key={s.id}>
                                  <Cell t={s} level={coverageLevel(coverage?.get(s.id))} sub selectMode={selectMode} selected={selected.has(s.id)} onSelect={toggleSelect} onOpen={openTechnique} />
                                </li>
                              ))}
                            </ul>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </section>
              ))}
          </div>
        </div>
      )}
      <p className="text-xs text-faint">
        Presence of a technique in ATT&amp;CK does not imply that your organization detects it. Data: MITRE ATT&amp;CK® Enterprise v{index.dataset.meta.version}, source {index.dataset.meta.sourceUrl.startsWith('https://') ? 'official attack-stix-data' : index.dataset.meta.sourceUrl}.
      </p>
    </div>
  );
}

function Cell({
  t,
  level,
  sub,
  dim,
  selectMode,
  selected,
  onSelect,
  onOpen,
  children,
}: {
  t: Technique;
  level: CoverageLevel;
  sub?: boolean;
  dim?: boolean;
  selectMode: boolean;
  selected: boolean;
  onSelect: (id: string) => void;
  onOpen: (id: string) => void;
  children?: React.ReactNode;
}) {
  return (
    <div className={cx('flex items-start gap-1 rounded border border-l-4 bg-panel px-1.5 py-1', BORDER[level], selected ? 'border-accent bg-accent/10' : 'border-y-line border-r-line', dim && 'opacity-50')}>
      {selectMode && (
        <input type="checkbox" className="mt-1 h-3.5 w-3.5 shrink-0" checked={selected} onChange={() => onSelect(t.id)} aria-label={`Select ${t.id} ${t.name}`} />
      )}
      <button type="button" onClick={() => onOpen(t.id)} className="min-w-0 flex-1 text-left" aria-label={`${t.id} ${t.name}${sub ? ' (sub-technique)' : ''}. ${level === 'none' ? 'No playbook' : level === 'direct' ? 'Playbook available' : level === 'parent' ? 'Parent-technique playbook' : 'Sub-technique playbook'}. Open details.`}>
        <span className="block font-mono text-[10px] text-faint">{t.id}</span>
        <span className={cx('block leading-tight', sub ? 'text-[11.5px] text-fg' : 'text-[12.5px] text-fg-strong')}>{t.name}</span>
        {level !== 'none' && (
          <span className="mt-0.5 block">
            <CoverageBadge level={level} compact />
          </span>
        )}
      </button>
      {children}
    </div>
  );
}

function Select({ id, label, value, onChange, options, allLabel = 'All' }: { id: string; label: string; value: string; onChange: (v: string) => void; options: [string, string][]; allLabel?: string }) {
  return (
    <div className="min-w-[9rem]">
      <label htmlFor={id} className="label">
        {label}
      </label>
      <select id={id} className="input" value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{allLabel}</option>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </div>
  );
}


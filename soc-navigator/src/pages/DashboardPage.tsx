import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity, BookOpen, FileWarning, Grid3x3, LayoutDashboard, ListChecks, PlayCircle, Table2 } from 'lucide-react';
import { InvestigationStatusBadge } from '../components/badges';
import { StartInvestigationDialog } from '../components/StartInvestigationDialog';
import { Badge, Button, Callout, Card, DemoBadge, EmptyState, PageHeader, relativeTime } from '../components/ui';
import { coverageLevel } from '../lib/playbooks/library';
import { isActive } from '../lib/investigations/model';
import { useApp } from '../state/AppState';

const BAR = '#3a9be6'; // validated against the dark panel surface (#101720): lightness band + >= 3:1 contrast

export function DashboardPage() {
  const { attack, library, investigations, usage, playbookById, coverage, openTechnique } = useApp();
  const [startOpen, setStartOpen] = useState(false);
  const [showTable, setShowTable] = useState(false);
  const index = attack.index;

  const active = investigations.filter(isActive);
  const awaiting = investigations.filter((i) => i.status === 'Escalation Recommended');
  const demoCount = investigations.filter((i) => i.demo).length;

  const coverageRows = useMemo(() => {
    if (!index || !coverage) return [];
    return index.tactics.map((t) => {
      const ids = new Set<string>();
      for (const parent of index.column(t.shortname)) {
        ids.add(parent.id);
        parent.subtechniqueIds.forEach((s) => ids.add(s));
      }
      const covered = [...ids].filter((id) => coverageLevel(coverage.get(id)) === 'direct').length;
      return { tactic: t.name, total: ids.size, covered, pct: ids.size ? Math.round((covered / ids.size) * 1000) / 10 : 0 };
    });
  }, [index, coverage]);

  const axisMax = Math.max(10, Math.ceil(Math.max(0, ...coverageRows.map((r) => r.pct)) / 10) * 10);
  const axisTicks = Array.from({ length: axisMax / 10 + 1 }, (_, i) => i * 10);
  const totalCovered = useMemo(() => (coverage ? [...coverage.values()].filter((c) => c.direct.length > 0).length : 0), [coverage]);

  const activity = useMemo(
    () =>
      investigations
        .flatMap((inv) => inv.activity.slice(0, 5).map((a) => ({ ...a, inv })))
        .sort((a, b) => b.at.localeCompare(a.at))
        .slice(0, 8),
    [investigations],
  );

  const popular = useMemo(() => {
    const counts = new Map<string, number>(Object.entries(usage.techniqueViews));
    for (const inv of investigations) for (const t of inv.relatedTechniques) counts.set(t.id, (counts.get(t.id) ?? 0) + 1);
    return [...counts.entries()]
      .filter(([id]) => index?.get(id))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [usage.techniqueViews, investigations, index]);

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<LayoutDashboard className="h-5 w-5 text-accent" aria-hidden />}
        title="Dashboard"
        subtitle="Your Tier 1 workload and the ATT&CK coverage of this playbook library. Figures are computed from data in this browser; nothing here is live organizational telemetry."
        actions={
          <>
            <Button variant="primary" icon={<PlayCircle className="h-4 w-4" aria-hidden />} onClick={() => setStartOpen(true)}>
              Start investigation
            </Button>
            <Link to="/matrix" className="inline-flex items-center gap-1.5 rounded-md border border-line bg-panel-2 px-3 py-1.5 text-sm hover:bg-panel-3">
              <Grid3x3 className="h-4 w-4" aria-hidden /> Open matrix
            </Link>
          </>
        }
      />

      {demoCount > 0 && (
        <Callout tone="info" title="Demo data present">
          {demoCount} fictional sample investigation{demoCount === 1 ? ' is' : 's are'} loaded and marked <DemoBadge />. They are not real incidents. Remove them in Settings and Data Sources.
        </Callout>
      )}
      {attack.status === 'error' && (
        <Callout tone="danger" title="ATT&CK data unavailable">
          {attack.error} Playbooks and investigations still work. See Settings and Data Sources.
        </Callout>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <Stat label="ATT&CK tactics" value={index?.dataset.meta.counts.tactics ?? '-'} sub={index ? `Enterprise v${index.dataset.meta.version}` : attack.status} />
        <Stat label="Techniques" value={index?.dataset.meta.counts.techniques ?? '-'} sub={index ? `+ ${index.dataset.meta.counts.subtechniques} sub-techniques` : ''} />
        <Stat label="Playbooks" value={library.length} sub={`${library.filter((e) => e.playbook.status === 'Approved').length} approved, ${library.filter((e) => e.playbook.status === 'Draft').length} draft`} />
        <Stat label="Techniques with a playbook" value={index ? totalCovered : '-'} sub={index ? `of ${index.dataset.techniques.length} (direct mapping)` : ''} />
        <Stat label="Active investigations" value={active.length} sub={<Link to="/investigations" className="text-accent hover:underline">View all</Link>} />
        <Stat label="Awaiting escalation" value={awaiting.length} sub={<Link to="/reports" className="text-accent hover:underline">Reports</Link>} tone={awaiting.length ? 'bad' : undefined} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card
          title="Playbook coverage by tactic (% of techniques incl. sub-techniques with a direct playbook)"
          actions={
            <Button size="sm" variant="ghost" icon={<Table2 className="h-3.5 w-3.5" aria-hidden />} onClick={() => setShowTable((s) => !s)} aria-pressed={showTable}>
              {showTable ? 'Chart view' : 'Table view'}
            </Button>
          }
        >
          {!index ? (
            <EmptyState title="Coverage unavailable">ATT&amp;CK data is not loaded.</EmptyState>
          ) : showTable ? (
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted">
                <tr>
                  <th className="py-1 font-medium">Tactic</th>
                  <th className="py-1 text-right font-medium">With playbook</th>
                  <th className="py-1 text-right font-medium">Total</th>
                  <th className="py-1 text-right font-medium">Coverage</th>
                </tr>
              </thead>
              <tbody>
                {coverageRows.map((r) => (
                  <tr key={r.tactic} className="border-t border-line">
                    <td className="py-1">{r.tactic}</td>
                    <td className="py-1 text-right tabular-nums">{r.covered}</td>
                    <td className="py-1 text-right tabular-nums">{r.total}</td>
                    <td className="py-1 text-right tabular-nums">{r.pct}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="h-[420px]" role="img" aria-label="Bar chart of playbook coverage percentage per ATT&CK tactic. Use Table view for exact values.">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={coverageRows} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 8 }} barCategoryGap={3}>
                  <CartesianGrid horizontal={false} stroke="#253243" strokeDasharray="0" />
                  <XAxis type="number" domain={[0, axisMax]} ticks={axisTicks} tickFormatter={(v: number) => `${v}%`} stroke="#93a3b8" tick={{ fill: '#93a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="tactic" width={150} stroke="#93a3b8" tick={{ fill: '#dce5ef', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: 'rgba(79,179,255,0.08)' }}
                    contentStyle={{ background: '#1b2633', border: '1px solid #34465c', borderRadius: 6, color: '#dce5ef', fontSize: 12 }}
                    formatter={(_v, _n, item) => {
                      const p = item.payload as (typeof coverageRows)[number];
                      return [`${p.pct}% (${p.covered} of ${p.total})`, 'Playbook coverage'];
                    }}
                  />
                  <Bar dataKey="pct" fill={BAR} radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          <p className="mt-2 text-xs text-faint">Coverage counts only playbooks in this library. It says nothing about whether your security tools detect these techniques.</p>
        </Card>

        <div className="space-y-5">
          <Card title="Recent investigation activity">
            {activity.length === 0 ? (
              <EmptyState icon={<Activity className="h-6 w-6" aria-hidden />} title="No activity yet">
                Start an investigation from a playbook or the matrix.
              </EmptyState>
            ) : (
              <ul className="space-y-2 text-sm">
                {activity.map((a, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-16 shrink-0 text-xs text-faint">{relativeTime(a.at)}</span>
                    <span className="min-w-0 flex-1">
                      <Link to={`/investigations/${a.inv.id}`} className="font-mono text-xs text-accent hover:underline">
                        {a.inv.id}
                      </Link>{' '}
                      {a.inv.demo && <DemoBadge />} <span className="text-muted">{a.text}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Awaiting escalation">
            {awaiting.length === 0 ? (
              <p className="text-sm text-muted">No investigation is waiting for escalation.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {awaiting.map((inv) => (
                  <li key={inv.id} className="flex flex-wrap items-center gap-2">
                    <FileWarning className="h-4 w-4 text-bad" aria-hidden />
                    <Link to={`/reports/${inv.id}`} className="text-fg-strong hover:underline">
                      {inv.title}
                    </Link>
                    {inv.demo && <DemoBadge />}
                    <InvestigationStatusBadge status={inv.status} />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Recently opened playbooks">
          {usage.recentPlaybooks.length === 0 ? (
            <EmptyState icon={<BookOpen className="h-6 w-6" aria-hidden />} title="Nothing opened yet" action={<Link to="/playbooks" className="text-accent hover:underline">Browse playbooks</Link>} />
          ) : (
            <ul className="space-y-1.5 text-sm">
              {usage.recentPlaybooks.slice(0, 6).map((r) => {
                const pb = playbookById.get(r.id);
                return (
                  <li key={r.id} className="flex items-center gap-2">
                    <BookOpen className="h-4 w-4 text-ok" aria-hidden />
                    {pb ? (
                      <Link to={`/playbooks/${pb.id}`} className="hover:underline">
                        {pb.title}
                      </Link>
                    ) : (
                      <span className="text-muted">{r.id} (removed)</span>
                    )}
                    <span className="ml-auto text-xs text-faint">{relativeTime(r.at)}</span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
        <Card title="Popular techniques (views and investigations in this browser)">
          {popular.length === 0 ? (
            <EmptyState icon={<ListChecks className="h-6 w-6" aria-hidden />} title="No usage recorded yet">
              Techniques you open in the matrix or investigate appear here.
            </EmptyState>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {popular.map(([id, n]) => (
                <li key={id} className="flex items-center gap-2">
                  <button type="button" className="font-mono text-xs text-accent hover:underline" onClick={() => openTechnique(id)}>
                    {id}
                  </button>
                  <span className="truncate">{index?.get(id)?.name}</span>
                  <Badge className="ml-auto">{n}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <StartInvestigationDialog open={startOpen} onClose={() => setStartOpen(false)} />
    </div>
  );
}

function Stat({ label, value, sub, tone }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: 'bad' }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <p className="text-xs text-muted">{label}</p>
      <p className={tone === 'bad' ? 'text-2xl font-semibold text-bad tabular-nums' : 'text-2xl font-semibold text-fg-strong tabular-nums'}>{value}</p>
      {sub && <p className="mt-0.5 text-xs text-faint">{sub}</p>}
    </div>
  );
}

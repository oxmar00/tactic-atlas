import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { Download, ListChecks, PlayCircle } from 'lucide-react';
import { InvestigationStatusBadge, SeverityBadge } from '../components/badges';
import { StartInvestigationDialog } from '../components/StartInvestigationDialog';
import { Button, Callout, DemoBadge, EmptyState, PageHeader, ProgressBar, downloadFile, relativeTime } from '../components/ui';
import { isActive, progressOf } from '../lib/investigations/model';
import { INVESTIGATION_STATUSES } from '../lib/playbooks/outcomes';
import { useApp } from '../state/AppState';

export function InvestigationsPage() {
  const { investigations, playbookById } = useApp();
  const [filter, setFilter] = useState<string>('active');
  const [q, setQ] = useState('');
  const [startOpen, setStartOpen] = useState(false);

  const list = useMemo(() => {
    const lower = q.trim().toLowerCase();
    return investigations
      .filter((i) => (filter === 'active' ? isActive(i) : filter === 'all' ? true : i.status === filter))
      .filter((i) => !lower || [i.id, i.title, i.alertRef, i.playbookId, i.analyst].join(' ').toLowerCase().includes(lower))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }, [investigations, filter, q]);

  return (
    <div className="space-y-4">
      <PageHeader
        icon={<ListChecks className="h-5 w-5 text-accent" aria-hidden />}
        title="Active Investigations"
        subtitle="Investigations started from playbooks. Progress is saved in this browser as you work."
        actions={
          <>
            <Button variant="primary" icon={<PlayCircle className="h-4 w-4" aria-hidden />} onClick={() => setStartOpen(true)}>
              Start investigation
            </Button>
            <Button
              icon={<Download className="h-4 w-4" aria-hidden />}
              disabled={investigations.length === 0}
              onClick={() => downloadFile('soc-navigator-investigations.json', `${JSON.stringify({ format: 'soc-navigator-investigations', exportedAt: new Date().toISOString(), investigations }, null, 2)}\n`, 'application/json')}
            >
              Export all
            </Button>
          </>
        }
      />
      <Callout tone="info">
        Browser storage is for demonstration only: do not record credentials or unnecessary personal data. Production use requires the secured backend described in docs/PRODUCTION.md.
      </Callout>
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="inv-q" className="label">
            Search
          </label>
          <input id="inv-q" className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="ID, title, alert reference, playbook, analyst" />
        </div>
        <div>
          <label htmlFor="inv-status" className="label">
            Status
          </label>
          <select id="inv-status" className="input" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="active">Active (not resolved/escalated)</option>
            <option value="all">All</option>
            {INVESTIGATION_STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>
      {list.length === 0 ? (
        <EmptyState icon={<ListChecks className="h-8 w-8" aria-hidden />} title={investigations.length ? 'No investigations match' : 'No investigations yet'} action={<Button variant="primary" onClick={() => setStartOpen(true)}>Start an investigation</Button>}>
          {investigations.length ? 'Change the status filter or search.' : 'Pick a playbook from the library or a technique in the matrix to begin.'}
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full text-left text-sm">
            <thead className="bg-panel-2 text-xs text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Investigation</th>
                <th className="px-3 py-2 font-medium">Playbook</th>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="w-40 px-3 py-2 font-medium">Progress</th>
                <th className="px-3 py-2 font-medium">Analyst</th>
                <th className="px-3 py-2 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {list.map((inv) => {
                const pb = playbookById.get(inv.playbookId);
                return (
                  <tr key={inv.id} className="border-t border-line align-top hover:bg-panel-2/50">
                    <td className="px-3 py-2">
                      <Link to={`/investigations/${inv.id}`} className="font-medium text-fg-strong hover:underline">
                        {inv.title}
                      </Link>
                      <p className="flex items-center gap-2 font-mono text-xs text-faint">
                        {inv.id} - {inv.alertRef} {inv.demo && <DemoBadge />}
                      </p>
                    </td>
                    <td className="px-3 py-2 text-xs">
                      <span className="font-mono">{inv.playbookId}</span>
                      {!pb && <p className="text-warn">playbook missing</p>}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={inv.severity} />
                    </td>
                    <td className="px-3 py-2">
                      <InvestigationStatusBadge status={inv.status} />
                    </td>
                    <td className="px-3 py-2">
                      <ProgressBar value={progressOf(inv, pb).percent} label={`Progress of ${inv.id}`} />
                    </td>
                    <td className="px-3 py-2 text-xs">{inv.analyst}</td>
                    <td className="px-3 py-2 text-xs text-muted">{relativeTime(inv.updatedAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <StartInvestigationDialog open={startOpen} onClose={() => setStartOpen(false)} />
    </div>
  );
}

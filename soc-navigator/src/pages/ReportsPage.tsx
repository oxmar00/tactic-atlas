import { Link } from 'react-router';
import { FileText } from 'lucide-react';
import { InvestigationStatusBadge, SeverityBadge } from '../components/badges';
import { DemoBadge, EmptyState, PageHeader, formatDate } from '../components/ui';
import type { Investigation } from '../lib/investigations/model';
import { useApp } from '../state/AppState';

const GROUPS: { title: string; description: string; match: (i: Investigation) => boolean }[] = [
  { title: 'Awaiting escalation', description: 'Escalation recommended - generate and send the Tier 2 handoff.', match: (i) => i.status === 'Escalation Recommended' },
  { title: 'Awaiting information', description: 'Blocked on missing telemetry or access.', match: (i) => i.status === 'Awaiting Information' },
  { title: 'Escalated', description: 'Handed off to Tier 2.', match: (i) => i.status === 'Escalated' },
  { title: 'In progress', description: 'Reports can be drafted at any time.', match: (i) => i.status === 'New' || i.status === 'In Progress' },
  { title: 'Resolved', description: 'Closed investigations (keep the record for audit).', match: (i) => i.status === 'Resolved' },
];

export function ReportsPage() {
  const { investigations } = useApp();
  return (
    <div className="space-y-5">
      <PageHeader
        icon={<FileText className="h-5 w-5 text-accent" aria-hidden />}
        title="Reports and Escalations"
        subtitle="Generate, edit, and export structured Tier 2 handoff reports (Markdown, JSON, or print to PDF) from investigation records."
      />
      {investigations.length === 0 ? (
        <EmptyState icon={<FileText className="h-8 w-8" aria-hidden />} title="No investigations yet" action={<Link to="/playbooks" className="text-accent hover:underline">Choose a playbook</Link>}>
          Reports are generated from investigations.
        </EmptyState>
      ) : (
        GROUPS.map((g) => {
          const items = investigations.filter(g.match).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
          return (
            <section key={g.title} aria-labelledby={`rg-${g.title}`}>
              <h2 id={`rg-${g.title}`} className="text-sm font-semibold text-fg-strong">
                {g.title} <span className="text-muted">({items.length})</span>
              </h2>
              <p className="mb-2 text-xs text-muted">{g.description}</p>
              {items.length === 0 ? (
                <p className="rounded-md border border-dashed border-line px-3 py-2 text-sm text-faint">None.</p>
              ) : (
                <ul className="divide-y divide-line rounded-lg border border-line bg-panel">
                  {items.map((inv) => (
                    <li key={inv.id} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
                      <Link to={`/reports/${inv.id}`} className="font-medium text-fg-strong hover:underline">
                        {inv.title}
                      </Link>
                      <span className="font-mono text-xs text-faint">{inv.id}</span>
                      {inv.demo && <DemoBadge />}
                      <SeverityBadge severity={inv.severity} />
                      <InvestigationStatusBadge status={inv.status} />
                      <span className="ml-auto text-xs text-muted">
                        {inv.escalation.escalatedAt ? `escalated ${formatDate(inv.escalation.escalatedAt)}` : `updated ${formatDate(inv.updatedAt)}`}
                      </span>
                      <Link to={`/reports/${inv.id}`} className="text-xs text-accent hover:underline">
                        Open report
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          );
        })
      )}
    </div>
  );
}

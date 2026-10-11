import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router';
import { ArrowLeft, CheckCircle2, Download, FileJson, Pencil, Printer, RotateCcw, Send } from 'lucide-react';
import { InvestigationStatusBadge } from '../components/badges';
import { Badge, Button, Callout, CopyButton, DeferredInput, DeferredTextArea, EmptyState, Field, downloadFile } from '../components/ui';
import { progressOf, setStatus, update } from '../lib/investigations/model';
import type { Investigation } from '../lib/investigations/model';
import { buildReport, reportToJson, reportToMarkdown } from '../lib/report';
import type { HandoffReport } from '../lib/report';
import { useApp } from '../state/AppState';

export function ReportPage() {
  const { id = '' } = useParams();
  const { investigations, playbookById, attack, updateInvestigation, notify } = useApp();
  const inv = investigations.find((i) => i.id === id);
  const pb = inv ? playbookById.get(inv.playbookId) : undefined;
  const [editing, setEditing] = useState(false);

  const report = useMemo(() => (inv ? buildReport(inv, pb, (tid) => attack.index?.get(tid)?.name) : null), [inv, pb, attack.index]);
  const generatedMd = useMemo(() => (report ? reportToMarkdown(report) : ''), [report]);

  if (!inv || !report) {
    return (
      <EmptyState title={`Investigation ${id} not found`} action={<Link to="/reports" className="text-accent hover:underline">Back to reports</Link>}>
        Reports are generated from investigations stored in this browser.
      </EmptyState>
    );
  }
  const mutate = (fn: (i: Investigation) => Investigation) => updateInvestigation(inv.id, fn);
  const markdown = inv.reportOverride ?? generatedMd;
  const progress = progressOf(inv, pb);
  const base = `${inv.id}-tier2-handoff`;

  return (
    <div className="space-y-4">
      <div className="no-print flex flex-wrap items-center gap-2">
        <Link to={`/investigations/${inv.id}`} className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
          <ArrowLeft className="h-4 w-4" aria-hidden /> Back to investigation
        </Link>
        <div className="ml-auto flex flex-wrap gap-2">
          <Button icon={<Download className="h-4 w-4" aria-hidden />} onClick={() => downloadFile(`${base}.md`, markdown, 'text/markdown')}>
            Export Markdown
          </Button>
          <Button
            icon={<FileJson className="h-4 w-4" aria-hidden />}
            onClick={() => downloadFile(`${base}.json`, reportToJson(inv.reportOverride ? ({ ...report, markdownOverride: inv.reportOverride } as HandoffReport) : report), 'application/json')}
          >
            Export JSON
          </Button>
          <Button icon={<Printer className="h-4 w-4" aria-hidden />} onClick={() => window.print()}>
            Print / Save as PDF
          </Button>
          <CopyButton text={markdown} label="Copy Markdown" />
        </div>
      </div>

      <div className="no-print grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="space-y-3">
          {progress.missingRequiredEvidence.length > 0 && (
            <Callout tone="warning" title={`${progress.missingRequiredEvidence.length} required evidence item(s) not recorded`}>
              {progress.missingRequiredEvidence.join(', ')}. They are listed in the report as limitations.
            </Callout>
          )}
          {inv.reportOverride && (
            <Callout tone="info" title="Manual edits active">
              This report uses your edited Markdown. Changes to the investigation are not reflected until you regenerate.{' '}
              <button type="button" className="text-accent hover:underline" onClick={() => mutate((i) => update(i, 'reportOverride', null))}>
                Discard edits and regenerate
              </button>
            </Callout>
          )}
        </div>
        <div className="space-y-2 rounded-lg border border-line bg-panel p-3">
          <p className="flex items-center gap-2 text-sm font-semibold text-fg-strong">
            Handoff status <InvestigationStatusBadge status={inv.status} />
          </p>
          <Field label="Escalated to (team / person)" htmlFor="r-to">
            <DeferredInput id="r-to" value={inv.escalation.recipient} maxLength={200} onCommit={(v) => mutate((i) => update(i, 'escalation', { ...i.escalation, recipient: v }))} />
          </Field>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              size="sm"
              icon={<Send className="h-3.5 w-3.5" aria-hidden />}
              disabled={inv.status === 'Escalated'}
              onClick={() => {
                if (!inv.escalation.recipient.trim()) {
                  notify('Record who the case was escalated to first.', 'warning');
                  return;
                }
                if (!inv.escalation.reason.trim() && !window.confirm('No reason for escalation is recorded. Mark as escalated anyway?')) return;
                mutate((i) => setStatus(i, 'Escalated'));
                notify('Marked as escalated. Send the exported report through your approved channel - SOC Navigator does not send it.', 'success');
              }}
            >
              Mark as escalated
            </Button>
            <Button size="sm" icon={<CheckCircle2 className="h-3.5 w-3.5" aria-hidden />} disabled={inv.status === 'Resolved'} onClick={() => mutate((i) => setStatus(i, 'Resolved'))}>
              Mark resolved
            </Button>
          </div>
          <p className="text-xs text-faint">Status changes are recorded locally. This app does not notify Tier 2 or create tickets.</p>
        </div>
      </div>

      <div className="no-print grid gap-3 lg:grid-cols-2">
        <Field label="Executive summary (leave empty to use the generated one)" htmlFor="r-sum">
          <DeferredTextArea id="r-sum" rows={3} value={inv.executiveSummary} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'executiveSummary', v))} placeholder={report.executiveSummary} />
        </Field>
        <Field label="Reason for escalation" htmlFor="r-reason">
          <DeferredTextArea id="r-reason" rows={3} value={inv.escalation.reason} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'escalation', { ...i.escalation, reason: v }))} />
        </Field>
        <Field label="Recommended next investigative steps" htmlFor="r-next">
          <DeferredTextArea id="r-next" rows={3} value={inv.escalation.nextSteps} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'escalation', { ...i.escalation, nextSteps: v }))} />
        </Field>
        <div className="text-sm text-muted">
          Outstanding questions, findings, timeline, and missing telemetry are edited in the{' '}
          <Link to={`/investigations/${inv.id}`} className="text-accent hover:underline">
            investigation workspace
          </Link>
          .
        </div>
      </div>

      <div className="no-print flex items-center gap-2">
        <Button size="sm" icon={<Pencil className="h-3.5 w-3.5" aria-hidden />} onClick={() => setEditing((e) => !e)} aria-pressed={editing}>
          {editing ? 'Show formatted preview' : 'Edit as Markdown'}
        </Button>
        {inv.reportOverride && (
          <Button size="sm" variant="ghost" icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden />} onClick={() => mutate((i) => update(i, 'reportOverride', null))}>
            Regenerate from investigation
          </Button>
        )}
      </div>

      {editing ? (
        <div className="no-print">
          <label htmlFor="r-md" className="label">
            Report Markdown (your edits are saved with the investigation)
          </label>
          <DeferredTextArea id="r-md" rows={30} className="font-mono text-xs" value={markdown} maxLength={100000} onCommit={(v) => mutate((i) => update(i, 'reportOverride', v === generatedMd ? null : v))} />
        </div>
      ) : inv.reportOverride ? (
        <pre className="print-area rounded-lg border border-line bg-panel p-5 text-sm whitespace-pre-wrap">{inv.reportOverride}</pre>
      ) : (
        <ReportPreview r={report} />
      )}
    </div>
  );
}

/** Structured rendering of the report (React text only - no Markdown-to-HTML conversion). */
function ReportPreview({ r }: { r: HandoffReport }) {
  return (
    <article className="print-area space-y-5 rounded-lg border border-line bg-panel p-6 text-sm">
      <header>
        <h1 className="text-xl font-semibold text-fg-strong">Tier 2 Handoff - {r.investigation.id}</h1>
        {r.demo && (
          <p className="mt-1">
            <Badge tone="violet">DEMO DATA - fictional sample investigation, not real telemetry</Badge>
          </p>
        )}
        <dl className="mt-3 grid gap-x-4 gap-y-1 sm:grid-cols-[10rem_1fr]">
          {[
            ['Title', r.investigation.title],
            ['Alert reference', r.investigation.alertRef],
            ['Severity', r.investigation.severity],
            ['Status', r.investigation.status],
            ['Analyst', r.investigation.analyst],
            ['Created / updated', `${r.investigation.createdAt} / ${r.investigation.updatedAt}`],
            ['Playbook', r.playbook ? `${r.playbook.id} v${r.playbook.version} - ${r.playbook.title} (${r.playbook.reviewStatus})` : 'Not available'],
            ['Generated', r.generatedAt],
          ].map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd className="break-words">{v}</dd>
            </div>
          ))}
        </dl>
      </header>
      <RSection title="Executive summary">
        <p>{r.executiveSummary}</p>
      </RSection>
      <RSection title="Alert context">
        <KV items={r.alertContext.map((c) => [c.label, c.value])} />
      </RSection>
      <div className="grid gap-4 sm:grid-cols-2">
        <RSection title="Affected users / accounts">
          <Bullets items={r.affectedUsers} />
        </RSection>
        <RSection title="Affected assets / systems">
          <Bullets items={r.affectedAssets} />
        </RSection>
      </div>
      <RSection title="Timeline of events">
        {r.timeline.length ? (
          <ol className="space-y-0.5">
            {r.timeline.map((t, i) => (
              <li key={i}>
                <span className="font-mono text-xs text-muted">{t.time || 'time unknown'}</span> - {t.description} {t.source && <span className="text-xs text-faint">(source: {t.source})</span>}
              </li>
            ))}
          </ol>
        ) : (
          <Empty />
        )}
      </RSection>
      <RSection title="Investigation steps completed">
        {r.stepsCompleted.length ? (
          <ul className="space-y-1">
            {r.stepsCompleted.map((s) => (
              <li key={s.title}>
                [x] {s.title} {s.completedAt && <span className="text-xs text-faint">({s.completedAt})</span>}
                {s.notes && <p className="ml-6 text-xs text-muted">Notes: {s.notes}</p>}
              </li>
            ))}
          </ul>
        ) : (
          <Empty />
        )}
        {r.stepsPending.length > 0 && <p className="mt-1 text-xs text-muted">Not completed: {r.stepsPending.join('; ')}</p>}
      </RSection>
      <RSection title="Evidence collected">
        {r.evidence.length ? <KV items={r.evidence.map((e) => [e.label, e.value])} mono /> : <Empty />}
      </RSection>
      <RSection title="Relevant ATT&CK techniques (hypotheses)">
        <Bullets items={r.techniques.map((t) => `${t.id}${t.name ? ` ${t.name}` : ''}${t.note ? ` - ${t.note}` : ''}`)} />
      </RSection>
      <div className="grid gap-4 sm:grid-cols-2">
        <RSection title="Benign explanations considered">
          <Bullets items={r.benignExplanationsConsidered} />
        </RSection>
        <RSection title="Indicators supporting suspicion">
          <Bullets items={r.indicatorsSupportingSuspicion} />
        </RSection>
      </div>
      {r.observations.length > 0 && (
        <RSection title="Other observations">
          <Bullets items={r.observations} />
        </RSection>
      )}
      <RSection title="Assessment">
        <p>
          {r.assessment.suspicion} ({r.assessment.confidence} confidence). {r.assessment.rationale}
        </p>
        {r.decisionPath.length > 0 && (
          <ol className="mt-2 list-decimal space-y-0.5 pl-5 text-xs text-muted">
            {r.decisionPath.map((d, i) => (
              <li key={i}>
                {d.question} - <strong className="text-fg">{d.answer}</strong>
              </li>
            ))}
          </ol>
        )}
        {r.decisionOutcome && <p className="mt-1 text-xs">Decision outcome: {r.decisionOutcome}</p>}
      </RSection>
      <RSection title="Missing telemetry and limitations">
        <Bullets items={r.missingTelemetryAndLimitations} />
      </RSection>
      <RSection title="Recommended next investigative steps">
        <p className="whitespace-pre-wrap">{r.recommendedNextSteps || 'Not recorded.'}</p>
      </RSection>
      <RSection title="Reason for escalation">
        <p className="whitespace-pre-wrap">{r.reasonForEscalation || 'Not recorded.'}</p>
      </RSection>
      <RSection title="Disposition">
        <p>
          {r.disposition.recommendation}. {r.disposition.rationale}
        </p>
        {r.escalationRecipient && <p className="text-xs text-muted">Escalated to: {r.escalationRecipient}</p>}
      </RSection>
      <RSection title="Outstanding questions">
        <Bullets items={r.outstandingQuestions} />
      </RSection>
      {r.analystNotes && (
        <RSection title="Analyst notes">
          <pre className="text-xs whitespace-pre-wrap">{r.analystNotes}</pre>
        </RSection>
      )}
      <footer className="space-y-1 border-t border-line pt-3 text-xs text-muted italic">
        {r.statements.map((s) => (
          <p key={s}>{s}</p>
        ))}
      </footer>
    </article>
  );
}

function RSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="mb-1 border-b border-line pb-0.5 text-sm font-semibold text-fg-strong">{title}</h2>
      {children}
    </section>
  );
}

function Bullets({ items }: { items: string[] }) {
  return items.length ? (
    <ul className="list-disc space-y-0.5 pl-5">
      {items.map((x, i) => (
        <li key={i} className="break-words whitespace-pre-wrap">
          {x}
        </li>
      ))}
    </ul>
  ) : (
    <Empty />
  );
}

function KV({ items, mono }: { items: [string, string][]; mono?: boolean }) {
  return (
    <dl className="space-y-1.5">
      {items.map(([k, v], i) => (
        <div key={i}>
          <dt className="text-xs text-muted">{k}</dt>
          <dd className={mono ? 'font-mono text-xs break-words whitespace-pre-wrap' : 'break-words whitespace-pre-wrap'}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Empty() {
  return <p className="text-muted italic">None recorded.</p>;
}

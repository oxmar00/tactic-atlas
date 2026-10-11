import { useState } from 'react';
import { Link } from 'react-router';
import { AlertOctagon, ExternalLink } from 'lucide-react';
import { LOG_SOURCE_BY_ID } from '../../data/logSources';
import type { Answer } from '../../lib/investigations/model';
import type { Playbook } from '../../lib/playbooks/schema';
import { useApp } from '../../state/AppState';
import { PlaybookStatusBadge } from '../badges';
import { Badge, Callout, Term, cx, formatDate } from '../ui';
import { DecisionTree } from './DecisionTree';
import { QueryCard } from './QueryCard';
import { StepCard } from './StepCard';

const SECTIONS = [
  ['overview', 'Overview'],
  ['alert-context', 'Alert context'],
  ['prerequisites', 'Prerequisites'],
  ['steps', 'Investigation steps'],
  ['decision', 'Decision tree'],
  ['evidence', 'Evidence to collect'],
  ['escalation', 'Escalation criteria'],
  ['queries', 'Queries'],
  ['detection', 'Detection notes'],
  ['references', 'References and review'],
] as const;

export function DraftNotice({ pb }: { pb: Playbook }) {
  if (pb.status === 'Approved') return null;
  return (
    <Callout tone="warning" title={pb.status === 'Draft' ? 'Draft guidance - not yet reviewed' : 'Reviewed, not yet approved'}>
      {pb.status === 'Draft'
        ? `${pb.aiAssisted ? 'This playbook contains AI-assisted content and ' : 'This playbook '}has not been reviewed by an authorized person. Validate each step against your organization's procedures before relying on it.`
        : `Reviewed by ${pb.review.reviewer ?? 'unknown'}${pb.review.reviewedAt ? ` on ${formatDate(pb.review.reviewedAt)}` : ''}. Awaiting formal approval.`}
    </Callout>
  );
}

/** Analyst-perspective reader used on the playbook page and as the authoring preview. */
export function PlaybookView({ pb, preview = false }: { pb: Playbook; preview?: boolean }) {
  const { attack, openTechnique } = useApp();
  const [practice, setPractice] = useState<{ nodeId: string; answer: Answer }[]>([]);
  const queriesById = new Map(pb.queries.map((q) => [q.id, q]));
  const tacticName = (s: string) => attack.index?.tacticByShortname.get(s)?.name ?? s;

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_14rem]">
      <div className="min-w-0 space-y-6">
        <DraftNotice pb={pb} />

        <Section id="overview" title="Playbook overview">
          <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
            <PlaybookStatusBadge status={pb.status} />
            <Badge>v{pb.version}</Badge>
            <Badge tone="info">{pb.difficulty}</Badge>
            <Badge>Effort: {pb.effort}</Badge>
            {pb.aiAssisted && <Badge tone="violet">AI-assisted content</Badge>}
          </div>
          <dl className="grid gap-x-4 gap-y-3 text-sm md:grid-cols-[10rem_1fr]">
            <Dt>ATT&amp;CK techniques</Dt>
            <dd className="flex flex-wrap gap-1.5">
              {pb.techniques.map((id) => (
                <button key={id} type="button" onClick={() => openTechnique(id)} className="rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-xs text-accent hover:bg-accent/20">
                  <span className="font-mono">{id}</span> {attack.index?.get(id)?.name ?? ''}
                </button>
              ))}
            </dd>
            <Dt>
              <Term term="Tactic">Tactics</Term>
            </Dt>
            <dd className="flex flex-wrap gap-1.5">
              {pb.tactics.map((s) => (
                <Badge key={s} tone="accent">
                  {tacticName(s)}
                </Badge>
              ))}
            </dd>
            <Dt>Objective</Dt>
            <dd>{pb.objective}</dd>
            <Dt>What the alert means</Dt>
            <dd>{pb.alertMeaning}</dd>
            <Dt>Why it matters</Dt>
            <dd>{pb.whyItMatters}</dd>
            <Dt>Platforms</Dt>
            <dd className="flex flex-wrap gap-1.5">
              {pb.platforms.map((p) => (
                <Badge key={p}>{p}</Badge>
              ))}
            </dd>
            <Dt>Log sources</Dt>
            <dd className="flex flex-wrap gap-1.5">
              {pb.logSources.map((id) => (
                <Link key={id} to={`/reference?source=${id}`} className="rounded border border-line bg-panel-2 px-1.5 py-0.5 text-xs hover:border-accent hover:text-accent">
                  {LOG_SOURCE_BY_ID.get(id)?.name ?? id}
                </Link>
              ))}
            </dd>
          </dl>
        </Section>

        <Section id="alert-context" title="Alert context">
          <div className="grid gap-3 md:grid-cols-3">
            <ListBox title="Alerts that trigger this playbook" items={pb.alertContext.triggers} />
            <ListBox title="Review first" items={pb.alertContext.reviewFirst} />
            <ListBox title="Often missing from the alert" items={pb.alertContext.oftenMissing} empty="Nothing noted." />
          </div>
        </Section>

        <Section id="prerequisites" title="Prerequisites">
          <ul className="space-y-1.5 text-sm">
            {pb.prerequisites.map((p, i) => (
              <li key={i} className="flex items-start gap-2">
                <Badge tone={p.required ? 'warn' : 'neutral'} className="mt-0.5 w-[5.5rem] justify-center">
                  {p.required ? 'Mandatory' : 'Helpful'}
                </Badge>
                <Badge className="mt-0.5 w-20 justify-center">{p.type}</Badge>
                <span>{p.text}</span>
              </li>
            ))}
          </ul>
        </Section>

        <Section id="steps" title={`Step-by-step investigation (${pb.steps.length} steps)`}>
          {!preview && <p className="mb-2 text-sm text-muted">Read-only view. Start an investigation to check off steps and record notes.</p>}
          <ol className="space-y-2">
            {pb.steps.map((s, i) => (
              <StepCard key={s.id} step={s} number={i + 1} playbookId={pb.id} queries={s.queryIds.map((id) => queriesById.get(id)).filter((q): q is NonNullable<typeof q> => !!q)} />
            ))}
          </ol>
        </Section>

        <Section id="decision" title="Investigation decision tree">
          <p className="mb-2 text-sm text-muted">Practice mode: answers here are not saved. In an investigation, your path is recorded and the outcome can be applied as a disposition.</p>
          <DecisionTree
            playbook={pb}
            answers={practice}
            onReset={() => setPractice([])}
            onAnswer={(nodeId, answer) =>
              setPractice((prev) => {
                const idx = prev.findIndex((p) => p.nodeId === nodeId);
                return [...(idx >= 0 ? prev.slice(0, idx) : prev), { nodeId, answer }];
              })
            }
          />
        </Section>

        <Section id="evidence" title="Evidence to collect">
          <ul className="grid gap-2 md:grid-cols-2">
            {pb.evidence.map((e) => (
              <li key={e.id} className="rounded-md border border-line bg-panel-2 px-3 py-2 text-sm">
                <p className="flex items-center gap-2 font-medium text-fg-strong">
                  {e.label}
                  {e.required ? <Badge tone="warn">Required</Badge> : <Badge>If relevant</Badge>}
                </p>
                {e.hint && <p className="mt-0.5 text-xs text-muted">{e.hint}</p>}
              </li>
            ))}
          </ul>
        </Section>

        <Section id="escalation" title="Escalation criteria">
          <div className="grid gap-3 lg:grid-cols-3">
            <div className="rounded-md border border-bad/40 bg-bad/5 p-3 text-sm">
              <p className="mb-1 flex items-center gap-1.5 font-semibold text-bad">
                <AlertOctagon className="h-4 w-4" aria-hidden /> Immediate incident escalation
              </p>
              {pb.escalation.immediate.length ? (
                <ul className="list-disc space-y-1 pl-4">
                  {pb.escalation.immediate.map((x) => (
                    <li key={x}>{x}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted">No playbook-specific immediate criteria; follow your incident escalation procedure.</p>
              )}
            </div>
            <ListBox title="Escalate to Tier 2 when" items={pb.escalation.tier2} tone="warn" />
            <ListBox title="Close as benign only when" items={pb.escalation.benignClosure} tone="ok" />
          </div>
          <p className="mt-2 text-xs text-faint">Criteria apply under your organization&apos;s configured escalation policy. An alert is not a confirmed incident until evidence supports it.</p>
        </Section>

        <Section id="queries" title={`SIEM query templates (${pb.queries.length})`}>
          <div className="space-y-2">
            {pb.queries.map((q) => (
              <QueryCard key={q.id} query={q} playbookId={pb.id} />
            ))}
          </div>
        </Section>

        <Section id="detection" title="Detection considerations and visibility gaps">
          <div className="grid gap-3 md:grid-cols-2">
            <ListBox title="Detection considerations" items={pb.detectionConsiderations} empty="None recorded." />
            <ListBox title="Known limitations / visibility gaps" items={pb.visibilityGaps} empty="None recorded." />
          </div>
          {pb.relatedTechniques.length > 0 && (
            <div className="mt-3">
              <p className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Related techniques to consider (hypotheses, not confirmed)</p>
              <ul className="space-y-1 text-sm">
                {pb.relatedTechniques.map((r) => (
                  <li key={r.id}>
                    <button type="button" className="font-mono text-xs text-accent hover:underline" onClick={() => openTechnique(r.id)}>
                      {r.id}
                    </button>{' '}
                    <span className="text-fg">{attack.index?.get(r.id)?.name}</span> <span className="text-muted">- {r.reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Section>

        <Section id="references" title="References, assumptions, and review">
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <p className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">References</p>
              <ul className="space-y-1 text-sm">
                {pb.references.map((r) => (
                  <li key={r.url}>
                    <a href={r.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
                      {r.title}
                      <ExternalLink className="h-3 w-3" aria-hidden />
                      <span className="sr-only">(opens in new tab)</span>
                    </a>
                  </li>
                ))}
              </ul>
            </div>
            <ListBox title="Assumptions" items={pb.assumptions} empty="None recorded." />
          </div>
          <div className="mt-3 rounded-md border border-line bg-panel-2 p-3 text-sm">
            <p>
              <span className="text-muted">Author:</span> {pb.review.author} <span className="ml-3 text-muted">Reviewer:</span> {pb.review.reviewer ?? 'none'}{' '}
              <span className="ml-3 text-muted">Last updated:</span> {pb.updatedAt}
            </p>
            {pb.review.notes && <p className="mt-1 text-muted">{pb.review.notes}</p>}
            <ul className="mt-2 space-y-0.5 text-xs text-muted">
              {[...pb.review.history].reverse().map((h, i) => (
                <li key={i}>
                  {formatDate(h.at)} - v{h.version} - {h.status} - {h.by}
                  {h.note && `: ${h.note}`}
                </li>
              ))}
            </ul>
          </div>
        </Section>
      </div>

      <nav aria-label="Playbook sections" className="no-print hidden xl:block">
        <ul className="sticky top-20 space-y-0.5 border-l border-line pl-3 text-sm">
          {SECTIONS.map(([id, label]) => (
            <li key={id}>
              <a href={`#${id}`} onClick={(e) => { e.preventDefault(); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }} className="block py-0.5 text-muted hover:text-fg">
                {label}
              </a>
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20 rounded-lg border border-line bg-panel p-4">
      <h2 className="mb-3 text-base font-semibold text-fg-strong">{title}</h2>
      {children}
    </section>
  );
}

function Dt({ children }: { children: React.ReactNode }) {
  return <dt className="text-xs font-semibold tracking-wide text-muted uppercase md:pt-0.5">{children}</dt>;
}

function ListBox({ title, items, empty, tone }: { title: string; items: string[]; empty?: string; tone?: 'ok' | 'warn' }) {
  return (
    <div className={cx('rounded-md border p-3 text-sm', tone === 'ok' ? 'border-ok/30 bg-ok/5' : tone === 'warn' ? 'border-warn/40 bg-warn/5' : 'border-line bg-panel-2')}>
      <p className={cx('mb-1 font-semibold', tone === 'ok' ? 'text-ok' : tone === 'warn' ? 'text-warn' : 'text-fg-strong')}>{title}</p>
      {items.length ? (
        <ul className="list-disc space-y-1 pl-4">
          {items.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      ) : (
        <p className="text-muted">{empty ?? 'None.'}</p>
      )}
    </div>
  );
}

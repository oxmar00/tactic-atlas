import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ArrowLeft, Bot, CheckCircle2, Circle, Download, FileText, Plus, RotateCcw, Trash2, X } from 'lucide-react';
import { InvestigationStatusBadge, PlaybookStatusBadge } from '../components/badges';
import { DecisionTree } from '../components/playbook/DecisionTree';
import { DraftNotice } from '../components/playbook/PlaybookView';
import { QueryCard } from '../components/playbook/QueryCard';
import { StepCard } from '../components/playbook/StepCard';
import { Badge, Button, Callout, Card, DeferredInput, DeferredTextArea, DemoBadge, EmptyState, Field, ProgressBar, TabPanel, Tabs, Term, cx, downloadFile, formatDate } from '../components/ui';
import { ASSISTANT_TASKS, TASK_LABEL, runLocalTask, runRemoteTask } from '../lib/assistant/assistant';
import type { AssistantResult, AssistantTask } from '../lib/assistant/assistant';
import {
  CONFIDENCE_LEVELS,
  FINDING_KINDS,
  SEVERITIES,
  SUSPICION_LEVELS,
  addFinding,
  addListItem,
  addTimelineEntry,
  answerDecision,
  applyOutcome,
  evaluateDecision,
  progressOf,
  removeListItem,
  resetDecision,
  resetProgress,
  setDisposition,
  setEvidence,
  setStatus,
  setStepDone,
  setStepNotes,
  sortedTimeline,
  update,
} from '../lib/investigations/model';
import type { FindingKind, Investigation } from '../lib/investigations/model';
import { DISPOSITIONS, INVESTIGATION_STATUSES, OUTCOME_INFO } from '../lib/playbooks/outcomes';
import type { Disposition, InvestigationStatus } from '../lib/playbooks/outcomes';
import type { Playbook } from '../lib/playbooks/schema';
import { useApp } from '../state/AppState';

type RightTab = 'evidence' | 'findings' | 'assessment' | 'assistant' | 'notes';

export function WorkspacePage() {
  const { id = '' } = useParams();
  const { investigations, playbookById, updateInvestigation, deleteInvestigation, notify } = useApp();
  const navigate = useNavigate();
  const inv = investigations.find((i) => i.id === id);
  const pb = inv ? playbookById.get(inv.playbookId) : undefined;
  const [tab, setTab] = useState<RightTab>('evidence');

  if (!inv) {
    return (
      <EmptyState title={`Investigation ${id} not found`} action={<Link to="/investigations" className="text-accent hover:underline">Back to investigations</Link>}>
        It may have been deleted or exist only in another browser.
      </EmptyState>
    );
  }
  const mutate = (fn: (i: Investigation) => Investigation) => updateInvestigation(inv.id, fn);
  const progress = progressOf(inv, pb);
  const decision = pb ? evaluateDecision(pb, inv.decisionPath) : null;
  const queriesById = new Map((pb?.queries ?? []).map((q) => [q.id, q]));
  const staleSteps = pb ? Object.keys(inv.steps).filter((sid) => !pb.steps.some((s) => s.id === sid)) : [];

  const exportJson = () =>
    downloadFile(`${inv.id}.json`, `${JSON.stringify({ format: 'soc-navigator-investigation', exportedAt: new Date().toISOString(), investigation: inv, playbook: pb ? { id: pb.id, version: pb.version } : null }, null, 2)}\n`, 'application/json');

  return (
    <div className="space-y-4">
      <Link to="/investigations" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
        <ArrowLeft className="h-4 w-4" aria-hidden /> All investigations
      </Link>

      <header className="rounded-lg border border-line bg-panel p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="flex flex-wrap items-center gap-2 font-mono text-xs text-faint">
              {inv.id} {inv.demo && <DemoBadge />} <InvestigationStatusBadge status={inv.status} />
            </p>
            <h1 className="mt-1 text-xl font-semibold text-fg-strong">{inv.title}</h1>
            <p className="mt-1 text-sm text-muted">
              Alert <span className="font-mono text-fg">{inv.alertRef}</span>
              {inv.alertSource && <> from {inv.alertSource}</>} - analyst {inv.analyst} - started {formatDate(inv.createdAt)} - updated {formatDate(inv.updatedAt)}
            </p>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-sm">
              Playbook:{' '}
              {pb ? (
                <>
                  <Link to={`/playbooks/${pb.id}`} className="text-accent hover:underline">
                    {pb.title}
                  </Link>
                  <span className="font-mono text-xs text-faint">
                    {pb.id} v{pb.version}
                  </span>
                  <PlaybookStatusBadge status={pb.status} />
                </>
              ) : (
                <span className="text-warn">
                  {inv.playbookId} v{inv.playbookVersion} (no longer in the library)
                </span>
              )}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link to={`/reports/${inv.id}`} className="inline-flex items-center gap-1.5 rounded-md border border-transparent bg-accent-strong px-3 py-1.5 text-sm font-medium text-white hover:bg-accent">
              <FileText className="h-4 w-4" aria-hidden /> Tier 2 handoff report
            </Link>
            <Button icon={<Download className="h-4 w-4" aria-hidden />} onClick={exportJson}>
              Export JSON
            </Button>
            <Button
              variant="danger"
              icon={<RotateCcw className="h-4 w-4" aria-hidden />}
              onClick={() => {
                if (window.confirm('Reset all recorded progress, evidence, findings, and decisions for this investigation? This cannot be undone. Export first if needed.')) {
                  mutate((i) => resetProgress(i));
                  notify('Investigation progress reset.', 'warning');
                }
              }}
            >
              Reset
            </Button>
            <Button
              variant="danger"
              icon={<Trash2 className="h-4 w-4" aria-hidden />}
              onClick={() => {
                if (window.confirm(`Delete ${inv.id} from this browser? This cannot be undone.`)) {
                  deleteInvestigation(inv.id);
                  notify(`${inv.id} deleted.`, 'warning');
                  navigate('/investigations');
                }
              }}
            >
              Delete
            </Button>
          </div>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_14rem]">
          <div>
            <p className="label">Progress</p>
            <ProgressBar value={progress.percent} label="Investigation progress" />
            <p className="mt-1 text-xs text-muted">
              {progress.stepsDone}/{progress.stepsTotal} steps - {progress.requiredEvidenceDone}/{progress.requiredEvidenceTotal} required evidence - decision {progress.decisionComplete ? 'complete' : 'pending'}
            </p>
          </div>
          <Field label="Severity" htmlFor="ws-sev">
            <select id="ws-sev" className="input" value={inv.severity} onChange={(e) => mutate((i) => update(i, 'severity', e.target.value as Investigation['severity']))}>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Status" htmlFor="ws-status">
            <select id="ws-status" className="input" value={inv.status} onChange={(e) => mutate((i) => setStatus(i, e.target.value as InvestigationStatus))}>
              {INVESTIGATION_STATUSES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        </div>
      </header>

      {pb && inv.playbookVersion !== pb.version && (
        <Callout tone="warning" title="Playbook changed since this investigation started">
          Started with v{inv.playbookVersion}; the library now has v{pb.version}. Steps and questions shown are from the current version.
        </Callout>
      )}
      {pb && <DraftNotice pb={pb} />}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          {!pb ? (
            <Callout tone="warning" title="Playbook unavailable">
              The playbook this investigation used is no longer in the library. Recorded evidence, findings, and notes remain available on the right.
            </Callout>
          ) : (
            <>
              <Card title={`Investigation steps (${progress.stepsDone}/${progress.stepsTotal})`}>
                <ol className="space-y-2">
                  {pb.steps.map((s, i) => (
                    <StepCard
                      key={s.id}
                      step={s}
                      number={i + 1}
                      playbookId={pb.id}
                      defaultOpen={i === pb.steps.findIndex((x) => !inv.steps[x.id]?.done)}
                      state={inv.steps[s.id]}
                      evidence={inv.evidence}
                      queries={s.queryIds.map((qid) => queriesById.get(qid)).filter((q): q is NonNullable<typeof q> => !!q)}
                      onToggle={(done) => mutate((x) => setStepDone(x, s.id, done))}
                      onNotes={(notes) => mutate((x) => setStepNotes(x, s.id, notes))}
                    />
                  ))}
                </ol>
                {staleSteps.length > 0 && <p className="mt-2 text-xs text-faint">Recorded progress for steps no longer in this playbook version: {staleSteps.join(', ')} (kept in the export).</p>}
              </Card>
              <Card title="Decision tree">
                <DecisionTree
                  playbook={pb}
                  answers={inv.decisionPath}
                  onAnswer={(nodeId, answer) => mutate((x) => answerDecision(x, pb, nodeId, answer))}
                  onReset={() => mutate((x) => resetDecision(x))}
                  applied={!!decision?.outcome && inv.disposition.recommendation === OUTCOME_INFO[decision.outcome].disposition}
                  onApply={(outcome, guidance) => {
                    mutate((x) => applyOutcome(x, outcome, guidance));
                    notify('Decision outcome applied to disposition and status. Review the Assessment tab.', 'success');
                  }}
                />
              </Card>
              <Card title="All query templates for this playbook">
                <p className="mb-2 text-xs text-muted">Placeholders are pre-filled from recorded evidence where possible. Copy and run them in your own SIEM.</p>
                <div className="space-y-2">
                  {pb.queries.map((q) => (
                    <QueryCard key={q.id} query={q} evidence={inv.evidence} playbookId={`ws-${pb.id}`} />
                  ))}
                </div>
              </Card>
            </>
          )}
        </div>

        <div className="min-w-0">
          <div className="sticky top-16 rounded-lg border border-line bg-panel">
            <div className="px-3 pt-2">
              <Tabs
                label="Investigation record"
                value={tab}
                onChange={setTab}
                tabs={[
                  { id: 'evidence', label: 'Evidence', count: Object.keys(inv.evidence).length },
                  { id: 'findings', label: 'Findings', count: inv.findings.length + inv.timeline.length },
                  { id: 'assessment', label: 'Assessment' },
                  { id: 'assistant', label: 'Assistant' },
                  { id: 'notes', label: 'Notes' },
                ]}
              />
            </div>
            <TabPanel id={tab} className="scroll-thin max-h-[calc(100vh-9rem)] overflow-y-auto p-4">
              {tab === 'evidence' && <EvidenceTab inv={inv} pb={pb} mutate={mutate} />}
              {tab === 'findings' && <FindingsTab inv={inv} mutate={mutate} />}
              {tab === 'assessment' && <AssessmentTab inv={inv} mutate={mutate} />}
              {tab === 'assistant' && <AssistantTab inv={inv} pb={pb} />}
              {tab === 'notes' && <NotesTab inv={inv} mutate={mutate} />}
            </TabPanel>
          </div>
        </div>
      </div>
    </div>
  );
}

type Mutate = (fn: (i: Investigation) => Investigation) => void;

function EvidenceTab({ inv, pb, mutate }: { inv: Investigation; pb: Playbook | undefined; mutate: Mutate }) {
  const fields = pb?.evidence ?? Object.keys(inv.evidence).map((id) => ({ id, label: id, hint: '', required: false, multiline: true }));
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">
        Record only what the investigation needs. Treat alert text and <Term term="Command line">command lines</Term> as untrusted. Never paste passwords, tokens, or secrets.
      </p>
      {fields.map((f) => {
        const value = inv.evidence[f.id] ?? '';
        const id = `ev-${f.id}`;
        return (
          <div key={f.id}>
            <label htmlFor={id} className="mb-1 flex items-center gap-1.5 text-sm font-medium text-fg-strong">
              {value.trim() ? <CheckCircle2 className="h-4 w-4 text-ok" aria-label="recorded" /> : <Circle className="h-4 w-4 text-faint" aria-label="not recorded" />}
              {f.label}
              {f.required ? <Badge tone="warn">Required</Badge> : <Badge>If relevant</Badge>}
            </label>
            {f.multiline ? (
              <DeferredTextArea id={id} value={value} rows={3} maxLength={8000} onCommit={(v) => mutate((i) => setEvidence(i, f.id, v))} className="font-mono text-xs" />
            ) : (
              <DeferredInput id={id} value={value} maxLength={8000} onCommit={(v) => mutate((i) => setEvidence(i, f.id, v))} />
            )}
            {f.hint && <p className="mt-0.5 text-xs text-faint">{f.hint}</p>}
          </div>
        );
      })}
    </div>
  );
}

function FindingsTab({ inv, mutate }: { inv: Investigation; mutate: Mutate }) {
  const [kind, setKind] = useState<FindingKind>('supporting');
  const [text, setText] = useState('');
  const [time, setTime] = useState('');
  const [desc, setDesc] = useState('');
  const [source, setSource] = useState('');
  const KIND_LABEL: Record<FindingKind, string> = { supporting: 'Supports suspicion', contradicting: 'Supports benign explanation', observation: 'Neutral observation' };
  const KIND_TONE = { supporting: 'bad', contradicting: 'ok', observation: 'neutral' } as const;
  return (
    <div className="space-y-5">
      <section>
        <h3 className="mb-2 text-sm font-semibold text-fg-strong">Findings and observations</h3>
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutate((i) => addFinding(i, kind, text));
            setText('');
          }}
        >
          <div className="flex gap-2">
            <label htmlFor="f-kind" className="sr-only">
              Finding type
            </label>
            <select id="f-kind" className="input w-56" value={kind} onChange={(e) => setKind(e.target.value as FindingKind)}>
              {FINDING_KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </select>
            <Button type="submit" icon={<Plus className="h-4 w-4" aria-hidden />} disabled={!text.trim()}>
              Add
            </Button>
          </div>
          <label htmlFor="f-text" className="sr-only">
            Finding
          </label>
          <textarea id="f-text" className="input" rows={2} maxLength={8000} value={text} onChange={(e) => setText(e.target.value)} placeholder="State what you observed and where (source, time)." />
        </form>
        {inv.findings.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No findings yet. Record both supporting and contradicting evidence.</p>
        ) : (
          <ul className="mt-2 space-y-1.5">
            {inv.findings.map((f) => (
              <li key={f.id} className="flex items-start gap-2 rounded-md border border-line bg-panel-2 px-2.5 py-1.5 text-sm">
                <Badge tone={KIND_TONE[f.kind]} className="mt-0.5 shrink-0">
                  {KIND_LABEL[f.kind]}
                </Badge>
                <span className="min-w-0 flex-1 break-words whitespace-pre-wrap">{f.text}</span>
                <RemoveButton label="Remove finding" onClick={() => mutate((i) => removeListItem(i, 'findings', f.id))} />
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h3 className="mb-2 text-sm font-semibold text-fg-strong">Timeline</h3>
        <form
          className="grid gap-2 sm:grid-cols-[11rem_1fr]"
          onSubmit={(e) => {
            e.preventDefault();
            mutate((i) => addTimelineEntry(i, { time, description: desc, source }));
            setDesc('');
            setTime('');
          }}
        >
          <div>
            <label htmlFor="t-time" className="label">
              Time (UTC, ISO 8601)
            </label>
            <input id="t-time" className="input" value={time} maxLength={200} onChange={(e) => setTime(e.target.value)} placeholder="2026-10-10T14:03:11Z" />
          </div>
          <div>
            <label htmlFor="t-source" className="label">
              Source
            </label>
            <input id="t-source" className="input" value={source} maxLength={200} onChange={(e) => setSource(e.target.value)} placeholder="e.g. DeviceProcessEvents, 4624" />
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="t-desc" className="label">
              Event
            </label>
            <div className="flex gap-2">
              <input id="t-desc" className="input" value={desc} maxLength={8000} onChange={(e) => setDesc(e.target.value)} placeholder="What happened" />
              <Button type="submit" icon={<Plus className="h-4 w-4" aria-hidden />} disabled={!desc.trim()}>
                Add
              </Button>
            </div>
          </div>
        </form>
        {inv.timeline.length > 0 && (
          <ol className="mt-3 space-y-1 border-l border-line-strong pl-3">
            {sortedTimeline(inv).map((t) => (
              <li key={t.id} className="relative flex items-start gap-2 text-sm">
                <span className="absolute top-1.5 -left-[17px] h-2 w-2 rounded-full bg-accent" aria-hidden />
                <span className="w-44 shrink-0 font-mono text-xs text-muted">{t.time || 'time unknown'}</span>
                <span className="min-w-0 flex-1 break-words">
                  {t.description} {t.source && <span className="text-xs text-faint">[{t.source}]</span>}
                </span>
                <RemoveButton label="Remove timeline entry" onClick={() => mutate((i) => removeListItem(i, 'timeline', t.id))} />
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}

function AssessmentTab({ inv, mutate }: { inv: Investigation; mutate: Mutate }) {
  const { attack, openTechnique } = useApp();
  const [techId, setTechId] = useState('');
  const [techNote, setTechNote] = useState('');
  const techError = techId && !attack.index?.get(techId.trim().toUpperCase()) ? (attack.index ? 'Not an active ATT&CK technique ID.' : 'ATT&CK data not loaded.') : null;
  return (
    <div className="space-y-5">
      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-fg-strong">Suspicion and confidence</h3>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Assessment" htmlFor="a-susp">
            <select id="a-susp" className="input" value={inv.assessment.suspicion} onChange={(e) => mutate((i) => update(i, 'assessment', { ...i.assessment, suspicion: e.target.value as Investigation['assessment']['suspicion'] }))}>
              {SUSPICION_LEVELS.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Confidence" htmlFor="a-conf">
            <select id="a-conf" className="input" value={inv.assessment.confidence} onChange={(e) => mutate((i) => update(i, 'assessment', { ...i.assessment, confidence: e.target.value as Investigation['assessment']['confidence'] }))}>
              {CONFIDENCE_LEVELS.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        </div>
        <Field label="Rationale" htmlFor="a-rat" hint="Cite the evidence. If evidence is insufficient, say so - do not force a benign verdict.">
          <DeferredTextArea id="a-rat" value={inv.assessment.rationale} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'assessment', { ...i.assessment, rationale: v }))} />
        </Field>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-fg-strong">Related ATT&amp;CK techniques (hypotheses)</h3>
        <ul className="space-y-1">
          {inv.relatedTechniques.map((t) => (
            <li key={t.id} className="flex items-start gap-2 text-sm">
              <button type="button" className="font-mono text-xs text-accent hover:underline" onClick={() => openTechnique(t.id)}>
                {t.id}
              </button>
              <span className="min-w-0 flex-1">
                {attack.index?.get(t.id)?.name} {t.note && <span className="text-xs text-muted">- {t.note}</span>}
              </span>
              <RemoveButton label={`Remove ${t.id}`} onClick={() => mutate((i) => update(i, 'relatedTechniques', i.relatedTechniques.filter((x) => x.id !== t.id)))} />
            </li>
          ))}
        </ul>
        <form
          className="flex flex-wrap items-start gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const tid = techId.trim().toUpperCase();
            if (techError || !tid || inv.relatedTechniques.some((x) => x.id === tid)) return;
            mutate((i) => update(i, 'relatedTechniques', [...i.relatedTechniques, { id: tid, note: techNote.trim().slice(0, 8000) }]));
            setTechId('');
            setTechNote('');
          }}
        >
          <div className="w-28">
            <label htmlFor="rt-id" className="sr-only">
              Technique ID
            </label>
            <input id="rt-id" className={cx('input font-mono', techError && 'border-bad')} placeholder="T1059.001" value={techId} onChange={(e) => setTechId(e.target.value)} aria-invalid={!!techError} aria-describedby="rt-err" />
          </div>
          <div className="min-w-[10rem] flex-1">
            <label htmlFor="rt-note" className="sr-only">
              Supporting reason
            </label>
            <input id="rt-note" className="input" placeholder="Evidence that supports this mapping" value={techNote} maxLength={8000} onChange={(e) => setTechNote(e.target.value)} />
          </div>
          <Button type="submit" icon={<Plus className="h-4 w-4" aria-hidden />} disabled={!techId.trim() || !!techError}>
            Add
          </Button>
          {techError && (
            <p id="rt-err" className="w-full text-xs text-bad">
              {techError}
            </p>
          )}
        </form>
      </section>

      <ListEditor title="Missing information and telemetry gaps" hint="Missing data is not proof that nothing happened. Be specific: which log, field, or access." items={inv.missingInfo} onAdd={(t) => mutate((i) => addListItem(i, 'missingInfo', t))} onRemove={(id) => mutate((i) => removeListItem(i, 'missingInfo', id))} />
      <ListEditor title="Outstanding questions" items={inv.openQuestions} onAdd={(t) => mutate((i) => addListItem(i, 'openQuestions', t))} onRemove={(id) => mutate((i) => removeListItem(i, 'openQuestions', id))} />

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-fg-strong">
          <Term term="Disposition">Disposition</Term> recommendation
        </h3>
        <Field label="Recommendation" htmlFor="d-rec">
          <select id="d-rec" className="input" value={inv.disposition.recommendation} onChange={(e) => mutate((i) => setDisposition(i, e.target.value as Disposition, i.disposition.rationale))}>
            {DISPOSITIONS.map((d) => (
              <option key={d}>{d}</option>
            ))}
          </select>
        </Field>
        <Field label="Rationale" htmlFor="d-rat">
          <DeferredTextArea id="d-rat" value={inv.disposition.rationale} maxLength={8000} onCommit={(v) => mutate((i) => setDisposition(i, i.disposition.recommendation, v))} />
        </Field>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold text-fg-strong">Escalation details</h3>
        <Field label="Reason for escalation" htmlFor="e-reason">
          <DeferredTextArea id="e-reason" value={inv.escalation.reason} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'escalation', { ...i.escalation, reason: v }))} />
        </Field>
        <Field label="Recommended next investigative steps" htmlFor="e-next">
          <DeferredTextArea id="e-next" value={inv.escalation.nextSteps} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'escalation', { ...i.escalation, nextSteps: v }))} />
        </Field>
        <Field label="Escalated to (team / person)" htmlFor="e-to">
          <DeferredInput id="e-to" value={inv.escalation.recipient} maxLength={200} onCommit={(v) => mutate((i) => update(i, 'escalation', { ...i.escalation, recipient: v }))} />
        </Field>
        <Field label="Executive summary for the handoff (optional)" htmlFor="e-sum" hint="Leave empty to use the generated summary.">
          <DeferredTextArea id="e-sum" value={inv.executiveSummary} maxLength={8000} onCommit={(v) => mutate((i) => update(i, 'executiveSummary', v))} />
        </Field>
        <Link to={`/reports/${inv.id}`} className="inline-flex items-center gap-1 text-sm text-accent hover:underline">
          <FileText className="h-4 w-4" aria-hidden /> Preview and export the Tier 2 handoff report
        </Link>
      </section>
    </div>
  );
}

function ListEditor({ title, hint, items, onAdd, onRemove }: { title: string; hint?: string; items: { id: string; text: string }[]; onAdd: (t: string) => void; onRemove: (id: string) => void }) {
  const [text, setText] = useState('');
  const inputId = `le-${title.replace(/\W+/g, '-').toLowerCase()}`;
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-semibold text-fg-strong">{title}</h3>
      {hint && <p className="text-xs text-muted">{hint}</p>}
      <ul className="space-y-1">
        {items.map((m) => (
          <li key={m.id} className="flex items-start gap-2 rounded-md border border-line bg-panel-2 px-2.5 py-1 text-sm">
            <span className="min-w-0 flex-1 break-words">{m.text}</span>
            <RemoveButton label="Remove item" onClick={() => onRemove(m.id)} />
          </li>
        ))}
      </ul>
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          onAdd(text);
          setText('');
        }}
      >
        <label htmlFor={inputId} className="sr-only">
          Add to {title}
        </label>
        <input id={inputId} className="input" value={text} maxLength={8000} onChange={(e) => setText(e.target.value)} placeholder="Add an item" />
        <Button type="submit" icon={<Plus className="h-4 w-4" aria-hidden />} disabled={!text.trim()}>
          Add
        </Button>
      </form>
    </section>
  );
}

function AssistantTab({ inv, pb }: { inv: Investigation; pb: Playbook | undefined }) {
  const { attack, settings } = useApp();
  const [result, setResult] = useState<AssistantResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const remote = settings.assistant.mode === 'remote-proxy' && settings.assistant.consent;
  const run = async (task: AssistantTask, useRemote: boolean) => {
    setError(null);
    setBusy(true);
    try {
      const ctx = { investigation: inv, playbook: pb, index: attack.index };
      setResult(useRemote ? await runRemoteTask(task, ctx, settings.assistant) : runLocalTask(task, ctx));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Assistant request failed.');
    } finally {
      setBusy(false);
    }
  };
  const groups = useMemo(
    () =>
      result
        ? ([
            ['Observed facts (from your recorded data)', result.facts, 'border-line'],
            ['Hypotheses (unconfirmed)', result.hypotheses, 'border-warn/40'],
            ['Recommendations (advisory)', result.recommendations, 'border-accent/40'],
          ] as const)
        : [],
    [result],
  );
  return (
    <div className="space-y-3">
      <Callout tone="info" title="Advisory only">
        The assistant cannot close incidents, change status, contain hosts, or run queries. The default provider is an offline rule engine that only reads data you recorded. {remote ? 'A remote provider is enabled via your proxy.' : 'No external AI service is configured.'}
      </Callout>
      <div className="flex flex-wrap gap-2">
        {ASSISTANT_TASKS.map((t) => (
          <Button key={t} size="sm" icon={<Bot className="h-3.5 w-3.5" aria-hidden />} disabled={busy} onClick={() => void run(t, false)}>
            {TASK_LABEL[t]}
          </Button>
        ))}
      </div>
      {remote && result && result.provider === 'local-rules' && result.task !== 'explain-query' && result.task !== 'explain-term' && (
        <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run(result.task as AssistantTask, true)}>
          Ask the remote provider for this task (sends minimized investigation data to your proxy)
        </Button>
      )}
      {error && <Callout tone="danger">{error}</Callout>}
      {result && (
        <div className="space-y-2" aria-live="polite">
          <p className="flex items-center gap-2 text-sm font-semibold text-fg-strong">
            {result.title} <Badge>{result.provider === 'local-rules' ? 'Local rules (offline)' : 'Remote via proxy'}</Badge>
          </p>
          {result.warnings.map((w) => (
            <Callout key={w} tone="warning">
              {w}
            </Callout>
          ))}
          {groups.map(([title, items, border]) =>
            items.length ? (
              <div key={title} className={cx('rounded-md border p-2.5 text-sm', border)}>
                <p className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">{title}</p>
                <ul className="list-disc space-y-0.5 pl-4">
                  {items.map((x, i) => (
                    <li key={i} className="break-words">
                      {x}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null,
          )}
          {result.draft && (
            <div>
              <p className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Draft (review and edit in Reports)</p>
              <pre className="scroll-thin max-h-72 overflow-auto rounded-md border border-line bg-bg p-2.5 text-xs whitespace-pre-wrap">{result.draft}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function NotesTab({ inv, mutate }: { inv: Investigation; mutate: Mutate }) {
  return (
    <div className="space-y-4">
      <Field label="Investigation notes" htmlFor="n-notes" hint="Saved automatically.">
        <DeferredTextArea id="n-notes" rows={8} maxLength={20000} value={inv.notes} onCommit={(v) => mutate((i) => update(i, 'notes', v))} />
      </Field>
      <section>
        <h3 className="mb-1 text-sm font-semibold text-fg-strong">Activity log</h3>
        <p className="mb-2 text-xs text-faint">Local audit trail for this browser only - not a tamper-proof audit log.</p>
        <ul className="space-y-1 text-xs">
          {inv.activity.map((a, i) => (
            <li key={i} className="flex gap-2">
              <span className="w-36 shrink-0 text-faint">{formatDate(a.at)}</span>
              <span className="text-muted">{a.text}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function RemoveButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} aria-label={label} className="shrink-0 rounded p-0.5 text-faint hover:bg-bad/10 hover:text-bad">
      <X className="h-3.5 w-3.5" aria-hidden />
    </button>
  );
}

import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ArrowDown, ArrowLeft, ArrowUp, Eye, Plus, Save, Trash2 } from 'lucide-react';
import { PlaybookStatusBadge } from '../components/badges';
import { PlaybookView } from '../components/playbook/PlaybookView';
import { Badge, Button, Callout, Card, Field, PageHeader, TabPanel, Tabs, cx } from '../components/ui';
import { LOG_SOURCES } from '../data/logSources';
import { blankPlaybook, bumpVersion, nextLocalId, withStatus } from '../lib/playbooks/library';
import { DIFFICULTIES, OUTCOMES, PLACEHOLDER_KINDS, PLAYBOOK_STATUSES, PREREQ_TYPES, QUERY_LANGUAGES, playbookSchema } from '../lib/playbooks/schema';
import type { DecisionBranch, Playbook, PlaybookStatus, QueryTemplate } from '../lib/playbooks/schema';
import { OUTCOME_INFO } from '../lib/playbooks/outcomes';
import { useApp } from '../state/AppState';

const toLines = (xs: string[]) => xs.join('\n');
const fromLines = (s: string) =>
  s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean);

/** Stable content fingerprint excluding review metadata, used to reset approval on edits. */
function contentKey(pb: Playbook): string {
  const { review: _r, status: _s, version: _v, updatedAt: _u, source: _src, ...rest } = pb;
  return JSON.stringify(rest);
}

export function PlaybookEditorPage() {
  const { id } = useParams();
  const { playbookById, library, settings, savePlaybook, attack, notify } = useApp();
  const navigate = useNavigate();
  const isNew = !id;
  const original = id ? playbookById.get(id) : undefined;

  const [draft, setDraft] = useState<Playbook | null>(null);
  useEffect(() => {
    if (draft) return;
    if (isNew) setDraft(blankPlaybook(nextLocalId(library.map((e) => e.playbook.id)), settings.analystName));
    else if (original) setDraft(structuredClone(original));
  }, [draft, isNew, original, library, settings.analystName]);

  const [tab, setTab] = useState<'edit' | 'preview'>('edit');
  const [bump, setBump] = useState<'none' | 'patch' | 'minor' | 'major'>('patch');
  const [errors, setErrors] = useState<string[]>([]);
  const [reviewNote, setReviewNote] = useState('');
  const canAuthor = settings.role !== 'analyst';
  const canReview = settings.role === 'reviewer';

  const techniqueProblems = useMemo(() => {
    if (!draft || !attack.index) return [];
    return [...draft.techniques, ...draft.relatedTechniques.map((r) => r.id)].filter((t) => !attack.index!.get(t)).map((t) => `${t} is not an active technique in ATT&CK ${attack.index!.dataset.meta.version}.`);
  }, [draft, attack.index]);

  if (!isNew && !original) {
    return (
      <Callout tone="danger" title={`Playbook ${id} not found`}>
        <Link to="/playbooks?tab=manage" className="text-accent hover:underline">
          Back to playbook management
        </Link>
      </Callout>
    );
  }
  if (!draft) return null;

  const set = <K extends keyof Playbook>(key: K, value: Playbook[K]) => setDraft((d) => (d ? { ...d, [key]: value } : d));
  const contentChanged = !original || contentKey(original) !== contentKey(draft);

  const save = (nextStatus?: PlaybookStatus) => {
    if (!canAuthor) return;
    let pb: Playbook = { ...draft, source: 'local', updatedAt: new Date().toISOString().slice(0, 10) };
    if (contentChanged && bump !== 'none' && original) pb.version = bumpVersion(original.version, bump);
    if (nextStatus && nextStatus !== 'Draft') {
      if (!canReview) return setErrors(['Only the Playbook reviewer role can mark a playbook Reviewed or Approved.']);
      if (!settings.analystName.trim()) return setErrors(['Set your analyst identifier in Settings before reviewing.']);
      if (nextStatus === 'Approved' && settings.analystName === pb.review.author) return setErrors(['The approver must be a different person from the author (separation of duties).']);
      if (pb.aiAssisted && !reviewNote.trim()) return setErrors(['AI-assisted content needs a review note describing what was validated.']);
      pb = withStatus(pb, nextStatus, settings.analystName, reviewNote.trim() || `Marked ${nextStatus}.`);
    } else if (nextStatus === 'Draft' && pb.status !== 'Draft') {
      pb = withStatus(pb, 'Draft', settings.analystName, reviewNote.trim() || 'Returned to Draft.');
    } else if (contentChanged && original && original.status !== 'Draft') {
      pb = withStatus({ ...pb, status: 'Draft' }, 'Draft', settings.analystName, `Content edited in v${pb.version}; review status reset to Draft.`);
    } else if (contentChanged) {
      pb = { ...pb, review: { ...pb.review, history: [...pb.review.history, { version: pb.version, status: pb.status, by: settings.analystName, at: new Date().toISOString(), note: isNew ? 'Created.' : 'Content edited.' }].slice(-100) } };
    }
    if (isNew && library.some((e) => e.playbook.id === pb.id)) return setErrors([`Playbook ID ${pb.id} already exists. Choose another ID.`]);
    const r = playbookSchema.safeParse(pb);
    const problems = [...techniqueProblems, ...(r.success ? [] : r.error.issues.slice(0, 15).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`))];
    if (problems.length) {
      setErrors(problems);
      notify('Playbook not saved - fix the listed problems.', 'danger');
      return;
    }
    if (savePlaybook(r.data!)) {
      setErrors([]);
      setDraft(r.data!);
      setReviewNote('');
      notify(`${pb.id} v${pb.version} saved (${pb.status}).`, 'success');
      if (isNew) navigate(`/playbooks/${pb.id}/edit`, { replace: true });
    }
  };

  return (
    <div className="space-y-4">
      <Link to="/playbooks?tab=manage" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
        <ArrowLeft className="h-4 w-4" aria-hidden /> Playbook management
      </Link>
      <PageHeader
        title={isNew ? 'New playbook' : `Edit ${draft.id}`}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <PlaybookStatusBadge status={draft.status} /> v{draft.version}
            {original?.source === 'starter-library' && <Badge tone="info">Saving creates a local revision of the starter playbook</Badge>}
          </span>
        }
        actions={
          <>
            <label htmlFor="ed-bump" className="text-xs text-muted">
              Version bump
            </label>
            <select id="ed-bump" className="input w-28 py-1" value={bump} onChange={(e) => setBump(e.target.value as typeof bump)} disabled={isNew}>
              <option value="none">none</option>
              <option value="patch">patch</option>
              <option value="minor">minor</option>
              <option value="major">major</option>
            </select>
            <Button variant="primary" icon={<Save className="h-4 w-4" aria-hidden />} disabled={!canAuthor} onClick={() => save()}>
              Save
            </Button>
          </>
        }
      />
      {!canAuthor && <Callout tone="warning">Your role is Tier 1 analyst. Switch to Playbook author or reviewer in Settings to save changes.</Callout>}
      {contentChanged && original && original.status !== 'Draft' && <Callout tone="info">Saving content changes resets the review status to Draft so the change can be reviewed again.</Callout>}
      {errors.length > 0 && (
        <Callout tone="danger" title="Validation problems">
          <ul className="list-disc pl-4">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Callout>
      )}

      <Tabs
        label="Editor views"
        value={tab}
        onChange={setTab}
        tabs={[
          { id: 'edit', label: 'Edit' },
          { id: 'preview', label: <span className="inline-flex items-center gap-1"><Eye className="h-3.5 w-3.5" aria-hidden /> Preview as Tier 1 analyst</span> },
        ]}
      />
      <TabPanel id={tab}>
        {tab === 'preview' ? (
          <div className="pt-3">
            <PlaybookView pb={draft} preview />
          </div>
        ) : (
          <div className="space-y-4 pt-3">
            <OverviewEditor draft={draft} set={set} techniqueProblems={techniqueProblems} isNew={isNew} />
            <StepsEditor draft={draft} set={set} />
            <DecisionEditor draft={draft} set={set} />
            <EvidenceEditor draft={draft} set={set} />
            <Card title="Escalation criteria">
              <div className="grid gap-3 md:grid-cols-3">
                <LinesField id="esc-imm" label="Immediate incident escalation" value={draft.escalation.immediate} onChange={(v) => set('escalation', { ...draft.escalation, immediate: v })} />
                <LinesField id="esc-t2" label="Escalate to Tier 2 when" value={draft.escalation.tier2} onChange={(v) => set('escalation', { ...draft.escalation, tier2: v })} />
                <LinesField id="esc-ben" label="Close as benign only when" value={draft.escalation.benignClosure} onChange={(v) => set('escalation', { ...draft.escalation, benignClosure: v })} />
              </div>
            </Card>
            <QueriesEditor draft={draft} set={set} />
            <Card title="Detection notes, references, and assumptions">
              <div className="grid gap-3 md:grid-cols-2">
                <LinesField id="det" label="Detection considerations" value={draft.detectionConsiderations} onChange={(v) => set('detectionConsiderations', v)} />
                <LinesField id="gaps" label="Known limitations / visibility gaps" value={draft.visibilityGaps} onChange={(v) => set('visibilityGaps', v)} />
                <LinesField
                  id="rel"
                  label="Related techniques (one per line: T1234.001: reason)"
                  value={draft.relatedTechniques.map((r) => `${r.id}: ${r.reason}`)}
                  onChange={(v) => set('relatedTechniques', v.map((l) => ({ id: l.split(':')[0].trim().toUpperCase(), reason: l.split(':').slice(1).join(':').trim() || 'Related technique.' })))}
                />
                <LinesField
                  id="refs"
                  label="References (one per line: Title | https://url)"
                  value={draft.references.map((r) => `${r.title} | ${r.url}`)}
                  onChange={(v) => set('references', v.map((l) => ({ title: l.split('|')[0].trim(), url: (l.split('|')[1] ?? '').trim() })))}
                />
                <LinesField id="assume" label="Assumptions" value={draft.assumptions} onChange={(v) => set('assumptions', v)} />
              </div>
            </Card>
            <Card title="Review and approval">
              <div className="space-y-3 text-sm">
                <p>
                  Author: <strong>{draft.review.author}</strong> - Last reviewer: <strong>{draft.review.reviewer ?? 'none'}</strong> - Current status: <PlaybookStatusBadge status={draft.status} />
                </p>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={draft.aiAssisted} onChange={(e) => set('aiAssisted', e.target.checked)} />
                  Contains AI-assisted content (must remain Draft until reviewed by an authorized person)
                </label>
                <Field label="Review notes (shown to analysts)" htmlFor="rv-notes">
                  <textarea id="rv-notes" className="input" rows={2} maxLength={2000} value={draft.review.notes} onChange={(e) => set('review', { ...draft.review, notes: e.target.value })} />
                </Field>
                <Field label="Review note for this status change" htmlFor="rv-note" hint="What did you validate (telemetry, queries, escalation thresholds)?">
                  <textarea id="rv-note" className="input" rows={2} maxLength={2000} value={reviewNote} onChange={(e) => setReviewNote(e.target.value)} />
                </Field>
                <div className="flex flex-wrap gap-2">
                  {PLAYBOOK_STATUSES.filter((s) => s !== draft.status).map((s) => (
                    <Button key={s} size="sm" disabled={!canAuthor || (s !== 'Draft' && !canReview)} onClick={() => save(s)}>
                      Save and mark {s}
                    </Button>
                  ))}
                </div>
                {!canReview && <p className="text-xs text-faint">Marking Reviewed or Approved requires the reviewer role (Settings). The approver must differ from the author.</p>}
                <ul className="space-y-0.5 text-xs text-muted">
                  {[...draft.review.history].reverse().map((h, i) => (
                    <li key={i}>
                      {h.at.slice(0, 19).replace('T', ' ')} - v{h.version} - {h.status} - {h.by}
                      {h.note && `: ${h.note}`}
                    </li>
                  ))}
                </ul>
              </div>
            </Card>
          </div>
        )}
      </TabPanel>
    </div>
  );
}

type SetFn = <K extends keyof Playbook>(key: K, value: Playbook[K]) => void;

function OverviewEditor({ draft, set, techniqueProblems, isNew }: { draft: Playbook; set: SetFn; techniqueProblems: string[]; isNew: boolean }) {
  const { attack } = useApp();
  return (
    <Card title="Overview">
      <div className="grid gap-3 md:grid-cols-2">
        <Field label="Playbook ID" htmlFor="ov-id" hint={isNew ? 'Format PB-XXXX-001.' : 'IDs cannot change after creation.'}>
          <input id="ov-id" className="input font-mono" value={draft.id} disabled={!isNew} maxLength={44} onChange={(e) => set('id', e.target.value.toUpperCase())} />
        </Field>
        <Field label="Title" htmlFor="ov-title" required>
          <input id="ov-title" className="input" value={draft.title} maxLength={200} onChange={(e) => set('title', e.target.value)} />
        </Field>
        <Field label="ATT&CK technique IDs (comma-separated; first is primary)" htmlFor="ov-tech" hint={techniqueProblems.length ? techniqueProblems.join(' ') : 'Validated against the loaded ATT&CK dataset.'}>
          <CommaField id="ov-tech" value={draft.techniques} upper onChange={(v) => set('techniques', v)} invalid={techniqueProblems.length > 0} />
        </Field>
        <Field label="Platforms (comma-separated)" htmlFor="ov-plat">
          <CommaField id="ov-plat" value={draft.platforms} onChange={(v) => set('platforms', v)} />
        </Field>
        <fieldset className="md:col-span-2">
          <legend className="label">Tactics</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
            {(attack.index?.tactics ?? []).map((t) => (
              <label key={t.shortname} className="flex items-center gap-1.5">
                <input type="checkbox" checked={draft.tactics.includes(t.shortname)} onChange={(e) => set('tactics', e.target.checked ? [...draft.tactics, t.shortname] : draft.tactics.filter((x) => x !== t.shortname))} />
                {t.name}
              </label>
            ))}
          </div>
        </fieldset>
        <TextField id="ov-obj" label="Objective" value={draft.objective} onChange={(v) => set('objective', v)} />
        <TextField id="ov-mean" label="What the alert means" value={draft.alertMeaning} onChange={(v) => set('alertMeaning', v)} />
        <TextField id="ov-why" label="Why this activity matters" value={draft.whyItMatters} onChange={(v) => set('whyItMatters', v)} />
        <div className="grid grid-cols-2 gap-3">
          <Field label="Difficulty" htmlFor="ov-diff">
            <select id="ov-diff" className="input" value={draft.difficulty} onChange={(e) => set('difficulty', e.target.value as Playbook['difficulty'])}>
              {DIFFICULTIES.map((d) => (
                <option key={d}>{d}</option>
              ))}
            </select>
          </Field>
          <Field label="Estimated effort" htmlFor="ov-eff">
            <input id="ov-eff" className="input" value={draft.effort} maxLength={200} onChange={(e) => set('effort', e.target.value)} />
          </Field>
        </div>
        <fieldset className="md:col-span-2">
          <legend className="label">Log sources</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
            {LOG_SOURCES.map((s) => (
              <label key={s.id} className="flex items-center gap-1.5">
                <input type="checkbox" checked={draft.logSources.includes(s.id)} onChange={(e) => set('logSources', e.target.checked ? [...draft.logSources, s.id] : draft.logSources.filter((x) => x !== s.id))} />
                {s.name}
              </label>
            ))}
          </div>
        </fieldset>
        <LinesField id="ac-trig" label="Alerts that trigger this playbook" value={draft.alertContext.triggers} onChange={(v) => set('alertContext', { ...draft.alertContext, triggers: v })} />
        <LinesField id="ac-first" label="What to review first" value={draft.alertContext.reviewFirst} onChange={(v) => set('alertContext', { ...draft.alertContext, reviewFirst: v })} />
        <LinesField id="ac-miss" label="Often missing from the alert" value={draft.alertContext.oftenMissing} onChange={(v) => set('alertContext', { ...draft.alertContext, oftenMissing: v })} />
        <div>
          <p className="label">Prerequisites</p>
          <RowList
            items={draft.prerequisites}
            onChange={(v) => set('prerequisites', v)}
            make={() => ({ text: 'New prerequisite', type: 'telemetry' as const, required: false })}
            render={(p, upd) => (
              <div className="flex flex-wrap items-center gap-2">
                <input aria-label="Prerequisite" className="input min-w-[12rem] flex-1" value={p.text} maxLength={2000} onChange={(e) => upd({ ...p, text: e.target.value })} />
                <select aria-label="Type" className="input w-28" value={p.type} onChange={(e) => upd({ ...p, type: e.target.value as typeof p.type })}>
                  {PREREQ_TYPES.map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
                <label className="flex items-center gap-1 text-xs">
                  <input type="checkbox" checked={p.required} onChange={(e) => upd({ ...p, required: e.target.checked })} /> mandatory
                </label>
              </div>
            )}
          />
        </div>
      </div>
    </Card>
  );
}

function StepsEditor({ draft, set }: { draft: Playbook; set: SetFn }) {
  return (
    <Card title={`Investigation steps (${draft.steps.length})`}>
      <RowList
        items={draft.steps}
        onChange={(v) => set('steps', v)}
        make={() => ({ id: `step-${draft.steps.length + 1}`, title: 'New step', action: 'What to do.', why: 'Why it matters.', where: ['Where to look'], fields: [], suspicious: ['What is suspicious'], legitimate: [], next: 'What to do next.', queryIds: [] })}
        render={(s, upd, i) => (
          <div className="grid gap-2 md:grid-cols-2">
            <Field label={`Step ${i + 1} ID`} htmlFor={`st-id-${i}`}>
              <input id={`st-id-${i}`} className="input font-mono" value={s.id} maxLength={48} onChange={(e) => upd({ ...s, id: e.target.value.toLowerCase() })} />
            </Field>
            <Field label="Title" htmlFor={`st-t-${i}`}>
              <input id={`st-t-${i}`} className="input" value={s.title} maxLength={200} onChange={(e) => upd({ ...s, title: e.target.value })} />
            </Field>
            <TextField id={`st-a-${i}`} label="What to do" value={s.action} onChange={(v) => upd({ ...s, action: v })} />
            <TextField id={`st-w-${i}`} label="Why this step matters" value={s.why} onChange={(v) => upd({ ...s, why: v })} />
            <LinesField id={`st-where-${i}`} label="Where to investigate" value={s.where} onChange={(v) => upd({ ...s, where: v })} />
            <LinesField id={`st-f-${i}`} label="Fields / events to inspect" value={s.fields} onChange={(v) => upd({ ...s, fields: v })} />
            <LinesField id={`st-s-${i}`} label="Suspicious evidence" value={s.suspicious} onChange={(v) => upd({ ...s, suspicious: v })} />
            <LinesField id={`st-l-${i}`} label="Legitimate explanations" value={s.legitimate} onChange={(v) => upd({ ...s, legitimate: v })} />
            <TextField id={`st-n-${i}`} label="What to do next" value={s.next} onChange={(v) => upd({ ...s, next: v })} />
            <fieldset>
              <legend className="label">Linked queries</legend>
              {draft.queries.length === 0 ? (
                <p className="text-xs text-faint">Add query templates below to link them.</p>
              ) : (
                draft.queries.map((q) => (
                  <label key={q.id} className="flex items-center gap-1.5 text-xs">
                    <input type="checkbox" checked={s.queryIds.includes(q.id)} onChange={(e) => upd({ ...s, queryIds: e.target.checked ? [...s.queryIds, q.id] : s.queryIds.filter((x) => x !== q.id) })} />
                    <span className="font-mono">{q.id}</span> {q.title}
                  </label>
                ))
              )}
            </fieldset>
          </div>
        )}
      />
    </Card>
  );
}

function BranchEditor({ label, branch, nodes, selfId, onChange, idPrefix }: { label: string; branch: DecisionBranch; nodes: string[]; selfId: string; onChange: (b: DecisionBranch) => void; idPrefix: string }) {
  const kind = branch.next ? 'next' : 'outcome';
  return (
    <div className="rounded-md border border-line p-2">
      <p className="mb-1 text-xs font-semibold text-muted">{label}</p>
      <div className="flex flex-wrap gap-2">
        <select aria-label={`${label} leads to`} className="input w-36" value={kind} onChange={(e) => onChange(e.target.value === 'next' ? { next: nodes.find((n) => n !== selfId) ?? '', guidance: branch.guidance } : { outcome: 'escalate', guidance: branch.guidance })}>
          <option value="outcome">Outcome</option>
          <option value="next">Next question</option>
        </select>
        {kind === 'next' ? (
          <select aria-label={`${label} next question`} className="input w-44" value={branch.next} onChange={(e) => onChange({ next: e.target.value, guidance: branch.guidance })}>
            {nodes.filter((n) => n !== selfId).map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        ) : (
          <select aria-label={`${label} outcome`} className="input w-64" value={branch.outcome} onChange={(e) => onChange({ outcome: e.target.value as DecisionBranch['outcome'], guidance: branch.guidance })}>
            {OUTCOMES.map((o) => (
              <option key={o} value={o}>
                {OUTCOME_INFO[o].label}
              </option>
            ))}
          </select>
        )}
      </div>
      <label htmlFor={`${idPrefix}-g`} className="sr-only">
        {label} guidance
      </label>
      <input id={`${idPrefix}-g`} className="input mt-1.5" placeholder="Guidance shown to the analyst" maxLength={2000} value={branch.guidance} onChange={(e) => onChange({ ...branch, guidance: e.target.value })} />
    </div>
  );
}

function DecisionEditor({ draft, set }: { draft: Playbook; set: SetFn }) {
  const nodes = draft.decisionTree.nodes;
  const ids = nodes.map((n) => n.id);
  return (
    <Card title="Decision tree">
      <Field label="Start question" htmlFor="dt-start">
        <select id="dt-start" className="input w-60" value={draft.decisionTree.start} onChange={(e) => set('decisionTree', { ...draft.decisionTree, start: e.target.value })}>
          {ids.map((n) => (
            <option key={n}>{n}</option>
          ))}
        </select>
      </Field>
      <div className="mt-3">
        <RowList
          items={nodes}
          onChange={(v) => set('decisionTree', { ...draft.decisionTree, nodes: v })}
          make={(): Playbook['decisionTree']['nodes'][number] => ({ id: `q-${nodes.length + 1}`, question: 'New yes/no question?', yes: { outcome: 'escalate', guidance: 'Escalate.' }, no: { outcome: 'benign', guidance: 'Document why benign.' } })}
          render={(n, upd, i) => (
            <div className="space-y-2">
              <div className="grid gap-2 md:grid-cols-[12rem_1fr]">
                <Field label="Question ID" htmlFor={`dn-id-${i}`}>
                  <input id={`dn-id-${i}`} className="input font-mono" value={n.id} maxLength={48} onChange={(e) => upd({ ...n, id: e.target.value.toLowerCase() })} />
                </Field>
                <TextField id={`dn-q-${i}`} label="Question" value={n.question} onChange={(v) => upd({ ...n, question: v })} />
              </div>
              <div className="grid gap-2 lg:grid-cols-3">
                <BranchEditor idPrefix={`dn-${i}-y`} label="If Yes" branch={n.yes} nodes={ids} selfId={n.id} onChange={(b) => upd({ ...n, yes: b })} />
                <BranchEditor idPrefix={`dn-${i}-n`} label="If No" branch={n.no} nodes={ids} selfId={n.id} onChange={(b) => upd({ ...n, no: b })} />
                {n.unknown ? (
                  <div>
                    <BranchEditor idPrefix={`dn-${i}-u`} label="If Cannot determine" branch={n.unknown} nodes={ids} selfId={n.id} onChange={(b) => upd({ ...n, unknown: b })} />
                    <Button size="sm" variant="ghost" onClick={() => upd({ ...n, unknown: undefined })}>
                      Use default evidence-gap branch
                    </Button>
                  </div>
                ) : (
                  <div className="rounded-md border border-dashed border-line p-2 text-xs text-muted">
                    &quot;Cannot determine&quot; uses the standard evidence-gap outcome.
                    <Button size="sm" variant="ghost" onClick={() => upd({ ...n, unknown: { outcome: 'gap', guidance: 'Document the missing data and escalate per policy.' } })}>
                      Customize
                    </Button>
                  </div>
                )}
              </div>
            </div>
          )}
        />
      </div>
    </Card>
  );
}

function EvidenceEditor({ draft, set }: { draft: Playbook; set: SetFn }) {
  return (
    <Card title="Evidence checklist">
      <RowList
        items={draft.evidence}
        onChange={(v) => set('evidence', v)}
        make={() => ({ id: `field-${draft.evidence.length + 1}`, label: 'New evidence field', hint: '', required: false, multiline: false })}
        render={(e, upd, i) => (
          <div className="flex flex-wrap items-center gap-2">
            <input aria-label="Field ID" className="input w-36 font-mono" value={e.id} maxLength={48} onChange={(x) => upd({ ...e, id: x.target.value.toLowerCase() })} />
            <input aria-label="Label" className="input min-w-[10rem] flex-1" value={e.label} maxLength={200} onChange={(x) => upd({ ...e, label: x.target.value })} />
            <input aria-label="Hint" className="input min-w-[10rem] flex-1" placeholder="Hint" value={e.hint} maxLength={2000} onChange={(x) => upd({ ...e, hint: x.target.value })} />
            <label className="flex items-center gap-1 text-xs">
              <input type="checkbox" checked={e.required} onChange={(x) => upd({ ...e, required: x.target.checked })} /> required
            </label>
            <label className="flex items-center gap-1 text-xs">
              <input type="checkbox" checked={e.multiline} onChange={(x) => upd({ ...e, multiline: x.target.checked })} /> multi-line
            </label>
            <span className="sr-only">Evidence row {i + 1}</span>
          </div>
        )}
      />
    </Card>
  );
}

function QueriesEditor({ draft, set }: { draft: Playbook; set: SetFn }) {
  const make = (): QueryTemplate => ({
    id: `query-${draft.queries.length + 1}`,
    title: 'New query',
    language: 'kql',
    platform: 'Microsoft Sentinel',
    purpose: 'What this query investigates.',
    dataSources: ['Table or index'],
    query: '// Use {{placeholders}} for analyst-specific values',
    placeholders: [],
    keyFields: [],
    positive: 'What a non-empty result does and does not establish.',
    negative: 'What an empty result does and does not establish.',
    prerequisites: 'Required permissions and telemetry.',
    schemaNotes: 'Schema variance to be aware of.',
    example: '',
  });
  return (
    <Card title={`SIEM query templates (${draft.queries.length})`}>
      <p className="mb-2 text-xs text-muted">Use placeholders like {'{{hostname}}'} inside double quotes for strings. Non-string kinds (datetime, timespan, number) are validated strictly before insertion. Do not invent table or field names.</p>
      <RowList
        items={draft.queries}
        onChange={(v) => set('queries', v)}
        make={make}
        render={(q, upd, i) => (
          <div className="grid gap-2 md:grid-cols-2">
            <Field label="Query ID" htmlFor={`q-id-${i}`}>
              <input id={`q-id-${i}`} className="input font-mono" value={q.id} maxLength={48} onChange={(e) => upd({ ...q, id: e.target.value.toLowerCase() })} />
            </Field>
            <Field label="Title" htmlFor={`q-t-${i}`}>
              <input id={`q-t-${i}`} className="input" value={q.title} maxLength={200} onChange={(e) => upd({ ...q, title: e.target.value })} />
            </Field>
            <Field label="Language" htmlFor={`q-l-${i}`}>
              <select id={`q-l-${i}`} className="input" value={q.language} onChange={(e) => upd({ ...q, language: e.target.value as QueryTemplate['language'] })}>
                {QUERY_LANGUAGES.map((l) => (
                  <option key={l}>{l}</option>
                ))}
              </select>
            </Field>
            <Field label="Platform" htmlFor={`q-p-${i}`}>
              <input id={`q-p-${i}`} className="input" value={q.platform} maxLength={200} onChange={(e) => upd({ ...q, platform: e.target.value })} />
            </Field>
            <TextField id={`q-pu-${i}`} label="What the query investigates" value={q.purpose} onChange={(v) => upd({ ...q, purpose: v })} />
            <LinesField id={`q-ds-${i}`} label="Required tables / indexes / data sources" value={q.dataSources} onChange={(v) => upd({ ...q, dataSources: v })} />
            <div className="md:col-span-2">
              <label htmlFor={`q-q-${i}`} className="label">
                Query
              </label>
              <textarea id={`q-q-${i}`} className="input font-mono text-xs" rows={8} maxLength={12000} value={q.query} onChange={(e) => upd({ ...q, query: e.target.value })} spellCheck={false} />
            </div>
            <div className="md:col-span-2">
              <p className="label">Placeholders</p>
              <RowList
                items={q.placeholders}
                onChange={(v) => upd({ ...q, placeholders: v })}
                make={(): QueryTemplate['placeholders'][number] => ({ name: 'value', kind: 'string', description: 'Describe the value.', example: 'example' })}
                render={(p, up2) => (
                  <div className="flex flex-wrap gap-2">
                    <input aria-label="Placeholder name" className="input w-32 font-mono" value={p.name} maxLength={40} onChange={(e) => up2({ ...p, name: e.target.value.toLowerCase() })} />
                    <select aria-label="Kind" className="input w-28" value={p.kind} onChange={(e) => up2({ ...p, kind: e.target.value as typeof p.kind })}>
                      {PLACEHOLDER_KINDS.map((k) => (
                        <option key={k}>{k}</option>
                      ))}
                    </select>
                    <input aria-label="Description" className="input min-w-[10rem] flex-1" value={p.description} maxLength={2000} onChange={(e) => up2({ ...p, description: e.target.value })} />
                    <input aria-label="Example" className="input w-36" value={p.example} maxLength={200} onChange={(e) => up2({ ...p, example: e.target.value })} />
                    <select aria-label="Pre-fill from evidence" className="input w-40" value={p.evidenceField ?? ''} onChange={(e) => up2({ ...p, evidenceField: e.target.value || undefined })}>
                      <option value="">no evidence pre-fill</option>
                      {draft.evidence.map((ev) => (
                        <option key={ev.id} value={ev.id}>
                          {ev.id}
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              />
            </div>
            <LinesField
              id={`q-kf-${i}`}
              label="Important fields (one per line: Field: meaning)"
              value={q.keyFields.map((k) => `${k.name}: ${k.meaning}`)}
              onChange={(v) => upd({ ...q, keyFields: v.map((l) => ({ name: l.split(':')[0].trim(), meaning: l.split(':').slice(1).join(':').trim() || '-' })) })}
            />
            <TextField id={`q-pos-${i}`} label="Positive result means / does not mean" value={q.positive} onChange={(v) => upd({ ...q, positive: v })} />
            <TextField id={`q-neg-${i}`} label="Negative result means / does not mean" value={q.negative} onChange={(v) => upd({ ...q, negative: v })} />
            <TextField id={`q-pre-${i}`} label="Permissions and telemetry dependencies" value={q.prerequisites} onChange={(v) => upd({ ...q, prerequisites: v })} />
            <TextField id={`q-sch-${i}`} label="Schema / configuration notes" value={q.schemaNotes} onChange={(v) => upd({ ...q, schemaNotes: v })} />
            <TextField id={`q-ex-${i}`} label="Safe example (fictional values)" value={q.example} onChange={(v) => upd({ ...q, example: v })} />
          </div>
        )}
      />
    </Card>
  );
}

// --- Generic form helpers -------------------------------------------------------------------

function TextField({ id, label, value, onChange }: { id: string; label: string; value: string; onChange: (v: string) => void }) {
  return (
    <Field label={label} htmlFor={id}>
      <textarea id={id} className="input" rows={2} maxLength={2000} value={value} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}

/** Textarea editing a string[] one item per line without fighting the cursor. */
function LinesField({ id, label, value, onChange }: { id: string; label: string; value: string[]; onChange: (v: string[]) => void }) {
  const [text, setText] = useState(toLines(value));
  useEffect(() => {
    if (toLines(fromLines(text)) !== toLines(value)) setText(toLines(value));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return (
    <Field label={label} htmlFor={id} hint="One item per line.">
      <textarea
        id={id}
        className="input"
        rows={Math.min(8, Math.max(2, value.length + 1))}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          onChange(fromLines(e.target.value));
        }}
      />
    </Field>
  );
}

function CommaField({ id, value, onChange, upper, invalid }: { id: string; value: string[]; onChange: (v: string[]) => void; upper?: boolean; invalid?: boolean }) {
  const [text, setText] = useState(value.join(', '));
  const parse = (s: string) =>
    s
      .split(',')
      .map((x) => (upper ? x.trim().toUpperCase() : x.trim()))
      .filter(Boolean);
  useEffect(() => {
    if (parse(text).join(',') !== value.join(',')) setText(value.join(', '));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return (
    <input
      id={id}
      className={cx('input', invalid && 'border-bad')}
      aria-invalid={invalid}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        onChange(parse(e.target.value));
      }}
    />
  );
}

function RowList<T>({ items, onChange, make, render }: { items: T[]; onChange: (v: T[]) => void; make: () => T; render: (item: T, update: (v: T) => void, index: number) => ReactNode }) {
  const move = (i: number, d: number) => {
    const j = i + d;
    if (j < 0 || j >= items.length) return;
    const next = [...items];
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={i} className="flex gap-2 rounded-md border border-line bg-panel-2 p-2.5">
          <div className="min-w-0 flex-1">{render(item, (v) => onChange(items.map((x, k) => (k === i ? v : x))), i)}</div>
          <div className="flex shrink-0 flex-col gap-1">
            <button type="button" className="rounded p-1 text-muted hover:bg-panel-3 disabled:opacity-30" onClick={() => move(i, -1)} disabled={i === 0} aria-label={`Move item ${i + 1} up`}>
              <ArrowUp className="h-3.5 w-3.5" aria-hidden />
            </button>
            <button type="button" className="rounded p-1 text-muted hover:bg-panel-3 disabled:opacity-30" onClick={() => move(i, 1)} disabled={i === items.length - 1} aria-label={`Move item ${i + 1} down`}>
              <ArrowDown className="h-3.5 w-3.5" aria-hidden />
            </button>
            <button type="button" className="rounded p-1 text-bad hover:bg-bad/10" onClick={() => onChange(items.filter((_, k) => k !== i))} aria-label={`Remove item ${i + 1}`}>
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        </div>
      ))}
      <Button size="sm" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => onChange([...items, make()])}>
        Add
      </Button>
    </div>
  );
}

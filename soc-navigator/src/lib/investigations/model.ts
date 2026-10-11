import { z } from 'zod';
import { DEFAULT_UNKNOWN_BRANCH, DISPOSITIONS, INVESTIGATION_STATUSES, OUTCOME_INFO } from '../playbooks/outcomes';
import type { Disposition, InvestigationStatus } from '../playbooks/outcomes';
import { OUTCOMES } from '../playbooks/schema';
import type { DecisionBranch, Outcome, Playbook } from '../playbooks/schema';

/**
 * Investigation state. All functions are pure (return a new object) so they are easy to test
 * and to back with a different persistence layer later.
 */

export const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'] as const;
export const SUSPICION_LEVELS = ['Not assessed', 'Likely benign', 'Suspicious', 'Confirmed malicious'] as const;
export const CONFIDENCE_LEVELS = ['Low', 'Medium', 'High'] as const;
export const FINDING_KINDS = ['supporting', 'contradicting', 'observation'] as const;
export const ANSWERS = ['yes', 'no', 'unknown'] as const;

export type Severity = (typeof SEVERITIES)[number];
export type SuspicionLevel = (typeof SUSPICION_LEVELS)[number];
export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];
export type FindingKind = (typeof FINDING_KINDS)[number];
export type Answer = (typeof ANSWERS)[number];

export const MAX = { short: 200, field: 8_000, notes: 20_000, list: 200, activity: 300 } as const;

const iso = z.string().max(40);
const short = z.string().max(MAX.short);
const field = z.string().max(MAX.field);
const itemId = z.string().regex(/^[a-z0-9-]{1,40}$/);
/** Record keys must start with [a-z0-9] so "__proto__" can never be a key. */
const safeKey = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,59}$/);

export const investigationSchema = z.object({
  schemaVersion: z.literal(1),
  id: z.string().regex(/^INV-\d{8}-[A-Z0-9]{4}$/),
  title: short,
  alertRef: short,
  alertSource: short,
  severity: z.enum(SEVERITIES),
  playbookId: z.string().max(60),
  playbookVersion: z.string().max(20),
  playbookTitle: short,
  analyst: short,
  createdAt: iso,
  updatedAt: iso,
  status: z.enum(INVESTIGATION_STATUSES),
  demo: z.boolean(),
  steps: z.record(safeKey, z.object({ done: z.boolean(), notes: field, completedAt: iso.nullable() })),
  evidence: z.record(safeKey, field),
  decisionPath: z.array(z.object({ nodeId: z.string().max(60), answer: z.enum(ANSWERS), at: iso })).max(50),
  findings: z.array(z.object({ id: itemId, kind: z.enum(FINDING_KINDS), text: field, at: iso })).max(MAX.list),
  timeline: z.array(z.object({ id: itemId, time: short, description: field, source: short })).max(MAX.list),
  assessment: z.object({ suspicion: z.enum(SUSPICION_LEVELS), confidence: z.enum(CONFIDENCE_LEVELS), rationale: field }),
  relatedTechniques: z.array(z.object({ id: z.string().regex(/^T\d{4}(\.\d{3})?$/), note: field })).max(50),
  missingInfo: z.array(z.object({ id: itemId, text: field })).max(MAX.list),
  openQuestions: z.array(z.object({ id: itemId, text: field })).max(MAX.list),
  disposition: z.object({ recommendation: z.enum(DISPOSITIONS), rationale: field }),
  escalation: z.object({ reason: field, recipient: short, nextSteps: field, escalatedAt: iso.nullable() }),
  executiveSummary: field,
  notes: z.string().max(MAX.notes),
  reportOverride: z.string().max(100_000).nullable(),
  activity: z.array(z.object({ at: iso, text: short })).max(MAX.activity),
});

export type Investigation = z.infer<typeof investigationSchema>;

export interface NewInvestigationInput {
  playbook: Playbook;
  alertRef: string;
  title?: string;
  alertSource?: string;
  severity?: Severity;
  analyst: string;
  demo?: boolean;
  now?: Date;
  random?: () => number;
}

const ID_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function newInvestigationId(now: Date, random: () => number = Math.random): string {
  const date = now.toISOString().slice(0, 10).replace(/-/g, '');
  let suffix = '';
  for (let i = 0; i < 4; i += 1) suffix += ID_CHARS[Math.floor(random() * ID_CHARS.length)];
  return `INV-${date}-${suffix}`;
}

export function newItemId(random: () => number = Math.random): string {
  return `i${Math.floor(random() * 36 ** 8).toString(36)}`.slice(0, 12);
}

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) : s);

export function createInvestigation(input: NewInvestigationInput): Investigation {
  const now = (input.now ?? new Date()).toISOString();
  const pb = input.playbook;
  return {
    schemaVersion: 1,
    id: newInvestigationId(input.now ?? new Date(), input.random),
    title: clip((input.title ?? '').trim() || pb.title, MAX.short),
    alertRef: clip(input.alertRef.trim(), MAX.short),
    alertSource: clip((input.alertSource ?? '').trim(), MAX.short),
    severity: input.severity ?? 'Medium',
    playbookId: pb.id,
    playbookVersion: pb.version,
    playbookTitle: pb.title,
    analyst: clip(input.analyst.trim() || 'demo.analyst', MAX.short),
    createdAt: now,
    updatedAt: now,
    status: 'New',
    demo: input.demo ?? false,
    steps: {},
    evidence: {},
    decisionPath: [],
    findings: [],
    timeline: [],
    assessment: { suspicion: 'Not assessed', confidence: 'Low', rationale: '' },
    relatedTechniques: pb.techniques.slice(0, 1).map((id) => ({ id, note: 'Technique associated with the selected playbook (not confirmed by evidence).' })),
    missingInfo: [],
    openQuestions: [],
    disposition: { recommendation: 'Not yet determined', rationale: '' },
    escalation: { reason: '', recipient: '', nextSteps: '', escalatedAt: null },
    executiveSummary: '',
    notes: '',
    reportOverride: null,
    activity: [{ at: now, text: `Investigation created from playbook ${pb.id} v${pb.version}.` }],
  };
}

function touch(inv: Investigation, now: Date, activity?: string): Investigation {
  const at = now.toISOString();
  const next = { ...inv, updatedAt: at };
  if (activity) next.activity = [{ at, text: clip(activity, MAX.short) }, ...inv.activity].slice(0, MAX.activity);
  return next;
}

/** First meaningful work moves a New investigation to In Progress. */
function autoProgress(inv: Investigation): Investigation {
  return inv.status === 'New' ? { ...inv, status: 'In Progress' } : inv;
}

export function setStepDone(inv: Investigation, stepId: string, done: boolean, now = new Date()): Investigation {
  const prev = inv.steps[stepId] ?? { done: false, notes: '', completedAt: null };
  if (prev.done === done) return inv;
  const steps = { ...inv.steps, [stepId]: { ...prev, done, completedAt: done ? now.toISOString() : null } };
  return autoProgress(touch({ ...inv, steps }, now, `${done ? 'Completed' : 'Reopened'} step "${stepId}".`));
}

export function setStepNotes(inv: Investigation, stepId: string, notes: string, now = new Date()): Investigation {
  const prev = inv.steps[stepId] ?? { done: false, notes: '', completedAt: null };
  const steps = { ...inv.steps, [stepId]: { ...prev, notes: clip(notes, MAX.field) } };
  return autoProgress(touch({ ...inv, steps }, now));
}

export function setEvidence(inv: Investigation, fieldId: string, value: string, now = new Date()): Investigation {
  const evidence = { ...inv.evidence, [fieldId]: clip(value, MAX.field) };
  if (!value.trim()) delete evidence[fieldId];
  return autoProgress(touch({ ...inv, evidence }, now));
}

export interface DecisionState {
  /** Nodes answered so far, in order, with the branch taken. */
  path: { nodeId: string; question: string; answer: Answer; branch: DecisionBranch }[];
  /** Node awaiting an answer, if any. */
  current: Playbook['decisionTree']['nodes'][number] | null;
  outcome: Outcome | null;
  outcomeGuidance: string | null;
}

export function branchFor(node: Playbook['decisionTree']['nodes'][number], answer: Answer): DecisionBranch {
  if (answer === 'yes') return node.yes;
  if (answer === 'no') return node.no;
  return node.unknown ?? DEFAULT_UNKNOWN_BRANCH;
}

/** Replays recorded answers against the playbook's tree. Stale answers (tree changed) are dropped. */
export function evaluateDecision(playbook: Playbook, answers: { nodeId: string; answer: Answer }[]): DecisionState {
  const nodes = new Map(playbook.decisionTree.nodes.map((n) => [n.id, n]));
  const path: DecisionState['path'] = [];
  let current = nodes.get(playbook.decisionTree.start) ?? null;
  for (const a of answers) {
    if (!current || a.nodeId !== current.id) break;
    const branch = branchFor(current, a.answer);
    path.push({ nodeId: current.id, question: current.question, answer: a.answer, branch });
    if (branch.outcome) return { path, current: null, outcome: branch.outcome, outcomeGuidance: branch.guidance };
    current = branch.next ? (nodes.get(branch.next) ?? null) : null;
    if (path.length > 50) break;
  }
  return { path, current, outcome: null, outcomeGuidance: null };
}

export function answerDecision(inv: Investigation, playbook: Playbook, nodeId: string, answer: Answer, now = new Date()): Investigation {
  const state = evaluateDecision(playbook, inv.decisionPath);
  // Answering an earlier node rewinds the path to that node.
  const idx = state.path.findIndex((p) => p.nodeId === nodeId);
  const kept = idx >= 0 ? inv.decisionPath.slice(0, idx) : inv.decisionPath.slice(0, state.path.length);
  if (idx < 0 && state.current?.id !== nodeId) return inv;
  const decisionPath = [...kept, { nodeId, answer, at: now.toISOString() }];
  const evaluated = evaluateDecision(playbook, decisionPath);
  const note = evaluated.outcome ? ` -> outcome: ${OUTCOME_INFO[evaluated.outcome].label}` : '';
  return autoProgress(touch({ ...inv, decisionPath }, now, `Decision "${nodeId}" answered ${answer}${note}.`));
}

export function resetDecision(inv: Investigation, now = new Date()): Investigation {
  return touch({ ...inv, decisionPath: [] }, now, 'Decision tree reset.');
}

/** Applies the decision outcome as a disposition recommendation (analyst-initiated, never automatic). */
export function applyOutcome(inv: Investigation, outcome: Outcome, guidance: string, now = new Date()): Investigation {
  const info = OUTCOME_INFO[outcome];
  const disposition = { recommendation: info.disposition, rationale: inv.disposition.rationale || guidance };
  const gap = outcome === 'gap' && inv.missingInfo.length === 0 ? [{ id: newItemId(), text: 'Decision tree reached an evidence gap - record the specific missing data here.' }] : inv.missingInfo;
  return touch({ ...inv, disposition, status: info.suggestedStatus, missingInfo: gap }, now, `Applied decision outcome "${info.label}"; status set to ${info.suggestedStatus}.`);
}

export function setStatus(inv: Investigation, status: InvestigationStatus, now = new Date()): Investigation {
  if (inv.status === status) return inv;
  const escalatedAt = status === 'Escalated' ? (inv.escalation.escalatedAt ?? now.toISOString()) : inv.escalation.escalatedAt;
  return touch({ ...inv, status, escalation: { ...inv.escalation, escalatedAt } }, now, `Status changed from ${inv.status} to ${status}.`);
}

export function setDisposition(inv: Investigation, recommendation: Disposition, rationale: string, now = new Date()): Investigation {
  return touch({ ...inv, disposition: { recommendation, rationale: clip(rationale, MAX.field) } }, now);
}

export function addListItem(
  inv: Investigation,
  list: 'missingInfo' | 'openQuestions',
  text: string,
  now = new Date(),
  random: () => number = Math.random,
): Investigation {
  const t = text.trim();
  if (!t || inv[list].length >= MAX.list) return inv;
  return autoProgress(touch({ ...inv, [list]: [...inv[list], { id: newItemId(random), text: clip(t, MAX.field) }] }, now));
}

export function removeListItem(inv: Investigation, list: 'missingInfo' | 'openQuestions' | 'findings' | 'timeline', id: string, now = new Date()): Investigation {
  return touch({ ...inv, [list]: (inv[list] as { id: string }[]).filter((x) => x.id !== id) } as Investigation, now);
}

export function addFinding(inv: Investigation, kind: FindingKind, text: string, now = new Date(), random: () => number = Math.random): Investigation {
  const t = text.trim();
  if (!t || inv.findings.length >= MAX.list) return inv;
  const finding = { id: newItemId(random), kind, text: clip(t, MAX.field), at: now.toISOString() };
  return autoProgress(touch({ ...inv, findings: [...inv.findings, finding] }, now, `Added ${kind} finding.`));
}

export function addTimelineEntry(
  inv: Investigation,
  entry: { time: string; description: string; source: string },
  now = new Date(),
  random: () => number = Math.random,
): Investigation {
  if (!entry.description.trim() || inv.timeline.length >= MAX.list) return inv;
  const item = { id: newItemId(random), time: clip(entry.time.trim(), MAX.short), description: clip(entry.description.trim(), MAX.field), source: clip(entry.source.trim(), MAX.short) };
  return autoProgress(touch({ ...inv, timeline: [...inv.timeline, item] }, now));
}

/** Timeline sorted by parsable time first (ascending), unparsable entries after in entry order. */
export function sortedTimeline(inv: Investigation): Investigation['timeline'] {
  const withTime = inv.timeline.map((e, i) => ({ e, i, t: Date.parse(e.time) }));
  return withTime
    .sort((a, b) => {
      const an = Number.isNaN(a.t);
      const bn = Number.isNaN(b.t);
      if (an && bn) return a.i - b.i;
      if (an) return 1;
      if (bn) return -1;
      return a.t - b.t || a.i - b.i;
    })
    .map((x) => x.e);
}

export function update<K extends keyof Investigation>(inv: Investigation, key: K, value: Investigation[K], now = new Date()): Investigation {
  return touch({ ...inv, [key]: value }, now);
}

export interface Progress {
  stepsDone: number;
  stepsTotal: number;
  requiredEvidenceDone: number;
  requiredEvidenceTotal: number;
  decisionComplete: boolean;
  percent: number;
  missingRequiredEvidence: string[];
  pendingSteps: string[];
}

export function progressOf(inv: Investigation, playbook: Playbook | undefined): Progress {
  if (!playbook) {
    return { stepsDone: 0, stepsTotal: 0, requiredEvidenceDone: 0, requiredEvidenceTotal: 0, decisionComplete: false, percent: 0, missingRequiredEvidence: [], pendingSteps: [] };
  }
  const stepsDone = playbook.steps.filter((s) => inv.steps[s.id]?.done).length;
  const required = playbook.evidence.filter((e) => e.required);
  const missingRequiredEvidence = required.filter((e) => !(inv.evidence[e.id] ?? '').trim()).map((e) => e.label);
  const requiredEvidenceDone = required.length - missingRequiredEvidence.length;
  const decisionComplete = evaluateDecision(playbook, inv.decisionPath).outcome !== null;
  const units = playbook.steps.length + required.length + 1;
  const done = stepsDone + requiredEvidenceDone + (decisionComplete ? 1 : 0);
  return {
    stepsDone,
    stepsTotal: playbook.steps.length,
    requiredEvidenceDone,
    requiredEvidenceTotal: required.length,
    decisionComplete,
    percent: units ? Math.round((done / units) * 100) : 0,
    missingRequiredEvidence,
    pendingSteps: playbook.steps.filter((s) => !inv.steps[s.id]?.done).map((s) => s.title),
  };
}

export function isActive(inv: Investigation): boolean {
  return inv.status !== 'Resolved' && inv.status !== 'Escalated';
}

export function resetProgress(inv: Investigation, now = new Date()): Investigation {
  return touch(
    {
      ...inv,
      status: 'New',
      steps: {},
      evidence: {},
      decisionPath: [],
      findings: [],
      timeline: [],
      assessment: { suspicion: 'Not assessed', confidence: 'Low', rationale: '' },
      missingInfo: [],
      openQuestions: [],
      disposition: { recommendation: 'Not yet determined', rationale: '' },
      escalation: { reason: '', recipient: '', nextSteps: '', escalatedAt: null },
      executiveSummary: '',
      notes: '',
      reportOverride: null,
    },
    now,
    'Investigation progress reset by analyst.',
  );
}

export const OUTCOME_LIST = OUTCOMES;

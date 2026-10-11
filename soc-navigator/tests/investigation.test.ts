import { describe, expect, it } from 'vitest';
import { STARTER_PLAYBOOKS } from '../src/data/playbooks';
import { buildDemoInvestigations } from '../src/lib/demo';
import {
  addFinding,
  addListItem,
  addTimelineEntry,
  answerDecision,
  applyOutcome,
  createInvestigation,
  evaluateDecision,
  investigationSchema,
  isActive,
  progressOf,
  removeListItem,
  resetProgress,
  setEvidence,
  setStatus,
  setStepDone,
  setStepNotes,
  sortedTimeline,
} from '../src/lib/investigations/model';
import type { Playbook } from '../src/lib/playbooks/schema';
import { KEYS, createMemoryStorage, loadCollection, saveCollection } from '../src/lib/storage';

const pb = STARTER_PLAYBOOKS.find((p) => p.id === 'PB-PHISH-001') as Playbook;
const t0 = new Date('2026-10-10T12:00:00Z');
const later = (min: number) => new Date(t0.getTime() + min * 60_000);
const fixedRandom = () => 0.5;

function fresh() {
  return createInvestigation({ playbook: pb, alertRef: 'ALERT-1', analyst: 'tester', now: t0, random: fixedRandom });
}

describe('investigation lifecycle', () => {
  it('creates a valid New investigation tied to the playbook version', () => {
    const inv = fresh();
    expect(inv.id).toMatch(/^INV-20261010-[A-Z0-9]{4}$/);
    expect(inv.status).toBe('New');
    expect(inv.playbookVersion).toBe(pb.version);
    expect(investigationSchema.safeParse(inv).success).toBe(true);
  });

  it('completing a step moves New to In Progress and is reversible', () => {
    let inv = setStepDone(fresh(), pb.steps[0].id, true, later(1));
    expect(inv.status).toBe('In Progress');
    expect(inv.steps[pb.steps[0].id]).toMatchObject({ done: true, completedAt: later(1).toISOString() });
    inv = setStepDone(inv, pb.steps[0].id, false, later(2));
    expect(inv.steps[pb.steps[0].id].done).toBe(false);
    expect(inv.activity[0].text).toMatch(/Reopened/);
  });

  it('records notes and evidence, clipping oversized input and removing empty values', () => {
    let inv = setStepNotes(fresh(), 'identify-message', 'n'.repeat(10_000));
    expect(inv.steps['identify-message'].notes).toHaveLength(8_000);
    inv = setEvidence(inv, 'alert_id', 'A-1');
    expect(inv.evidence.alert_id).toBe('A-1');
    inv = setEvidence(inv, 'alert_id', '   ');
    expect('alert_id' in inv.evidence).toBe(false);
  });

  it('walks the decision tree, rewinds when an earlier answer changes, and reaches an outcome', () => {
    let inv = fresh();
    const start = pb.decisionTree.start;
    inv = answerDecision(inv, pb, start, 'yes', later(1));
    let state = evaluateDecision(pb, inv.decisionPath);
    expect(state.current?.id).toBe('delivered');
    inv = answerDecision(inv, pb, 'delivered', 'no', later(2));
    state = evaluateDecision(pb, inv.decisionPath);
    expect(state.outcome).toBe('contained');
    // Change the first answer: the path rewinds.
    inv = answerDecision(inv, pb, start, 'no', later(3));
    state = evaluateDecision(pb, inv.decisionPath);
    expect(inv.decisionPath).toHaveLength(1);
    expect(state.current?.id).toBe('verified-legit');
    // Unknown answers follow the evidence-gap default when a node does not override it.
    inv = answerDecision(inv, pb, 'verified-legit', 'unknown', later(4));
    expect(evaluateDecision(pb, inv.decisionPath).outcome).toBe('gap');
    // Answering a node that is not current or on the path is ignored.
    expect(answerDecision(inv, pb, 'widespread', 'yes')).toBe(inv);
  });

  it('applyOutcome sets disposition and suggested status but only when the analyst applies it', () => {
    let inv = answerDecision(fresh(), pb, pb.decisionTree.start, 'yes');
    inv = answerDecision(inv, pb, 'delivered', 'yes');
    inv = answerDecision(inv, pb, 'interaction', 'yes');
    inv = answerDecision(inv, pb, 'compromise', 'no');
    expect(inv.status).toBe('In Progress');
    const st = evaluateDecision(pb, inv.decisionPath);
    expect(st.outcome).toBe('escalate');
    inv = applyOutcome(inv, st.outcome!, st.outcomeGuidance!);
    expect(inv.status).toBe('Escalation Recommended');
    expect(inv.disposition.recommendation).toBe('Escalate to Tier 2');
  });

  it('gap outcome adds a missing-information placeholder', () => {
    const inv = applyOutcome(fresh(), 'gap', 'missing');
    expect(inv.status).toBe('Awaiting Information');
    expect(inv.missingInfo).toHaveLength(1);
  });

  it('computes progress from steps, required evidence, and decision completion', () => {
    let inv = fresh();
    expect(progressOf(inv, pb).percent).toBe(0);
    for (const s of pb.steps) inv = setStepDone(inv, s.id, true);
    for (const e of pb.evidence.filter((x) => x.required)) inv = setEvidence(inv, e.id, 'x');
    inv = answerDecision(inv, pb, pb.decisionTree.start, 'yes');
    inv = answerDecision(inv, pb, 'delivered', 'no');
    const p = progressOf(inv, pb);
    expect(p).toMatchObject({ percent: 100, missingRequiredEvidence: [], pendingSteps: [], decisionComplete: true });
  });

  it('findings, lists, and timeline sorting', () => {
    let inv = addFinding(fresh(), 'supporting', '  evidence  ', later(1), fixedRandom);
    expect(inv.findings[0].text).toBe('evidence');
    expect(addFinding(inv, 'supporting', '   ')).toBe(inv);
    inv = addListItem(inv, 'openQuestions', 'q1', later(2), () => 0.1);
    inv = removeListItem(inv, 'openQuestions', inv.openQuestions[0].id);
    expect(inv.openQuestions).toEqual([]);
    inv = addTimelineEntry(inv, { time: 'unknown', description: 'c', source: '' }, later(3), () => 0.2);
    inv = addTimelineEntry(inv, { time: '2026-10-10T13:00:00Z', description: 'b', source: '' }, later(4), () => 0.3);
    inv = addTimelineEntry(inv, { time: '2026-10-10T12:00:00Z', description: 'a', source: '' }, later(5), () => 0.4);
    expect(sortedTimeline(inv).map((t) => t.description)).toEqual(['a', 'b', 'c']);
  });

  it('status changes are logged; Escalated records the escalation time', () => {
    const inv = setStatus(fresh(), 'Escalated', later(9));
    expect(inv.escalation.escalatedAt).toBe(later(9).toISOString());
    expect(isActive(inv)).toBe(false);
    expect(inv.activity[0].text).toMatch(/New to Escalated/);
  });

  it('reset clears analyst work but keeps identity', () => {
    let inv = setStepDone(fresh(), pb.steps[0].id, true);
    inv = setEvidence(inv, 'alert_id', 'x');
    const reset = resetProgress(inv);
    expect(reset).toMatchObject({ id: inv.id, status: 'New', steps: {}, evidence: {} });
  });
});

describe('persistence', () => {
  it('round-trips through storage with validation', () => {
    const store = createMemoryStorage();
    const items = [fresh()];
    expect(saveCollection(store, KEYS.investigations, items)).toEqual({ ok: true });
    const loaded = loadCollection(store, KEYS.investigations, investigationSchema);
    expect(loaded).toEqual({ items, rejected: 0, error: null });
  });

  it('sets aside corrupted records without losing valid ones', () => {
    const good = fresh();
    const store = createMemoryStorage({ [KEYS.investigations]: JSON.stringify([good, { id: 'bad' }]) });
    const loaded = loadCollection(store, KEYS.investigations, investigationSchema);
    expect(loaded.items).toHaveLength(1);
    expect(loaded.rejected).toBe(1);
    expect(store.read(`${KEYS.investigations}.rejected`)).toContain('bad');
    const garbage = createMemoryStorage({ [KEYS.investigations]: '{not json' });
    expect(loadCollection(garbage, KEYS.investigations, investigationSchema).error).toMatch(/not valid JSON/);
  });

  it('never materializes prototype-pollution keys from stored evidence', () => {
    const raw = JSON.parse(JSON.stringify(fresh()));
    raw.evidence = JSON.parse('{"__proto__": {"polluted": true}, "_x": "y"}');
    const r = investigationSchema.safeParse(raw);
    // "_x" violates the key pattern, so the record is rejected outright.
    expect(r.success).toBe(false);
    raw.evidence = JSON.parse('{"__proto__": {"polluted": true}, "ok": "y"}');
    const r2 = investigationSchema.safeParse(raw);
    expect(r2.success && Object.keys(r2.data.evidence)).toEqual(['ok']);
    expect(r2.success && Object.getPrototypeOf(r2.data.evidence)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('refuses to save beyond the size cap', () => {
    const store = createMemoryStorage();
    const big = Array.from({ length: 300 }, () => ({ ...fresh(), notes: 'x'.repeat(20_000) }));
    const r = saveCollection(store, KEYS.investigations, big);
    expect(r.ok).toBe(false);
  });

  it('demo investigations are valid, flagged as demo, and use documentation IP ranges', () => {
    const demos = buildDemoInvestigations(new Map(STARTER_PLAYBOOKS.map((p) => [p.id, p as Playbook])), t0);
    expect(demos).toHaveLength(3);
    for (const d of demos) {
      expect(investigationSchema.safeParse(d).success).toBe(true);
      expect(d.demo).toBe(true);
      for (const ip of JSON.stringify(d).match(/\b\d{1,3}(\.\d{1,3}){3}\b/g) ?? []) {
        expect(ip, `${ip} should be a documentation address`).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
      }
    }
    expect(demos[0].status).toBe('Escalation Recommended');
    expect(demos[2].status).toBe('Resolved');
  });
});

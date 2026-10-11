import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { LOG_SOURCE_BY_ID } from '../src/data/logSources';
import { STARTER_PLAYBOOKS } from '../src/data/playbooks';
import { AttackIndex } from '../src/lib/attack/attackIndex';
import { parseDataset } from '../src/lib/attack/loader';
import {
  blankPlaybook,
  buildCoverage,
  bumpVersion,
  coverageLevel,
  exportPlaybooks,
  mergeLibrary,
  nextLocalId,
  parsePlaybookImport,
  withStatus,
} from '../src/lib/playbooks/library';
import { playbookSchema } from '../src/lib/playbooks/schema';
import type { Playbook } from '../src/lib/playbooks/schema';

const index = new AttackIndex(parseDataset(JSON.parse(readFileSync('public/data/attack-enterprise.json', 'utf8'))));

describe('starter playbook library', () => {
  it('contains the 15 required investigation areas with unique IDs', () => {
    expect(STARTER_PLAYBOOKS).toHaveLength(15);
    expect(new Set(STARTER_PLAYBOOKS.map((p) => p.id)).size).toBe(15);
  });

  it.each(STARTER_PLAYBOOKS.map((p) => [p.id, p] as const))('%s passes schema validation', (_id, pb) => {
    const r = playbookSchema.safeParse(pb);
    if (!r.success) throw new Error(JSON.stringify(r.error.issues.slice(0, 3)));
  });

  it.each(STARTER_PLAYBOOKS.map((p) => [p.id, p] as const))('%s only references active ATT&CK IDs and known tactics/log sources', (_id, pb) => {
    for (const id of [...pb.techniques, ...pb.relatedTechniques.map((r) => r.id)]) {
      expect(index.get(id), `${id} should be active in ATT&CK ${index.dataset.meta.version}`).toBeDefined();
    }
    for (const t of pb.tactics) expect(index.tacticByShortname.has(t)).toBe(true);
    // Every playbook tactic must belong to at least one of its techniques.
    for (const t of pb.tactics) expect(pb.techniques.some((id) => index.get(id)!.tactics.includes(t)), `${pb.id} tactic ${t}`).toBe(true);
    for (const l of pb.logSources) expect(LOG_SOURCE_BY_ID.has(l), l).toBe(true);
  });

  it.each(STARTER_PLAYBOOKS.map((p) => [p.id, p] as const))('%s is AI-assisted and therefore Draft with no reviewer', (_id, pb) => {
    expect(pb.aiAssisted).toBe(true);
    expect(pb.status).toBe('Draft');
    expect(pb.review.reviewer).toBeNull();
  });

  it.each(STARTER_PLAYBOOKS.map((p) => [p.id, p] as const))('%s provides KQL, SPL, and generic guidance plus complete steps', (_id, pb) => {
    const langs = new Set(pb.queries.map((q) => q.language));
    expect(langs).toEqual(new Set(['kql', 'spl', 'generic']));
    expect(pb.steps.length).toBeGreaterThanOrEqual(5);
    for (const s of pb.steps) {
      expect(s.where.length).toBeGreaterThan(0);
      expect(s.suspicious.length).toBeGreaterThan(0);
      expect(s.next.length).toBeGreaterThan(10);
    }
    expect(pb.evidence.some((e) => e.required)).toBe(true);
    expect(pb.escalation.tier2.length).toBeGreaterThan(0);
  });

  it.each(STARTER_PLAYBOOKS.map((p) => [p.id, p] as const))('%s decision tree: every node reachable and every path ends in an outcome', (_id, pb) => {
    const nodes = new Map(pb.decisionTree.nodes.map((n) => [n.id, n]));
    const reached = new Set<string>();
    const walk = (id: string, depth: number): void => {
      expect(depth).toBeLessThan(20);
      const n = nodes.get(id)!;
      reached.add(id);
      for (const b of [n.yes, n.no, n.unknown].filter(Boolean)) {
        if (b!.next) walk(b!.next, depth + 1);
        else expect(b!.outcome).toBeTruthy();
      }
    };
    walk(pb.decisionTree.start, 0);
    expect([...nodes.keys()].filter((id) => !reached.has(id))).toEqual([]);
    const outcomes = new Set(pb.decisionTree.nodes.flatMap((n) => [n.yes.outcome, n.no.outcome]).filter(Boolean));
    expect(outcomes.size).toBeGreaterThanOrEqual(2);
  });

  it('playbooks are tailored, not copies: step titles and queries are not shared across playbooks', () => {
    const seen = new Map<string, string>();
    for (const pb of STARTER_PLAYBOOKS) {
      for (const s of pb.steps) {
        const key = s.title.toLowerCase();
        expect(seen.get(key), `"${s.title}" duplicated in ${pb.id} and ${seen.get(key)}`).toBeUndefined();
        seen.set(key, pb.id);
      }
    }
    const queries = STARTER_PLAYBOOKS.flatMap((p) => p.queries.filter((q) => q.language !== 'generic').map((q) => q.query));
    expect(new Set(queries).size).toBe(queries.length);
  });

  it('query placeholders are documented, used, and have examples', () => {
    for (const pb of STARTER_PLAYBOOKS) {
      for (const q of pb.queries) {
        for (const p of q.placeholders) expect(p.example.length, `${pb.id}/${q.id}/${p.name}`).toBeGreaterThan(0);
        expect(q.positive.length).toBeGreaterThan(20);
        expect(q.negative.length).toBeGreaterThan(20);
      }
    }
  });

  it('references use https only', () => {
    for (const pb of STARTER_PLAYBOOKS) for (const r of pb.references) expect(r.url.startsWith('https://')).toBe(true);
  });
});

describe('playbook schema rejects unsafe or inconsistent content', () => {
  const base = (): Playbook => structuredClone(STARTER_PLAYBOOKS[0]) as Playbook;

  it('rejects non-https references', () => {
    const pb = base();
    pb.references.push({ title: 'x', url: 'javascript:alert(1)' });
    expect(playbookSchema.safeParse(pb).success).toBe(false);
  });

  it('rejects Approved status without a reviewer', () => {
    const pb = base();
    pb.status = 'Approved';
    expect(playbookSchema.safeParse(pb).success).toBe(false);
    pb.review.reviewer = 'ir.lead';
    expect(playbookSchema.safeParse(pb).success).toBe(true);
  });

  it('rejects decision cycles, dangling branches, unknown query refs, and undocumented placeholders', () => {
    const cyc = base();
    cyc.decisionTree.nodes[1].no = { next: cyc.decisionTree.nodes[0].id, guidance: 'loop' };
    expect(playbookSchema.safeParse(cyc).success).toBe(false);

    const dangling = base();
    dangling.decisionTree.nodes[0].yes = { next: 'nowhere', guidance: 'x' };
    expect(playbookSchema.safeParse(dangling).success).toBe(false);

    const badRef = base();
    badRef.steps[0].queryIds = ['missing-query'];
    expect(playbookSchema.safeParse(badRef).success).toBe(false);

    const ph = base();
    ph.queries[0].query += ' {{undocumented}}';
    expect(playbookSchema.safeParse(ph).success).toBe(false);
  });

  it('rejects malformed technique IDs', () => {
    const pb = base();
    pb.techniques = ['T59'];
    expect(playbookSchema.safeParse(pb).success).toBe(false);
  });
});

describe('library operations', () => {
  it('local playbooks override starter ones by ID and add new ones', () => {
    const revised = { ...STARTER_PLAYBOOKS[0], title: 'Revised', source: 'local' as const };
    const extra = blankPlaybook('PB-LOCAL-001', 'author');
    const merged = mergeLibrary(STARTER_PLAYBOOKS, [revised, extra]);
    expect(merged).toHaveLength(16);
    expect(merged[0]).toMatchObject({ origin: 'local-revision', playbook: { title: 'Revised' } });
    expect(merged.at(-1)?.origin).toBe('local');
  });

  it('computes direct, parent, and sub-technique coverage', () => {
    const cov = buildCoverage(index, STARTER_PLAYBOOKS);
    expect(coverageLevel(cov.get('T1059.001'))).toBe('direct');
    expect(coverageLevel(cov.get('T1059.003'))).toBe('direct');
    expect(coverageLevel(cov.get('T1059.005'))).toBe('parent');
    expect(coverageLevel(cov.get('T1110'))).toBe('direct');
    expect(coverageLevel(cov.get('T1595'))).toBe('none');
  });

  it('round-trips export/import and marks imports as local', () => {
    const json = exportPlaybooks(STARTER_PLAYBOOKS.slice(0, 2));
    const r = parsePlaybookImport(json, 'tester');
    expect(r.errors).toEqual([]);
    expect(r.playbooks.map((p) => p.id)).toEqual(['PB-PHISH-001', 'PB-USEREXEC-001']);
    expect(r.playbooks.every((p) => p.source === 'local')).toBe(true);
    expect(r.playbooks[0].review.history.at(-1)?.note).toMatch(/Imported/);
  });

  it('import rejects invalid JSON, oversized input, and invalid records with readable errors', () => {
    expect(parsePlaybookImport('{nope', 'x').errors[0]).toMatch(/not valid JSON/);
    expect(parsePlaybookImport('x'.repeat(2_000_001), 'x').errors[0]).toMatch(/larger/);
    const bad = parsePlaybookImport(JSON.stringify({ id: 'PB-BAD-1', title: 1 }), 'x');
    expect(bad.playbooks).toEqual([]);
    expect(bad.errors[0]).toMatch(/PB-BAD-1/);
    const proto = parsePlaybookImport('{"__proto__": {"polluted": true}}', 'x');
    expect(proto.playbooks).toEqual([]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('blank playbooks are valid drafts; status changes are recorded', () => {
    const pb = blankPlaybook(nextLocalId(['PB-LOCAL-001']), 'author');
    expect(pb.id).toBe('PB-LOCAL-002');
    expect(playbookSchema.safeParse(pb).success).toBe(true);
    const reviewed = withStatus(pb, 'Reviewed', 'reviewer.one', 'Checked against SOP');
    expect(reviewed.review.reviewer).toBe('reviewer.one');
    expect(reviewed.review.history.at(-1)).toMatchObject({ status: 'Reviewed', by: 'reviewer.one' });
    expect(playbookSchema.safeParse(reviewed).success).toBe(true);
  });

  it('bumps semantic versions', () => {
    expect(bumpVersion('1.2.3', 'patch')).toBe('1.2.4');
    expect(bumpVersion('1.2.3', 'minor')).toBe('1.3.0');
    expect(bumpVersion('1.2.3', 'major')).toBe('2.0.0');
  });
});

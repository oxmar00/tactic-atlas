import { compareTechniqueIds } from './normalize';
import type { AttackDataset, RetiredTechnique, Tactic, Technique } from './types';

export interface SearchHit {
  technique: Technique;
  score: number;
  /** Where the query matched, for display ("ID", "name", "description", ...). */
  matchedOn: string;
}

/**
 * Read-only lookup and search structure built once per dataset.
 */
export class AttackIndex {
  readonly dataset: AttackDataset;
  readonly tactics: Tactic[];
  readonly byId = new Map<string, Technique>();
  readonly retiredById = new Map<string, RetiredTechnique>();
  readonly tacticByShortname = new Map<string, Tactic>();
  readonly platforms: string[];
  readonly dataComponents: string[];
  private readonly haystacks = new Map<string, { id: string; name: string; text: string; telemetry: string }>();
  private readonly columns = new Map<string, Technique[]>();

  constructor(dataset: AttackDataset) {
    this.dataset = dataset;
    this.tactics = [...dataset.tactics].sort((a, b) => a.order - b.order);
    for (const t of this.tactics) this.tacticByShortname.set(t.shortname, t);
    for (const r of dataset.retired) this.retiredById.set(r.id, r);
    const platforms = new Set<string>();
    const components = new Set<string>();
    for (const t of dataset.techniques) {
      this.byId.set(t.id, t);
      t.platforms.forEach((p) => platforms.add(p));
      t.dataComponents.forEach((d) => components.add(d));
      this.haystacks.set(t.id, {
        id: t.id.toLowerCase(),
        name: t.name.toLowerCase(),
        text: t.description.toLowerCase(),
        telemetry: [...t.dataComponents, ...t.logSources.map((l) => `${l.name} ${l.channel}`)].join(' ').toLowerCase(),
      });
    }
    this.platforms = [...platforms].sort((a, b) => a.localeCompare(b));
    this.dataComponents = [...components].sort((a, b) => a.localeCompare(b));
    for (const tactic of this.tactics) {
      this.columns.set(
        tactic.shortname,
        dataset.techniques.filter((t) => !t.isSubtechnique && t.tactics.includes(tactic.shortname)).sort((a, b) => a.name.localeCompare(b.name)),
      );
    }
  }

  get(id: string): Technique | undefined {
    return this.byId.get(id.toUpperCase());
  }

  /** Parent techniques in a tactic column, alphabetical (Navigator ordering). */
  column(shortname: string): Technique[] {
    return this.columns.get(shortname) ?? [];
  }

  subtechniques(id: string): Technique[] {
    return (this.get(id)?.subtechniqueIds ?? []).map((s) => this.byId.get(s)).filter((t): t is Technique => !!t);
  }

  parent(t: Technique): Technique | undefined {
    return t.parentId ? this.byId.get(t.parentId) : undefined;
  }

  /** Display label like "T1059.001 PowerShell" or "T1059.001 Command and Scripting Interpreter: PowerShell". */
  label(id: string, withParent = false): string {
    const t = this.get(id);
    if (!t) return id;
    const parent = withParent && t.parentId ? this.byId.get(t.parentId) : undefined;
    return parent ? `${t.id} ${parent.name}: ${t.name}` : `${t.id} ${t.name}`;
  }

  tacticNames(t: Technique): string[] {
    return t.tactics.map((s) => this.tacticByShortname.get(s)?.name ?? s);
  }

  /**
   * Ranked search across ID, name, description, and official telemetry references.
   * Every whitespace-separated term must match somewhere (AND semantics).
   */
  search(query: string, limit = 50): SearchHit[] {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const terms = q.split(/\s+/).filter(Boolean).slice(0, 8);
    const hits: SearchHit[] = [];
    for (const t of this.dataset.techniques) {
      const h = this.haystacks.get(t.id)!;
      let score = 0;
      let matchedOn = '';
      let all = true;
      for (const term of terms) {
        if (h.id === term) {
          score += 100;
          matchedOn ||= 'ID';
        } else if (h.id.startsWith(term)) {
          score += 60;
          matchedOn ||= 'ID';
        } else if (h.name === term) {
          score += 50;
          matchedOn ||= 'name';
        } else if (h.name.includes(term)) {
          score += h.name.startsWith(term) ? 30 : 20;
          matchedOn ||= 'name';
        } else if (h.telemetry.includes(term)) {
          score += 6;
          matchedOn ||= 'telemetry';
        } else if (h.text.includes(term)) {
          score += 4;
          matchedOn ||= 'description';
        } else {
          all = false;
          break;
        }
      }
      if (all && score > 0) hits.push({ technique: t, score: t.isSubtechnique ? score - 1 : score, matchedOn });
    }
    hits.sort((a, b) => b.score - a.score || compareTechniqueIds(a.technique.id, b.technique.id));
    return hits.slice(0, limit);
  }

  /** If the query is a retired ID, explains what replaced it. */
  retiredMatch(query: string): RetiredTechnique | undefined {
    const q = query.trim().toUpperCase();
    return /^T\d{4}(\.\d{3})?$/.test(q) ? this.retiredById.get(q) : undefined;
  }
}

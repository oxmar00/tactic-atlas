import type { AttackIndex } from '../attack/attackIndex';
import { PLAYBOOK_SCHEMA_VERSION, playbookFileSchema, playbookSchema } from './schema';
import type { Playbook, PlaybookStatus } from './schema';

/**
 * Playbook library: merges starter content with locally authored playbooks, computes ATT&CK
 * coverage, and handles JSON import/export. Local playbooks with the same ID as a starter
 * playbook act as an organization revision and take precedence.
 */

export type PlaybookOrigin = 'starter' | 'local-revision' | 'local';

export interface LibraryEntry {
  playbook: Playbook;
  origin: PlaybookOrigin;
}

export function mergeLibrary(starter: readonly Playbook[], local: readonly Playbook[]): LibraryEntry[] {
  const localById = new Map(local.map((p) => [p.id, p]));
  const entries: LibraryEntry[] = starter.map((s) =>
    localById.has(s.id) ? { playbook: localById.get(s.id)!, origin: 'local-revision' as const } : { playbook: s, origin: 'starter' as const },
  );
  const starterIds = new Set(starter.map((s) => s.id));
  for (const p of local) if (!starterIds.has(p.id)) entries.push({ playbook: p, origin: 'local' });
  return entries;
}

export interface Coverage {
  /** Playbooks that list this technique directly. */
  direct: Playbook[];
  /** Playbooks that list the parent technique (for sub-techniques). */
  viaParent: Playbook[];
  /** Playbooks that list one of this technique's sub-techniques (for parents). */
  viaSub: Playbook[];
}

export type CoverageLevel = 'direct' | 'parent' | 'sub' | 'none';

export function buildCoverage(index: AttackIndex, playbooks: readonly Playbook[]): Map<string, Coverage> {
  const direct = new Map<string, Playbook[]>();
  for (const pb of playbooks) {
    for (const id of new Set(pb.techniques)) {
      const list = direct.get(id) ?? [];
      list.push(pb);
      direct.set(id, list);
    }
  }
  const out = new Map<string, Coverage>();
  for (const t of index.dataset.techniques) {
    const viaParent = t.parentId ? (direct.get(t.parentId) ?? []) : [];
    const viaSub = t.subtechniqueIds.flatMap((s) => direct.get(s) ?? []);
    out.set(t.id, { direct: direct.get(t.id) ?? [], viaParent, viaSub: [...new Set(viaSub)] });
  }
  return out;
}

export function coverageLevel(c: Coverage | undefined): CoverageLevel {
  if (!c) return 'none';
  if (c.direct.length) return 'direct';
  if (c.viaParent.length) return 'parent';
  if (c.viaSub.length) return 'sub';
  return 'none';
}

export const COVERAGE_LABEL: Record<CoverageLevel, string> = {
  direct: 'Playbook available',
  parent: 'Parent-technique playbook',
  sub: 'Sub-technique playbook',
  none: 'No playbook',
};

// --- Import / export ------------------------------------------------------------------------

export const MAX_IMPORT_BYTES = 2_000_000;

export interface ImportResult {
  playbooks: Playbook[];
  errors: string[];
}

export function exportPlaybooks(playbooks: readonly Playbook[], now = new Date()): string {
  return `${JSON.stringify({ format: 'soc-navigator-playbooks', exportedAt: now.toISOString(), playbooks }, null, 2)}\n`;
}

/**
 * Parses an imported JSON file. Imported playbooks are always marked source "local"; if one
 * claims Reviewed/Approved status, that claim is kept only when a reviewer is named (enforced by
 * the schema) and the review history records the import.
 */
export function parsePlaybookImport(text: string, importedBy: string, now = new Date()): ImportResult {
  if (text.length > MAX_IMPORT_BYTES) return { playbooks: [], errors: [`File is larger than ${MAX_IMPORT_BYTES / 1_000_000} MB.`] };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { playbooks: [], errors: ['File is not valid JSON.'] };
  }
  const file = playbookFileSchema.safeParse(json);
  const candidates: unknown[] = !file.success ? [json] : 'format' in file.data ? file.data.playbooks : [file.data];
  const playbooks: Playbook[] = [];
  const errors: string[] = [];
  candidates.forEach((c, i) => {
    const withSource = c && typeof c === 'object' ? { ...(c as object), source: 'local' } : c;
    const r = playbookSchema.safeParse(withSource);
    if (!r.success) {
      const id = (c as { id?: unknown })?.id;
      const issues = r.error.issues.slice(0, 4).map((iss) => `${iss.path.join('.') || '(root)'}: ${iss.message}`);
      errors.push(`Playbook #${i + 1}${typeof id === 'string' ? ` (${id.slice(0, 40)})` : ''} rejected - ${issues.join('; ')}`);
      return;
    }
    const pb = r.data;
    pb.review.history = [...pb.review.history, { version: pb.version, status: pb.status, by: importedBy.slice(0, 200) || 'unknown', at: now.toISOString(), note: 'Imported from JSON file.' }].slice(-100);
    playbooks.push(pb);
  });
  return { playbooks, errors };
}

export function bumpVersion(version: string, kind: 'patch' | 'minor' | 'major'): string {
  const [maj, min, pat] = version.split('.').map((n) => Number.parseInt(n, 10) || 0);
  if (kind === 'major') return `${maj + 1}.0.0`;
  if (kind === 'minor') return `${maj}.${min + 1}.0`;
  return `${maj}.${min}.${pat + 1}`;
}

export function blankPlaybook(id: string, author: string, now = new Date()): Playbook {
  const date = now.toISOString().slice(0, 10);
  return {
    schemaVersion: PLAYBOOK_SCHEMA_VERSION,
    id,
    version: '0.1.0',
    title: 'New investigation playbook',
    status: 'Draft',
    source: 'local',
    aiAssisted: false,
    techniques: ['T1059'],
    tactics: ['execution'],
    objective: 'Describe what the analyst must decide by the end of this playbook.',
    alertMeaning: 'Explain in plain language what the triggering alert means.',
    whyItMatters: 'Explain the risk if this activity is malicious.',
    difficulty: 'Beginner',
    effort: '30 minutes',
    platforms: ['Windows'],
    logSources: ['edr'],
    alertContext: { triggers: ['Describe a typical triggering detection.'], reviewFirst: ['List what to look at first.'], oftenMissing: [] },
    prerequisites: [{ text: 'Access needed to investigate.', type: 'access', required: true }],
    steps: [
      {
        id: 'validate-alert',
        title: 'Validate the alert',
        action: 'Describe exactly what to do.',
        why: 'Explain why this step matters.',
        where: ['Where to look'],
        fields: [],
        suspicious: ['What counts as suspicious'],
        legitimate: [],
        next: 'What to do next.',
        queryIds: [],
      },
    ],
    decisionTree: {
      start: 'authorized',
      nodes: [
        {
          id: 'authorized',
          question: 'Is the activity authorized and supported by reliable evidence?',
          yes: { outcome: 'benign', guidance: 'Document why it is benign and follow the closure procedure.' },
          no: { outcome: 'escalate', guidance: 'Escalate to Tier 2 with collected evidence.' },
        },
      ],
    },
    evidence: [
      { id: 'alert_id', label: 'Alert ID', hint: '', required: true, multiline: false },
      { id: 'event_time', label: 'Event timestamps and timezone', hint: '', required: true, multiline: false },
    ],
    escalation: { tier2: ['Describe findings that require Tier 2 review.'], immediate: [], benignClosure: ['Describe the evidence required to close as benign.'] },
    queries: [],
    detectionConsiderations: [],
    visibilityGaps: [],
    relatedTechniques: [],
    references: [],
    assumptions: [],
    review: { author, reviewer: null, reviewedAt: null, notes: '', history: [{ version: '0.1.0', status: 'Draft', by: author, at: date, note: 'Created.' }] },
    updatedAt: date,
  };
}

export function nextLocalId(existing: readonly string[]): string {
  let n = 1;
  while (existing.includes(`PB-LOCAL-${String(n).padStart(3, '0')}`)) n += 1;
  return `PB-LOCAL-${String(n).padStart(3, '0')}`;
}

/** Records a review/status transition in the playbook history. */
export function withStatus(pb: Playbook, status: PlaybookStatus, by: string, note: string, now = new Date()): Playbook {
  const at = now.toISOString();
  const reviewer = status === 'Draft' ? pb.review.reviewer : by;
  return {
    ...pb,
    status,
    review: {
      ...pb.review,
      reviewer,
      reviewedAt: status === 'Draft' ? pb.review.reviewedAt : at,
      history: [...pb.review.history, { version: pb.version, status, by, at, note }].slice(-100),
    },
  };
}

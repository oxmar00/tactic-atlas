import { z } from 'zod';

/**
 * Organization-authored investigation playbook contract.
 *
 * Playbooks reference ATT&CK by ID only; official names/descriptions are always read from the
 * ATT&CK dataset at runtime. This keeps MITRE metadata and local guidance separate so an
 * ATT&CK refresh can never overwrite authored content.
 */

export const PLAYBOOK_SCHEMA_VERSION = 1 as const;
export const PLAYBOOK_STATUSES = ['Draft', 'Reviewed', 'Approved'] as const;
export const DIFFICULTIES = ['Beginner', 'Intermediate', 'Advanced'] as const;
export const QUERY_LANGUAGES = ['kql', 'spl', 'generic'] as const;
export const OUTCOMES = ['benign', 'contained', 'investigate', 'escalate', 'critical', 'gap'] as const;
export const PREREQ_TYPES = ['access', 'tool', 'telemetry', 'information'] as const;
export const PLACEHOLDER_KINDS = ['string', 'datetime', 'timespan', 'number'] as const;

const LIMIT = { short: 200, medium: 2_000, long: 12_000 } as const;

const shortText = z.string().trim().min(1).max(LIMIT.short);
const text = z.string().trim().min(1).max(LIMIT.medium);
const optionalText = z.string().trim().max(LIMIT.medium);
const textList = (min = 0, max = 40) => z.array(text).min(min).max(max);

export const techniqueIdSchema = z.string().regex(/^T\d{4}(\.\d{3})?$/, 'Must be an ATT&CK technique ID such as T1059 or T1059.001');
const slug = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/, 'Use lowercase letters, digits, "-" or "_"');

/** Only https links are accepted for references (rendered with rel="noopener noreferrer"). */
export const httpsUrl = z
  .string()
  .trim()
  .max(1_000)
  .refine((v) => {
    try {
      return new URL(v).protocol === 'https:';
    } catch {
      return false;
    }
  }, 'Must be an https:// URL');

export const placeholderSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,39}$/),
  kind: z.enum(PLACEHOLDER_KINDS),
  description: text,
  example: z.string().max(LIMIT.short),
  /** Evidence field whose recorded value can pre-fill this placeholder. */
  evidenceField: slug.optional(),
});

export const queryTemplateSchema = z.object({
  id: slug,
  title: shortText,
  language: z.enum(QUERY_LANGUAGES),
  /** Product the syntax targets, e.g. "Microsoft Defender XDR advanced hunting / Microsoft Sentinel". */
  platform: shortText,
  purpose: text,
  dataSources: textList(1, 12),
  query: z.string().min(1).max(LIMIT.long),
  placeholders: z.array(placeholderSchema).max(15),
  keyFields: z.array(z.object({ name: shortText, meaning: text })).max(20),
  /** What a positive (non-empty) result does and does not establish. */
  positive: text,
  /** What a negative (empty) result does and does not establish. */
  negative: text,
  /** Permissions and telemetry the query depends on. */
  prerequisites: text,
  /** Schema/configuration variance the analyst must be aware of. */
  schemaNotes: text,
  /** A safe illustrative example (fictional values). */
  example: optionalText,
});

export const stepSchema = z.object({
  id: slug,
  title: shortText,
  action: text,
  why: text,
  where: textList(1, 12),
  fields: textList(0, 25),
  suspicious: textList(1, 15),
  legitimate: textList(0, 15),
  next: text,
  queryIds: z.array(slug).max(10),
});

const branchSchema = z
  .object({
    next: slug.optional(),
    outcome: z.enum(OUTCOMES).optional(),
    guidance: text,
  })
  .refine((b) => (b.next ? !b.outcome : !!b.outcome), 'A branch needs exactly one of "next" or "outcome"');

export const decisionNodeSchema = z.object({
  id: slug,
  question: text,
  help: optionalText.optional(),
  yes: branchSchema,
  no: branchSchema,
  /** Optional override for "Cannot determine"; defaults to the standard evidence-gap branch. */
  unknown: branchSchema.optional(),
});

export const evidenceFieldSchema = z.object({
  id: slug,
  label: shortText,
  hint: optionalText,
  required: z.boolean(),
  multiline: z.boolean(),
});

export const reviewEventSchema = z.object({
  version: shortText,
  status: z.enum(PLAYBOOK_STATUSES),
  by: shortText,
  at: z.string().max(40),
  note: optionalText,
});

export const playbookSchema = z
  .object({
    schemaVersion: z.literal(PLAYBOOK_SCHEMA_VERSION),
    id: z.string().regex(/^PB-[A-Z0-9][A-Z0-9-]{1,40}$/, 'Playbook IDs look like PB-PHISH-001'),
    version: z.string().regex(/^\d+\.\d+\.\d+$/, 'Use semantic versioning, e.g. 1.0.0'),
    title: shortText,
    status: z.enum(PLAYBOOK_STATUSES),
    source: z.enum(['starter-library', 'local']),
    aiAssisted: z.boolean(),
    techniques: z.array(techniqueIdSchema).min(1).max(20),
    tactics: z.array(slug).min(1).max(15),
    objective: text,
    alertMeaning: text,
    whyItMatters: text,
    difficulty: z.enum(DIFFICULTIES),
    effort: shortText,
    platforms: z.array(shortText).min(1).max(12),
    logSources: z.array(slug).min(1).max(20),
    alertContext: z.object({
      triggers: textList(1, 15),
      reviewFirst: textList(1, 15),
      oftenMissing: textList(0, 15),
    }),
    prerequisites: z
      .array(z.object({ text, type: z.enum(PREREQ_TYPES), required: z.boolean() }))
      .min(1)
      .max(25),
    steps: z.array(stepSchema).min(1).max(30),
    decisionTree: z.object({ start: slug, nodes: z.array(decisionNodeSchema).min(1).max(30) }),
    evidence: z.array(evidenceFieldSchema).min(1).max(40),
    escalation: z.object({
      tier2: textList(1, 20),
      immediate: textList(0, 15),
      benignClosure: textList(1, 15),
    }),
    queries: z.array(queryTemplateSchema).max(20),
    detectionConsiderations: textList(0, 15),
    visibilityGaps: textList(0, 15),
    relatedTechniques: z.array(z.object({ id: techniqueIdSchema, reason: text })).max(20),
    references: z.array(z.object({ title: shortText, url: httpsUrl })).max(25),
    assumptions: textList(0, 15),
    review: z.object({
      author: shortText,
      reviewer: z.string().max(LIMIT.short).nullable(),
      reviewedAt: z.string().max(40).nullable(),
      notes: optionalText,
      history: z.array(reviewEventSchema).max(100),
    }),
    updatedAt: z.string().max(40),
  })
  .superRefine((pb, ctx) => {
    const issue = (message: string, path: (string | number)[]) => ctx.addIssue({ code: 'custom', message, path });
    const unique = <T,>(items: T[], key: (t: T) => string, path: string) => {
      const seen = new Set<string>();
      items.forEach((it, i) => {
        const k = key(it);
        if (seen.has(k)) issue(`Duplicate id "${k}"`, [path, i]);
        seen.add(k);
      });
    };
    unique(pb.steps, (s) => s.id, 'steps');
    unique(pb.queries, (q) => q.id, 'queries');
    unique(pb.evidence, (e) => e.id, 'evidence');
    unique(pb.decisionTree.nodes, (n) => n.id, 'decisionTree');

    const queryIds = new Set(pb.queries.map((q) => q.id));
    pb.steps.forEach((s, i) =>
      s.queryIds.forEach((q) => {
        if (!queryIds.has(q)) issue(`Step references unknown query "${q}"`, ['steps', i, 'queryIds']);
      }),
    );

    const nodeIds = new Set(pb.decisionTree.nodes.map((n) => n.id));
    if (!nodeIds.has(pb.decisionTree.start)) issue('Decision tree start node does not exist', ['decisionTree', 'start']);
    pb.decisionTree.nodes.forEach((n, i) => {
      for (const key of ['yes', 'no', 'unknown'] as const) {
        const b = n[key];
        if (b?.next && !nodeIds.has(b.next)) issue(`Branch points to unknown node "${b.next}"`, ['decisionTree', 'nodes', i, key]);
        if (b?.next === n.id) issue('Branch points to its own node', ['decisionTree', 'nodes', i, key]);
      }
    });
    if (hasCycle(pb.decisionTree.nodes)) issue('Decision tree contains a cycle', ['decisionTree']);

    const evidenceIds = new Set(pb.evidence.map((e) => e.id));
    pb.queries.forEach((q, qi) => {
      const declared = new Set(q.placeholders.map((p) => p.name));
      for (const m of q.query.matchAll(/\{\{([a-z][a-z0-9_]*)\}\}/g)) {
        if (!declared.has(m[1])) issue(`Placeholder {{${m[1]}}} is not documented`, ['queries', qi, 'placeholders']);
      }
      q.placeholders.forEach((p, pi) => {
        if (!q.query.includes(`{{${p.name}}}`)) issue(`Documented placeholder "${p.name}" is not used in the query`, ['queries', qi, 'placeholders', pi]);
        if (p.evidenceField && !evidenceIds.has(p.evidenceField)) issue(`Unknown evidence field "${p.evidenceField}"`, ['queries', qi, 'placeholders', pi]);
      });
    });
    if ((pb.status === 'Reviewed' || pb.status === 'Approved') && !pb.review.reviewer) {
      issue(`${pb.status} playbooks must name a reviewer`, ['review', 'reviewer']);
    }
  });

function hasCycle(nodes: z.infer<typeof decisionNodeSchema>[]): boolean {
  const edges = new Map(nodes.map((n) => [n.id, [n.yes.next, n.no.next, n.unknown?.next].filter((x): x is string => !!x)]));
  const state = new Map<string, 1 | 2>();
  const visit = (id: string): boolean => {
    if (state.get(id) === 1) return true;
    if (state.get(id) === 2) return false;
    state.set(id, 1);
    for (const next of edges.get(id) ?? []) if (visit(next)) return true;
    state.set(id, 2);
    return false;
  };
  return nodes.some((n) => visit(n.id));
}

export type Playbook = z.infer<typeof playbookSchema>;
export type PlaybookStep = z.infer<typeof stepSchema>;
export type QueryTemplate = z.infer<typeof queryTemplateSchema>;
export type QueryPlaceholder = z.infer<typeof placeholderSchema>;
export type DecisionNode = z.infer<typeof decisionNodeSchema>;
export type DecisionBranch = z.infer<typeof branchSchema>;
export type EvidenceField = z.infer<typeof evidenceFieldSchema>;
export type PlaybookStatus = (typeof PLAYBOOK_STATUSES)[number];
export type Outcome = (typeof OUTCOMES)[number];
export type QueryLanguage = (typeof QUERY_LANGUAGES)[number];

/** A JSON file that can hold one playbook or a library export. */
export const playbookFileSchema = z.union([
  playbookSchema,
  z.object({
    format: z.literal('soc-navigator-playbooks'),
    exportedAt: z.string().max(40),
    playbooks: z.array(z.unknown()).max(500),
  }),
]);

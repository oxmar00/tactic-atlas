import type {
  AnalyticRef,
  AttackDataset,
  DataComponentRef,
  DetectionStrategyRef,
  LogSourceRef,
  RetiredTechnique,
  Tactic,
  Technique,
} from './types';

/**
 * Converts the official MITRE ATT&CK Enterprise STIX 2.1 bundle into the compact
 * `AttackDataset` used by the application.
 *
 * This module is pure (no I/O) so it is shared by the Node refresh script
 * (`scripts/update-attack.ts`) and the in-browser "apply update" action in Settings.
 *
 * Rules:
 *  - Only `enterprise-attack` objects are considered.
 *  - Revoked or deprecated objects are excluded from `techniques` and listed in `retired`.
 *  - Tactic order comes from the official x-mitre-matrix `tactic_refs`.
 *  - Telemetry (data components / log sources) comes only from official detection strategies
 *    and analytics linked to a technique through `detects` relationships.
 *  - Nothing is invented: if MITRE does not publish a field it stays empty.
 */

export class StixNormalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StixNormalizationError';
  }
}

interface StixExternalReference {
  source_name?: string;
  external_id?: string;
  url?: string;
}

interface StixObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_domains?: string[];
  external_references?: StixExternalReference[];
  modified?: string;
  [key: string]: unknown;
}

export interface NormalizeOptions {
  sourceUrl: string;
  sha256?: string | null;
  retrievedAt?: string;
  generator?: string;
  /** Max distinct log sources kept per technique (size control). */
  maxLogSources?: number;
}

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
const TACTIC_ID = /^TA\d{4}$/;

/** Removes STIX `(Citation: …)` markers, tolerating one level of nested parentheses. */
export function stripCitations(text: string): string {
  return text
    .replace(/\s*\(Citation:[^()]*(?:\([^()]*\)[^()]*)*\)/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function mitreRef(obj: StixObject): StixExternalReference | undefined {
  return obj.external_references?.find((r) => r.source_name === 'mitre-attack');
}

function isActive(obj: StixObject): boolean {
  return obj.revoked !== true && obj.x_mitre_deprecated !== true;
}

function inEnterprise(obj: StixObject): boolean {
  // Relationships and a few core objects omit x_mitre_domains; treat absence as in-scope.
  return !Array.isArray(obj.x_mitre_domains) || obj.x_mitre_domains.includes('enterprise-attack');
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

export function normalizeStixBundle(bundle: unknown, options: NormalizeOptions): AttackDataset {
  if (!bundle || typeof bundle !== 'object') {
    throw new StixNormalizationError('Input is not a JSON object.');
  }
  const b = bundle as { type?: unknown; objects?: unknown };
  if (b.type !== 'bundle' || !Array.isArray(b.objects)) {
    throw new StixNormalizationError('Input is not a STIX 2.x bundle (missing type "bundle" or objects array).');
  }

  const objects = (b.objects as unknown[]).filter(
    (o): o is StixObject =>
      !!o && typeof o === 'object' && typeof (o as StixObject).type === 'string' && typeof (o as StixObject).id === 'string',
  );
  const byId = new Map<string, StixObject>();
  for (const o of objects) byId.set(o.id, o);

  // --- Collection metadata -------------------------------------------------------------
  const collection = objects.find((o) => o.type === 'x-mitre-collection');
  const version = typeof collection?.x_mitre_version === 'string' ? collection.x_mitre_version : null;
  if (!version) {
    throw new StixNormalizationError('Bundle has no x-mitre-collection version; refusing to guess the ATT&CK release.');
  }
  if (collection?.name && !/enterprise/i.test(collection.name)) {
    throw new StixNormalizationError(`Bundle collection is "${collection.name}", expected Enterprise ATT&CK.`);
  }

  // --- Tactics (ordered by the official matrix) ----------------------------------------
  const matrix = objects.find((o) => o.type === 'x-mitre-matrix' && isActive(o) && inEnterprise(o));
  const tacticRefs = asStringArray(matrix?.tactic_refs);
  if (tacticRefs.length === 0) {
    throw new StixNormalizationError('Bundle has no Enterprise x-mitre-matrix with tactic_refs.');
  }
  const tactics: Tactic[] = [];
  tacticRefs.forEach((ref) => {
    const t = byId.get(ref);
    if (!t || t.type !== 'x-mitre-tactic' || !isActive(t)) return;
    const ext = mitreRef(t);
    const shortname = typeof t.x_mitre_shortname === 'string' ? t.x_mitre_shortname : '';
    if (!ext?.external_id || !TACTIC_ID.test(ext.external_id) || !shortname) return;
    tactics.push({
      id: ext.external_id,
      shortname,
      name: t.name ?? shortname,
      description: stripCitations(t.description ?? ''),
      url: ext.url ?? `https://attack.mitre.org/tactics/${ext.external_id}/`,
      order: tactics.length,
    });
  });
  const tacticOrder = new Map(tactics.map((t) => [t.shortname, t.order]));

  // --- Data components -------------------------------------------------------------------
  const dataComponents: DataComponentRef[] = [];
  const dcNameByStixId = new Map<string, string>();
  for (const o of objects) {
    if (o.type !== 'x-mitre-data-component' || !inEnterprise(o)) continue;
    const ext = mitreRef(o);
    if (o.name) dcNameByStixId.set(o.id, o.name);
    if (!isActive(o) || !ext?.external_id || !o.name) continue;
    dataComponents.push({ id: ext.external_id, name: o.name, description: stripCitations(o.description ?? '') });
  }
  dataComponents.sort((a, b) => a.name.localeCompare(b.name));

  // --- Relationships ---------------------------------------------------------------------
  const parentOf = new Map<string, string>(); // child stix id -> parent stix id
  const strategiesFor = new Map<string, string[]>(); // attack-pattern stix id -> detection strategy stix ids
  const revokedBy = new Map<string, string>(); // stix id -> stix id
  for (const r of objects) {
    if (r.type !== 'relationship' || r.revoked === true) continue;
    const src = typeof r.source_ref === 'string' ? r.source_ref : '';
    const tgt = typeof r.target_ref === 'string' ? r.target_ref : '';
    switch (r.relationship_type) {
      case 'subtechnique-of':
        parentOf.set(src, tgt);
        break;
      case 'detects': {
        const list = strategiesFor.get(tgt) ?? [];
        list.push(src);
        strategiesFor.set(tgt, list);
        break;
      }
      case 'revoked-by':
        revokedBy.set(src, tgt);
        break;
      default:
        break;
    }
  }

  // --- Techniques --------------------------------------------------------------------------
  const maxLogSources = options.maxLogSources ?? 24;
  const techniques: Technique[] = [];
  const retired: RetiredTechnique[] = [];
  const idByStix = new Map<string, string>();
  let analyticsCount = 0;
  let strategyCount = 0;

  const attackPatterns = objects.filter((o) => o.type === 'attack-pattern' && inEnterprise(o));
  for (const o of attackPatterns) {
    const ext = mitreRef(o);
    if (ext?.external_id && TECHNIQUE_ID.test(ext.external_id)) idByStix.set(o.id, ext.external_id);
  }

  for (const o of attackPatterns) {
    const id = idByStix.get(o.id);
    if (!id) continue;
    const ext = mitreRef(o)!;
    if (!isActive(o)) {
      const replacement = revokedBy.get(o.id);
      retired.push({
        id,
        name: o.name ?? id,
        status: o.revoked === true ? 'revoked' : 'deprecated',
        replacedBy: replacement ? (idByStix.get(replacement) ?? null) : null,
      });
      continue;
    }

    const phases = Array.isArray(o.kill_chain_phases) ? (o.kill_chain_phases as { kill_chain_name?: string; phase_name?: string }[]) : [];
    const techniqueTactics = phases
      .filter((p) => p.kill_chain_name === 'mitre-attack' && typeof p.phase_name === 'string' && tacticOrder.has(p.phase_name))
      .map((p) => p.phase_name as string)
      .sort((a, c) => (tacticOrder.get(a) ?? 0) - (tacticOrder.get(c) ?? 0));

    // Detection strategies -> analytics -> log sources / data components (official only).
    const detectionStrategies: DetectionStrategyRef[] = [];
    const dcNames = new Set<string>();
    const logSources: LogSourceRef[] = [];
    const seenLogSource = new Set<string>();
    for (const dsId of strategiesFor.get(o.id) ?? []) {
      const ds = byId.get(dsId);
      if (!ds || ds.type !== 'x-mitre-detection-strategy' || !isActive(ds)) continue;
      const dsExt = mitreRef(ds);
      if (!dsExt?.external_id) continue;
      strategyCount += 1;
      const analytics: AnalyticRef[] = [];
      for (const anId of asStringArray(ds.x_mitre_analytic_refs)) {
        const an = byId.get(anId);
        if (!an || an.type !== 'x-mitre-analytic' || !isActive(an)) continue;
        const anExt = mitreRef(an);
        analyticsCount += 1;
        analytics.push({
          id: anExt?.external_id ?? an.name ?? 'analytic',
          platforms: asStringArray(an.x_mitre_platforms),
          description: stripCitations(an.description ?? ''),
          url: anExt?.url ?? dsExt.url ?? '',
        });
        const refs = Array.isArray(an.x_mitre_log_source_references)
          ? (an.x_mitre_log_source_references as { x_mitre_data_component_ref?: string; name?: string; channel?: string }[])
          : [];
        for (const ref of refs) {
          const dcName = ref.x_mitre_data_component_ref ? dcNameByStixId.get(ref.x_mitre_data_component_ref) : undefined;
          if (dcName) dcNames.add(dcName);
          const key = `${dcName ?? ''}|${ref.name ?? ''}|${ref.channel ?? ''}`;
          if (ref.name && !seenLogSource.has(key) && logSources.length < maxLogSources) {
            seenLogSource.add(key);
            logSources.push({ dataComponent: dcName ?? 'Unspecified', name: ref.name, channel: ref.channel ?? '' });
          }
        }
      }
      detectionStrategies.push({
        id: dsExt.external_id,
        name: ds.name ?? dsExt.external_id,
        url: dsExt.url ?? `https://attack.mitre.org/detectionstrategies/${dsExt.external_id}`,
        analytics,
      });
    }

    const isSub = o.x_mitre_is_subtechnique === true || id.includes('.');
    const parentStix = parentOf.get(o.id);
    const parentId = isSub ? (parentStix ? (idByStix.get(parentStix) ?? null) : id.split('.')[0]) : null;

    techniques.push({
      id,
      name: o.name ?? id,
      description: stripCitations(o.description ?? ''),
      url: ext.url ?? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
      tactics: techniqueTactics,
      platforms: asStringArray(o.x_mitre_platforms).sort(),
      isSubtechnique: isSub,
      parentId,
      subtechniqueIds: [],
      dataComponents: [...dcNames].sort(),
      logSources,
      detectionStrategies,
      version: typeof o.x_mitre_version === 'string' ? o.x_mitre_version : null,
      modified: o.modified ?? '',
    });
  }

  // Link sub-techniques to active parents.
  const byTechId = new Map(techniques.map((t) => [t.id, t]));
  for (const t of techniques) {
    if (!t.parentId) continue;
    const parent = byTechId.get(t.parentId);
    if (parent) parent.subtechniqueIds.push(t.id);
    else t.parentId = null; // parent retired: keep the sub-technique visible on its own
  }
  for (const t of techniques) t.subtechniqueIds.sort();
  techniques.sort((a, c) => compareTechniqueIds(a.id, c.id));
  retired.sort((a, c) => compareTechniqueIds(a.id, c.id));

  // A technique may appear in the bundle more than once only if MITRE published duplicates.
  const dedupedRetired = retired.filter((r, i) => retired.findIndex((x) => x.id === r.id) === i && !byTechId.has(r.id));

  const subCount = techniques.filter((t) => t.isSubtechnique).length;
  return {
    meta: {
      domain: 'enterprise-attack',
      version,
      modified: collection?.modified ?? '',
      sourceUrl: options.sourceUrl,
      sha256: options.sha256 ?? null,
      retrievedAt: options.retrievedAt ?? new Date().toISOString(),
      generator: options.generator ?? 'soc-navigator/normalizeStixBundle',
      attackSpecVersion: typeof collection?.x_mitre_attack_spec_version === 'string' ? collection.x_mitre_attack_spec_version : null,
      counts: {
        tactics: tactics.length,
        techniques: techniques.length - subCount,
        subtechniques: subCount,
        revoked: dedupedRetired.filter((r) => r.status === 'revoked').length,
        deprecated: dedupedRetired.filter((r) => r.status === 'deprecated').length,
        detectionStrategies: strategyCount,
        analytics: analyticsCount,
      },
    },
    tactics,
    techniques,
    retired: dedupedRetired,
    dataComponents,
  };
}

/** Sorts T1003 < T1003.001 < T1003.002 < T1005 numerically. */
export function compareTechniqueIds(a: string, b: string): number {
  const [aBase, aSub = '0'] = a.slice(1).split('.');
  const [bBase, bSub = '0'] = b.slice(1).split('.');
  return Number(aBase) - Number(bBase) || Number(aSub) - Number(bSub);
}

/**
 * Structural sanity checks on a normalized dataset. Returns human-readable problems;
 * an empty array means the dataset is usable.
 */
export function validateDataset(ds: AttackDataset, opts: { minTechniques?: number } = {}): string[] {
  const problems: string[] = [];
  const minTechniques = opts.minTechniques ?? 100;
  if (ds.meta?.domain !== 'enterprise-attack') problems.push('meta.domain must be "enterprise-attack".');
  if (!/^\d+(\.\d+)*$/.test(ds.meta?.version ?? '')) problems.push('meta.version is missing or malformed.');
  if (!Array.isArray(ds.tactics) || ds.tactics.length < 10) problems.push(`Expected at least 10 tactics, found ${ds.tactics?.length ?? 0}.`);
  if (!Array.isArray(ds.techniques) || ds.techniques.length < minTechniques) {
    problems.push(`Expected at least ${minTechniques} techniques, found ${ds.techniques?.length ?? 0}.`);
    return problems;
  }
  const shortnames = new Set(ds.tactics.map((t) => t.shortname));
  const ids = new Set<string>();
  for (const t of ds.techniques) {
    if (!TECHNIQUE_ID.test(t.id)) problems.push(`Malformed technique ID "${t.id}".`);
    if (ids.has(t.id)) problems.push(`Duplicate technique ID ${t.id}.`);
    ids.add(t.id);
    if (t.tactics.length === 0) problems.push(`${t.id} has no tactic in the Enterprise matrix.`);
    for (const s of t.tactics) if (!shortnames.has(s)) problems.push(`${t.id} references unknown tactic "${s}".`);
  }
  for (const t of ds.techniques) {
    if (t.isSubtechnique && t.parentId && !ids.has(t.parentId)) problems.push(`${t.id} references missing parent ${t.parentId}.`);
    for (const s of t.subtechniqueIds) if (!ids.has(s)) problems.push(`${t.id} lists missing sub-technique ${s}.`);
  }
  return problems.slice(0, 50);
}

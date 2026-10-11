import { z } from 'zod';
import { normalizeStixBundle, validateDataset } from './normalize';
import type { AttackDataset } from './types';
import { idbDelete, idbGet, idbSet } from '../idb';

/**
 * Loads the ATT&CK dataset with a documented fallback chain:
 *   1. A newer release the analyst explicitly downloaded in Settings (IndexedDB), if valid.
 *   2. The snapshot bundled with the build (public/data/attack-enterprise.json).
 *   3. Otherwise: an error state - playbooks and investigations keep working without the matrix.
 */

export const OFFICIAL_INDEX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json';
const OFFICIAL_PREFIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/';
const OVERRIDE_KEY = 'attack-enterprise-override';

export type DatasetSource = 'bundled' | 'browser-update';

export interface LoadedDataset {
  dataset: AttackDataset;
  source: DatasetSource;
  warnings: string[];
}

const datasetShape = z.object({
  meta: z.object({
    domain: z.literal('enterprise-attack'),
    version: z.string(),
    modified: z.string(),
    sourceUrl: z.string(),
    sha256: z.string().nullable(),
    retrievedAt: z.string(),
    generator: z.string(),
    attackSpecVersion: z.string().nullable(),
    counts: z.record(z.string(), z.number()),
  }),
  tactics: z.array(z.object({ id: z.string(), shortname: z.string(), name: z.string(), description: z.string(), url: z.string(), order: z.number() })),
  techniques: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      description: z.string(),
      url: z.string(),
      tactics: z.array(z.string()),
      platforms: z.array(z.string()),
      isSubtechnique: z.boolean(),
      parentId: z.string().nullable(),
      subtechniqueIds: z.array(z.string()),
      dataComponents: z.array(z.string()),
      logSources: z.array(z.object({ dataComponent: z.string(), name: z.string(), channel: z.string() })),
      detectionStrategies: z.array(
        z.object({
          id: z.string(),
          name: z.string(),
          url: z.string(),
          analytics: z.array(z.object({ id: z.string(), platforms: z.array(z.string()), description: z.string(), url: z.string() })),
        }),
      ),
      version: z.string().nullable(),
      modified: z.string(),
    }),
  ),
  retired: z.array(z.object({ id: z.string(), name: z.string(), status: z.enum(['revoked', 'deprecated']), replacedBy: z.string().nullable() })),
  dataComponents: z.array(z.object({ id: z.string(), name: z.string(), description: z.string() })),
});

/** Parses unknown JSON into a validated dataset or throws with a readable reason. */
export function parseDataset(json: unknown): AttackDataset {
  const parsed = datasetShape.safeParse(json);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new Error(`ATT&CK dataset has an unexpected shape at ${first?.path.join('.') || '(root)'}: ${first?.message ?? 'invalid'}`);
  }
  const dataset = parsed.data as AttackDataset;
  const problems = validateDataset(dataset);
  if (problems.length) throw new Error(`ATT&CK dataset failed validation: ${problems.slice(0, 3).join(' ')}`);
  return dataset;
}

export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export async function fetchBundledDataset(baseUrl: string): Promise<AttackDataset> {
  const res = await fetch(`${baseUrl}data/attack-enterprise.json`, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`Could not load the bundled ATT&CK snapshot (HTTP ${res.status}).`);
  return parseDataset(await res.json());
}

export async function loadDataset(baseUrl: string): Promise<LoadedDataset> {
  const warnings: string[] = [];
  let override: AttackDataset | null = null;
  try {
    const stored = await idbGet<unknown>(OVERRIDE_KEY);
    if (stored) override = parseDataset(stored);
  } catch (err) {
    warnings.push(`A previously downloaded ATT&CK update could not be used and was ignored (${err instanceof Error ? err.message : 'unknown error'}).`);
    await idbDelete(OVERRIDE_KEY).catch(() => undefined);
  }

  let bundled: AttackDataset | null = null;
  let bundledError: unknown = null;
  try {
    bundled = await fetchBundledDataset(baseUrl);
  } catch (err) {
    bundledError = err;
  }

  if (override && (!bundled || compareVersions(override.meta.version, bundled.meta.version) >= 0)) {
    if (!bundled) warnings.push('The bundled snapshot could not be loaded; using the release downloaded in this browser.');
    return { dataset: override, source: 'browser-update', warnings };
  }
  if (override && bundled) {
    warnings.push(`The bundled snapshot (${bundled.meta.version}) is newer than the release downloaded in this browser (${override.meta.version}); using the bundled snapshot.`);
  }
  if (bundled) return { dataset: bundled, source: 'bundled', warnings };
  throw bundledError instanceof Error ? bundledError : new Error('ATT&CK data could not be loaded.');
}

export interface ReleaseInfo {
  version: string;
  url: string;
  modified: string | null;
}

/** Analyst-initiated: asks MITRE's public index for the latest Enterprise release. Sends no incident data. */
export async function checkLatestRelease(signal?: AbortSignal): Promise<ReleaseInfo> {
  const res = await fetch(OFFICIAL_INDEX_URL, { signal, cache: 'no-cache', credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new Error(`MITRE index request failed (HTTP ${res.status}).`);
  const index = (await res.json()) as { collections?: { name?: string; versions?: { version?: string; url?: string; modified?: string }[] }[] };
  const latest = index.collections?.find((c) => c.name === 'Enterprise ATT&CK')?.versions?.[0];
  if (!latest?.version || !latest.url?.startsWith(OFFICIAL_PREFIX)) throw new Error('MITRE index did not list a usable Enterprise ATT&CK release.');
  return { version: latest.version, url: latest.url, modified: latest.modified ?? null };
}

/** Downloads, normalizes, validates, and stores a release in this browser. The previous data stays active on any failure. */
export async function downloadAndApplyRelease(release: ReleaseInfo, signal?: AbortSignal): Promise<AttackDataset> {
  if (!release.url.startsWith(OFFICIAL_PREFIX)) throw new Error('Refusing to download ATT&CK data from a non-official URL.');
  const res = await fetch(release.url, { signal, credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new Error(`Download failed (HTTP ${res.status}).`);
  const bundle = (await res.json()) as unknown;
  const dataset = normalizeStixBundle(bundle, { sourceUrl: release.url, sha256: null, generator: 'soc-navigator/browser-update' });
  if (dataset.meta.version !== release.version) throw new Error(`Downloaded bundle declares ${dataset.meta.version}, expected ${release.version}.`);
  const problems = validateDataset(dataset);
  if (problems.length) throw new Error(`Downloaded data failed validation: ${problems.slice(0, 3).join(' ')}`);
  await idbSet(OVERRIDE_KEY, dataset);
  return dataset;
}

export async function revertToBundled(): Promise<void> {
  await idbDelete(OVERRIDE_KEY);
}

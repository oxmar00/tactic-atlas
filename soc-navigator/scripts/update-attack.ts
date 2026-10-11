/**
 * Refreshes the bundled MITRE ATT&CK Enterprise snapshot from the official STIX 2.1 data.
 *
 *   npm run attack:update                         # latest Enterprise release from attack-stix-data
 *   npm run attack:update -- --version 19.2       # a specific release
 *   npm run attack:update -- --file ./enterprise-attack-19.2.json   # offline / air-gapped
 *   npm run attack:verify                         # validate the committed snapshot only
 *
 * Safety properties:
 *  - Downloads only from https://raw.githubusercontent.com/mitre-attack/attack-stix-data/.
 *  - Normalizes with the same pure module the browser uses (src/lib/attack/normalize.ts).
 *  - Validates before writing; on any failure the existing snapshot is left untouched.
 *  - Refuses to replace a newer snapshot with an older release unless --allow-downgrade.
 *  - Writes atomically (temp file + rename) and prints added/removed technique IDs.
 *  - Never touches organization-authored playbooks (src/data/playbooks, browser storage).
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeStixBundle, validateDataset } from '../src/lib/attack/normalize.ts';
import type { AttackDataset } from '../src/lib/attack/types.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_OUT = resolve(ROOT, 'public/data/attack-enterprise.json');
const INDEX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json';
const ALLOWED_PREFIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/';

interface Args {
  file?: string;
  version?: string;
  out: string;
  verifyOnly: boolean;
  allowDowngrade: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { out: DEFAULT_OUT, verifyOnly: false, allowDowngrade: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      const v = argv[i + 1];
      if (!v || v.startsWith('--')) throw new Error(`${a} requires a value`);
      i += 1;
      return v;
    };
    if (a === '--file') args.file = resolve(process.cwd(), next());
    else if (a === '--version') args.version = next();
    else if (a === '--out') args.out = resolve(process.cwd(), next());
    else if (a === '--verify-only') args.verifyOnly = true;
    else if (a === '--allow-downgrade') args.allowDowngrade = true;
    else if (a === '--help' || a === '-h') {
      console.log(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('*/')[0]);
      process.exit(0);
    } else throw new Error(`Unknown argument: ${a}`);
  }
  if (args.version && !/^\d+(\.\d+)*$/.test(args.version)) throw new Error('--version must look like 19.2');
  return args;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

async function fetchBytes(url: string): Promise<Buffer> {
  if (!url.startsWith(ALLOWED_PREFIX)) throw new Error(`Refusing to download from non-allowlisted URL: ${url}`);
  const res = await fetch(url, { redirect: 'error' });
  if (!res.ok) throw new Error(`HTTP ${res.status} while downloading ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

async function resolveBundleUrl(version?: string): Promise<{ url: string; version: string }> {
  const index = JSON.parse((await fetchBytes(INDEX_URL)).toString('utf8')) as {
    collections?: { name?: string; versions?: { version?: string; url?: string }[] }[];
  };
  const enterprise = index.collections?.find((c) => c.name === 'Enterprise ATT&CK');
  if (!enterprise?.versions?.length) throw new Error('index.json does not list an "Enterprise ATT&CK" collection.');
  const chosen = version ? enterprise.versions.find((v) => v.version === version) : enterprise.versions[0];
  if (!chosen?.url || !chosen.version) throw new Error(version ? `Enterprise ATT&CK ${version} is not listed in index.json.` : 'No Enterprise release found.');
  return { url: chosen.url, version: chosen.version };
}

function readExisting(path: string): AttackDataset | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as AttackDataset;
  } catch {
    return null;
  }
}

function summarizeDiff(prev: AttackDataset | null, next: AttackDataset): string {
  if (!prev) return 'No previous snapshot.';
  const before = new Set(prev.techniques.map((t) => t.id));
  const after = new Set(next.techniques.map((t) => t.id));
  const added = [...after].filter((id) => !before.has(id));
  const removed = [...before].filter((id) => !after.has(id));
  const fmt = (xs: string[]) => (xs.length ? `${xs.length} (${xs.slice(0, 25).join(', ')}${xs.length > 25 ? ', …' : ''})` : '0');
  return `Previous release ${prev.meta.version} -> ${next.meta.version}\n  Added active IDs:   ${fmt(added)}\n  Removed active IDs: ${fmt(removed)}`;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const existing = readExisting(args.out);

  if (args.verifyOnly) {
    if (!existing) throw new Error(`No readable snapshot at ${args.out}`);
    const problems = validateDataset(existing);
    if (problems.length) throw new Error(`Snapshot failed validation:\n - ${problems.join('\n - ')}`);
    console.log(`OK: ATT&CK Enterprise ${existing.meta.version} snapshot is valid (${existing.meta.counts.techniques} techniques, ${existing.meta.counts.subtechniques} sub-techniques, ${existing.meta.counts.tactics} tactics).`);
    return;
  }

  let bytes: Buffer;
  let sourceUrl: string;
  if (args.file) {
    bytes = readFileSync(args.file);
    sourceUrl = `local-file:${basename(args.file)}`;
    console.log(`Reading local STIX bundle ${args.file} (${(bytes.length / 1e6).toFixed(1)} MB)`);
  } else {
    const { url, version } = await resolveBundleUrl(args.version);
    console.log(`Downloading Enterprise ATT&CK ${version} from ${url}`);
    bytes = await fetchBytes(url);
    sourceUrl = url;
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const bundle = JSON.parse(bytes.toString('utf8')) as unknown;
  const dataset = normalizeStixBundle(bundle, {
    sourceUrl,
    sha256,
    generator: 'soc-navigator/scripts/update-attack.ts',
  });
  if (args.version && dataset.meta.version !== args.version) {
    throw new Error(`Requested ${args.version} but the bundle declares ${dataset.meta.version}.`);
  }
  const problems = validateDataset(dataset);
  if (problems.length) throw new Error(`Normalized dataset failed validation; snapshot NOT updated:\n - ${problems.join('\n - ')}`);

  if (existing?.meta?.version && compareVersions(dataset.meta.version, existing.meta.version) < 0 && !args.allowDowngrade) {
    throw new Error(`Refusing to downgrade ${existing.meta.version} -> ${dataset.meta.version}. Pass --allow-downgrade to force.`);
  }

  const tmp = `${args.out}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(dataset)}\n`);
  renameSync(tmp, args.out);

  const c = dataset.meta.counts;
  console.log(`Wrote ${args.out}`);
  console.log(`  ATT&CK Enterprise ${dataset.meta.version} (modified ${dataset.meta.modified})`);
  console.log(`  ${c.tactics} tactics, ${c.techniques} techniques, ${c.subtechniques} sub-techniques, ${c.revoked} revoked, ${c.deprecated} deprecated`);
  console.log(`  ${c.detectionStrategies} detection strategies, ${c.analytics} analytics; sha256 ${sha256}`);
  console.log(summarizeDiff(existing, dataset));
  console.log('Next: run `npm test` (verifies starter playbook technique IDs are still active) and review any removed IDs.');
}

main().catch((err: unknown) => {
  console.error(`ATT&CK update failed: ${err instanceof Error ? err.message : String(err)}`);
  console.error('The existing snapshot was left unchanged.');
  process.exit(1);
});

/**
 * Builds a small index of the TacticAtlas detection/response library (../data/playbooks.json)
 * so SOC Navigator can link each ATT&CK technique to the matching TacticAtlas record.
 *
 *   npm run tacticatlas:index            # regenerate public/data/tacticatlas-index.json
 *   npm run tacticatlas:index -- --check # fail if the committed index is stale (used in CI)
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = resolve(ROOT, '../data/playbooks.json');
const OUT = resolve(ROOT, 'public/data/tacticatlas-index.json');
const TECH = /^T\d{4}(\.\d{3})?$/;

interface SourceRecord {
  id: string;
  name: string;
  kind: string;
  severity?: string;
  techniques?: { id: string }[];
  subtechniques?: { id: string }[];
}

const data = JSON.parse(readFileSync(SOURCE, 'utf8')) as { meta: { content_version: string; attack: { version: string } }; playbooks: SourceRecord[] };
const records = data.playbooks
  .map((p) => ({
    id: p.id,
    name: p.name,
    kind: p.kind,
    severity: p.severity ?? '',
    techniques: [...new Set([...(p.techniques ?? []), ...(p.subtechniques ?? [])].map((t) => t.id).filter((id) => TECH.test(id)))].sort(),
  }))
  .filter((r) => r.techniques.length > 0)
  .sort((a, b) => a.id.localeCompare(b.id));

const output = `${JSON.stringify({ source: 'TacticAtlas data/playbooks.json', contentVersion: data.meta.content_version, attackVersion: data.meta.attack.version, records })}\n`;

if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(OUT, 'utf8');
  } catch {
    /* missing */
  }
  if (current !== output) {
    console.error('tacticatlas-index.json is stale. Run: npm run tacticatlas:index');
    process.exit(1);
  }
  console.log(`OK: TacticAtlas index is current (${records.length} records).`);
} else {
  writeFileSync(OUT, output);
  console.log(`Wrote ${OUT} (${records.length} records, ${output.length} bytes).`);
}

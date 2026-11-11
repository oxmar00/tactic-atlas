import { z } from 'zod';

/**
 * Link to the sibling TacticAtlas detection/response library published next to this app.
 * Optional: when the index cannot be loaded, the links simply do not appear.
 */

const indexSchema = z.object({
  source: z.string(),
  contentVersion: z.string(),
  attackVersion: z.string(),
  records: z.array(z.object({ id: z.string().max(60), name: z.string().max(300), kind: z.string().max(40), severity: z.string().max(40), techniques: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)) })).max(2000),
});

export interface TacticAtlasRecord {
  id: string;
  name: string;
  kind: string;
  severity: string;
  /** How this record relates to the technique that was looked up. */
  relation: 'technique' | 'parent';
}

export class TacticAtlasIndex {
  readonly contentVersion: string;
  readonly attackVersion: string;
  readonly recordCount: number;
  private readonly byTechnique = new Map<string, Omit<TacticAtlasRecord, 'relation'>[]>();

  constructor(json: unknown) {
    const data = indexSchema.parse(json);
    this.contentVersion = data.contentVersion;
    this.attackVersion = data.attackVersion;
    this.recordCount = data.records.length;
    for (const r of data.records) {
      for (const t of r.techniques) {
        const list = this.byTechnique.get(t) ?? [];
        list.push({ id: r.id, name: r.name, kind: r.kind, severity: r.severity });
        this.byTechnique.set(t, list);
      }
    }
  }

  /** Records covering the technique directly, or (for sub-techniques) its parent. */
  lookup(techniqueId: string): TacticAtlasRecord[] {
    const direct = (this.byTechnique.get(techniqueId) ?? []).map((r) => ({ ...r, relation: 'technique' as const }));
    const parentId = techniqueId.includes('.') ? techniqueId.split('.')[0] : null;
    const viaParent = parentId ? (this.byTechnique.get(parentId) ?? []).filter((r) => !direct.some((d) => d.id === r.id)).map((r) => ({ ...r, relation: 'parent' as const })) : [];
    return [...direct, ...viaParent];
  }
}

/** Base URL of the TacticAtlas app. Defaults to the parent path, matching the GitHub Pages layout. */
export function tacticAtlasUrl(recordId: string, base = '../'): string {
  return `${base.endsWith('/') ? base : `${base}/`}#${encodeURIComponent(recordId)}`;
}

export async function loadTacticAtlasIndex(baseUrl: string): Promise<TacticAtlasIndex | null> {
  try {
    const res = await fetch(`${baseUrl}data/tacticatlas-index.json`);
    if (!res.ok) return null;
    return new TacticAtlasIndex(await res.json());
  } catch {
    return null;
  }
}

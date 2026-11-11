import { z } from 'zod';
import { investigationSchema } from './investigations/model';
import type { Investigation } from './investigations/model';
import { playbookSchema } from './playbooks/schema';
import type { Playbook } from './playbooks/schema';

/** Import of exported investigations and backups, validated record by record. */

export const MAX_BACKUP_BYTES = 6_000_000;

export interface BackupImport {
  investigations: Investigation[];
  playbooks: Playbook[];
  rejected: string[];
}

const envelope = z.object({
  format: z.enum(['soc-navigator-backup', 'soc-navigator-investigations', 'soc-navigator-investigation']),
  investigations: z.array(z.unknown()).max(1000).optional(),
  investigation: z.unknown().optional(),
  localPlaybooks: z.array(z.unknown()).max(500).optional(),
});

export function parseBackup(text: string): BackupImport {
  const result: BackupImport = { investigations: [], playbooks: [], rejected: [] };
  if (text.length > MAX_BACKUP_BYTES) return { ...result, rejected: ['File is larger than 6 MB.'] };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ...result, rejected: ['File is not valid JSON.'] };
  }
  const env = envelope.safeParse(json);
  if (!env.success) return { ...result, rejected: ['Not a SOC Navigator export (expected an investigation, investigations, or backup file).'] };
  const rawInvestigations = [...(env.data.investigations ?? []), ...(env.data.investigation !== undefined ? [env.data.investigation] : [])];
  rawInvestigations.forEach((raw, i) => {
    const r = investigationSchema.safeParse(raw);
    if (r.success) result.investigations.push(r.data);
    else result.rejected.push(`Investigation #${i + 1} rejected: ${r.error.issues[0]?.path.join('.') || '(root)'} ${r.error.issues[0]?.message ?? ''}`.slice(0, 300));
  });
  (env.data.localPlaybooks ?? []).forEach((raw, i) => {
    const r = playbookSchema.safeParse(raw && typeof raw === 'object' ? { ...(raw as object), source: 'local' } : raw);
    if (r.success) result.playbooks.push(r.data);
    else result.rejected.push(`Playbook #${i + 1} rejected: ${r.error.issues[0]?.path.join('.') || '(root)'} ${r.error.issues[0]?.message ?? ''}`.slice(0, 300));
  });
  return result;
}

/** Merges imported records by ID. Existing records are kept unless `overwrite` is true. */
export function mergeById<T extends { id: string }>(existing: readonly T[], incoming: readonly T[], overwrite: boolean): { merged: T[]; added: number; replaced: number; skipped: number } {
  const map = new Map(existing.map((x) => [x.id, x]));
  let added = 0;
  let replaced = 0;
  let skipped = 0;
  for (const item of incoming) {
    if (!map.has(item.id)) {
      map.set(item.id, item);
      added += 1;
    } else if (overwrite) {
      map.set(item.id, item);
      replaced += 1;
    } else skipped += 1;
  }
  return { merged: [...map.values()], added, replaced, skipped };
}

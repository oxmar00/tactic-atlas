import type { z } from 'zod';

/**
 * Persistence boundary for the demo build.
 *
 * Browser localStorage is NOT a secure store: it is readable by any script running on the
 * same origin, is not encrypted at rest by the application, and is cleared when the user
 * clears site data. It is acceptable here only for demo progress and non-sensitive
 * preferences. Production deployments must replace `StorageAdapter` with an authenticated,
 * access-controlled, audited backend (see docs/PRODUCTION.md).
 */

export interface StorageAdapter {
  read(key: string): string | null;
  write(key: string, value: string): void;
  remove(key: string): void;
  /** Approximate bytes used by this app's keys. */
  usage(): number;
}

export const STORAGE_PREFIX = 'socnav.v1.';
export const KEYS = {
  settings: `${STORAGE_PREFIX}settings`,
  investigations: `${STORAGE_PREFIX}investigations`,
  playbooks: `${STORAGE_PREFIX}playbooks`,
  usage: `${STORAGE_PREFIX}usage`,
} as const;

/** Hard cap so a runaway import cannot fill the origin quota (typically ~5 MB). */
export const MAX_COLLECTION_BYTES = 3_500_000;

export function createBrowserStorage(): StorageAdapter {
  const ls = (): Storage | null => {
    try {
      return typeof window !== 'undefined' ? window.localStorage : null;
    } catch {
      return null;
    }
  };
  return {
    read(key) {
      try {
        return ls()?.getItem(key) ?? null;
      } catch {
        return null;
      }
    },
    write(key, value) {
      const s = ls();
      if (!s) throw new Error('Browser storage is unavailable (private mode or blocked). Progress will not persist.');
      s.setItem(key, value);
    },
    remove(key) {
      try {
        ls()?.removeItem(key);
      } catch {
        /* ignore */
      }
    },
    usage() {
      const s = ls();
      if (!s) return 0;
      let total = 0;
      for (let i = 0; i < s.length; i += 1) {
        const k = s.key(i);
        if (k?.startsWith(STORAGE_PREFIX)) total += k.length + (s.getItem(k)?.length ?? 0);
      }
      return total * 2; // UTF-16
    },
  };
}

/** In-memory adapter for tests and as a fallback when localStorage is blocked. */
export function createMemoryStorage(initial: Record<string, string> = {}): StorageAdapter {
  const map = new Map(Object.entries(initial));
  return {
    read: (k) => map.get(k) ?? null,
    write: (k, v) => void map.set(k, v),
    remove: (k) => void map.delete(k),
    usage: () => [...map.entries()].reduce((n, [k, v]) => n + (k.length + v.length) * 2, 0),
  };
}

export interface LoadResult<T> {
  items: T[];
  /** Records that failed validation and were set aside. */
  rejected: number;
  error: string | null;
}

/**
 * Reads a JSON array and validates each record independently, so one corrupted record does
 * not destroy the rest. Rejected raw data is preserved under `<key>.rejected` for recovery.
 */
export function loadCollection<T>(adapter: StorageAdapter, key: string, schema: z.ZodType<T>): LoadResult<T> {
  const raw = adapter.read(key);
  if (raw === null) return { items: [], rejected: 0, error: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    safeBackup(adapter, `${key}.rejected`, raw);
    return { items: [], rejected: 1, error: 'Stored data was not valid JSON and was set aside.' };
  }
  if (!Array.isArray(parsed)) {
    safeBackup(adapter, `${key}.rejected`, raw);
    return { items: [], rejected: 1, error: 'Stored data had an unexpected format and was set aside.' };
  }
  const items: T[] = [];
  const bad: unknown[] = [];
  for (const entry of parsed) {
    const r = schema.safeParse(entry);
    if (r.success) items.push(r.data);
    else bad.push(entry);
  }
  if (bad.length) safeBackup(adapter, `${key}.rejected`, JSON.stringify(bad).slice(0, 500_000));
  return { items, rejected: bad.length, error: bad.length ? `${bad.length} stored record(s) failed validation and were set aside.` : null };
}

export function saveCollection<T>(adapter: StorageAdapter, key: string, items: T[]): { ok: true } | { ok: false; error: string } {
  const json = JSON.stringify(items);
  if (json.length * 2 > MAX_COLLECTION_BYTES) {
    return { ok: false, error: 'Not saved: browser storage limit for this demo would be exceeded. Export and delete older investigations.' };
  }
  try {
    adapter.write(key, json);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'Browser storage write failed.' };
  }
}

export function loadObject<T>(adapter: StorageAdapter, key: string, schema: z.ZodType<T>, fallback: T): T {
  const raw = adapter.read(key);
  if (raw === null) return fallback;
  try {
    const r = schema.safeParse(JSON.parse(raw));
    return r.success ? r.data : fallback;
  } catch {
    return fallback;
  }
}

function safeBackup(adapter: StorageAdapter, key: string, value: string): void {
  try {
    adapter.write(key, value);
  } catch {
    /* best effort */
  }
}

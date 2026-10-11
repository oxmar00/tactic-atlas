/**
 * Minimal IndexedDB key/value wrapper used only for the (large, non-sensitive) ATT&CK dataset
 * downloaded in the browser. Investigation data never goes here.
 */

const DB_NAME = 'soc-navigator';
const STORE = 'kv';

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB is not available in this browser.'));
      return;
    }
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed.'));
  });
}

function run<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const req = fn(tx.objectStore(STORE));
        tx.oncomplete = () => {
          db.close();
          resolve(req.result as T);
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error ?? new Error('IndexedDB transaction failed.'));
        };
      }),
  );
}

export function idbGet<T>(key: string): Promise<T | undefined> {
  return run<T | undefined>('readonly', (s) => s.get(key)).catch(() => undefined);
}

export function idbSet(key: string, value: unknown): Promise<void> {
  return run<void>('readwrite', (s) => s.put(value, key));
}

export function idbDelete(key: string): Promise<void> {
  return run<void>('readwrite', (s) => s.delete(key));
}

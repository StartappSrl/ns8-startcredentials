/**
 * Archivio locale su IndexedDB. Contiene SOLO:
 * - `cache`: risposte GET in whitelist (ciphertext E2EE, identico al server);
 * - `meta`: impostazioni non segrete (serverUrl, email, pinnedOrgSignPublic, autoLock).
 *
 * Nessuna chiave sbloccata, nessun token, nessuno stato di sessione tocca il disco.
 * Il bundle delle chiavi (`me.privateEnc`) è avvolto da Argon2id(master password):
 * a riposo è ciphertext inutile senza la master password.
 */

const DB_NAME = "startcredentials-pwa";
const DB_VERSION = 1;
const CACHE = "cache";
const META = "meta";

export interface CachedResponse {
  status: number;
  contentType: string;
  /** b64 del corpo; se `enc`, è b64 di (IV ‖ ciphertext) AES-GCM (vedi cacheCrypto.ts). */
  body: string;
  at: number;
  /** true per le voci cifrate a riposo (tutto tranne /me). Assente = vecchia voce in chiaro. */
  enc?: boolean;
}

let dbp: Promise<IDBDatabase> | null = null;

function open(): Promise<IDBDatabase> {
  if (dbp) return dbp;
  dbp = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(CACHE)) db.createObjectStore(CACHE);
      if (!db.objectStoreNames.contains(META)) db.createObjectStore(META);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbp;
}

function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(store, mode);
        const req = fn(t.objectStore(store));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      }),
  );
}

/** Namespace della cache per origine del server (come il motore nativo). */
const cacheKey = (origin: string, pathAndQuery: string) => `${origin}|${pathAndQuery}`;

export async function getCached(origin: string, pathAndQuery: string): Promise<CachedResponse | null> {
  const v = await tx<CachedResponse | undefined>(CACHE, "readonly", (s) => s.get(cacheKey(origin, pathAndQuery)));
  return v ?? null;
}

export async function putCached(origin: string, pathAndQuery: string, v: Omit<CachedResponse, "at">): Promise<void> {
  await tx(CACHE, "readwrite", (s) => s.put({ ...v, at: Date.now() }, cacheKey(origin, pathAndQuery)));
}

export async function getMeta<T>(key: string): Promise<T | null> {
  const v = await tx<T | undefined>(META, "readonly", (s) => s.get(key));
  return v ?? null;
}

export async function setMeta(key: string, value: unknown): Promise<void> {
  await tx(META, "readwrite", (s) => s.put(value, key));
}

/** Uscita dall'account / cambio server / offline disattivato: via tutto. */
export async function wipeAll(): Promise<void> {
  await tx(CACHE, "readwrite", (s) => s.clear());
  await tx(META, "readwrite", (s) => s.clear());
}

/** Chiede al browser di non sfrattare i dati offline (concesso di norma dopo l'installazione). */
export async function requestPersistence(): Promise<boolean> {
  try {
    if (navigator.storage?.persist) return await navigator.storage.persist();
  } catch {
    /* non supportato */
  }
  return false;
}

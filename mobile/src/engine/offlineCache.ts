/**
 * Archivio per l'uso offline: conserva le risposte di lettura del server
 * (dati già cifrati, identici a quelli sul server) nella memoria privata
 * dell'app. Senza la master password sono illeggibili.
 */
import { Directory, File, Paths } from "expo-file-system";
import * as Crypto from "expo-crypto";

export interface CachedResponse { status: number; contentType: string; body: string; at: number }

export { isCacheable } from "./cachePolicy";

const hash = (s: string) => Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, s);
const root = () => new Directory(Paths.document, "offline");

async function dirFor(origin: string): Promise<Directory> {
  const r = root();
  if (!r.exists) r.create();
  const d = new Directory(r, (await hash(origin)).slice(0, 24));
  if (!d.exists) d.create();
  return d;
}

export async function putCached(origin: string, key: string, v: Omit<CachedResponse, "at">): Promise<void> {
  const f = new File(await dirFor(origin), `${await hash(key)}.json`);
  if (f.exists) f.delete();
  f.create();
  f.write(JSON.stringify({ ...v, at: Date.now() }));
}

export async function getCached(origin: string, key: string): Promise<CachedResponse | null> {
  const f = new File(await dirFor(origin), `${await hash(key)}.json`);
  if (!f.exists) return null;
  try {
    return JSON.parse(await f.text()) as CachedResponse;
  } catch {
    return null;
  }
}

export async function markSynced(origin: string): Promise<void> {
  const f = new File(await dirFor(origin), "sync.json");
  if (f.exists) f.delete();
  f.create();
  f.write(JSON.stringify({ at: Date.now() }));
}

export async function lastSynced(origin: string): Promise<number | null> {
  const f = new File(await dirFor(origin), "sync.json");
  if (!f.exists) return null;
  try {
    return (JSON.parse(await f.text()) as { at: number }).at;
  } catch {
    return null;
  }
}

/** Cancella tutti i dati offline (uscita dall'account, cambio server, opzione disattivata). */
export function wipeOffline(): void {
  const r = root();
  if (r.exists) r.delete();
}

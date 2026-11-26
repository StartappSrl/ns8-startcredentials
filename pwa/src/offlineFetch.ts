/**
 * `fetch` iniettato nell'Api dell'SDK (vedi packages/client/src/api.ts).
 * Replica `Engine.doFetch` del motore nativo (mobile/src/engine/Engine.tsx):
 *
 * - online: esegue la richiesta reale; se è una GET in whitelist e la risposta è OK,
 *   ne salva il corpo (ciphertext) in IndexedDB;
 * - offline (errore di rete): per le GET in whitelist restituisce la copia salvata,
 *   altrimenti propaga l'errore.
 *
 * Non salva MAI nulla fuori dalla whitelist `isCacheable`: niente `/auth/*`, niente token,
 * niente sessioni. Lo stato online/offline è osservabile.
 *
 * H2 — cifratura a riposo: quando una `cacheKey` è disponibile (dopo lo sblocco), tutte le
 * voci vengono cifrate (AES-GCM) TRANNE `/me`, che resta in chiaro perché serve al bootstrap
 * dello sblocco offline (la sua parte segreta è comunque già avvolta). Le vecchie voci in
 * chiaro restano leggibili e vengono riscritte cifrate al primo accesso online (migrazione).
 */
import { isCacheable } from "./cachePolicy.js";
import { getCached, putCached } from "./db.js";
import { openBody, sealBody } from "./cacheCrypto.js";

const bytesToB64 = (b: Uint8Array): string => {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
};
const b64ToBytes = (s: string): Uint8Array => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

/** `/me` resta in chiaro: è il bootstrap dello sblocco offline (parte segreta già avvolta). */
const BOOTSTRAP = "/api/v1/me";

export interface NetState {
  offline: boolean;
  onChange?: (offline: boolean) => void;
}

/** La cacheKey è fornita dal chiamante (sessione): null finché non si è sbloccato. */
export type CacheKeyGetter = () => CryptoKey | null;

/** Crea un fetch con fallback offline, legato all'origine consentita (il server configurato). */
export function makeOfflineFetch(allowedOrigin: string, net: NetState, getCacheKey: CacheKeyGetter): typeof fetch {
  const setOffline = (v: boolean) => {
    if (net.offline !== v) {
      net.offline = v;
      net.onChange?.(v);
    }
  };

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();

    let origin: string;
    let pathAndQuery: string;
    let cacheable = false;
    try {
      const u = new URL(url);
      origin = u.origin;
      if (origin !== allowedOrigin) throw new Error("Destinazione non consentita");
      pathAndQuery = `${u.pathname}${u.search}`;
      cacheable = isCacheable(method, pathAndQuery);
    } catch (e) {
      throw new TypeError((e as Error).message);
    }
    const encryptable = cacheable && pathAndQuery !== BOOTSTRAP;

    try {
      const res = await fetch(input, init);
      setOffline(false);
      if (cacheable && res.ok) {
        const bytes = new Uint8Array(await res.clone().arrayBuffer());
        const key = getCacheKey();
        let body: string;
        let enc = false;
        if (encryptable && key) {
          body = await sealBody(key, bytes);
          enc = true;
        } else {
          body = bytesToB64(bytes);
        }
        await putCached(origin, pathAndQuery, {
          status: res.status,
          contentType: res.headers.get("content-type") ?? "",
          body,
          enc,
        }).catch(() => undefined);
      }
      return res;
    } catch (netErr) {
      // Rete assente: per le letture in whitelist si usa la copia salvata.
      if (cacheable) {
        const c = await getCached(origin, pathAndQuery).catch(() => null);
        if (c) {
          let bytes: Uint8Array | null;
          if (c.enc) {
            const key = getCacheKey();
            // Senza chiave (non ancora sbloccato) o dato manomesso: trattalo come cache miss.
            bytes = key ? await openBody(key, c.body).catch(() => null) : null;
          } else {
            bytes = b64ToBytes(c.body);
          }
          if (bytes) {
            setOffline(true);
            return new Response(bytes, { status: c.status, headers: { "content-type": c.contentType } });
          }
        }
      }
      setOffline(true);
      throw netErr;
    }
  };
}

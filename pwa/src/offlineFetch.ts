/**
 * `fetch` iniettato nell'Api dell'SDK (vedi packages/client/src/api.ts).
 * Replica `Engine.doFetch` del motore nativo (mobile/src/engine/Engine.tsx):
 *
 * - online: esegue la richiesta reale; se è una GET in whitelist e la risposta è OK,
 *   ne salva il corpo (ciphertext) in IndexedDB;
 * - offline (errore di rete): per le GET in whitelist restituisce la copia salvata,
 *   altrimenti propaga l'errore.
 *
 * Non salva MAI nulla fuori dalla whitelist `isCacheable`: niente `/auth/*`,
 * niente token, niente sessioni. Lo stato online/offline è osservabile.
 */
import { isCacheable } from "./cachePolicy.js";
import { getCached, putCached } from "./db.js";

const bytesToB64 = (buf: ArrayBuffer): string => {
  let s = "";
  const b = new Uint8Array(buf);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
};
const b64ToBytes = (s: string): Uint8Array => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export interface NetState {
  offline: boolean;
  onChange?: (offline: boolean) => void;
}

/** Crea un fetch con fallback offline, legato all'origine consentita (il server configurato). */
export function makeOfflineFetch(allowedOrigin: string, net: NetState): typeof fetch {
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

    try {
      const res = await fetch(input, init);
      setOffline(false);
      if (cacheable && res.ok) {
        const buf = await res.clone().arrayBuffer();
        await putCached(origin, pathAndQuery, {
          status: res.status,
          contentType: res.headers.get("content-type") ?? "",
          body: bytesToB64(buf),
        }).catch(() => undefined);
      }
      return res;
    } catch (netErr) {
      // Rete assente: per le letture in whitelist si usa la copia salvata (ciphertext).
      if (cacheable) {
        const c = await getCached(origin, pathAndQuery).catch(() => null);
        if (c) {
          setOffline(true);
          return new Response(b64ToBytes(c.body), {
            status: c.status,
            headers: { "content-type": c.contentType },
          });
        }
      }
      setOffline(true);
      throw netErr;
    }
  };
}

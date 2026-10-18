/**
 * Ospita il motore crittografico in una WebView invisibile e ne fa da ponte:
 * - chiamate: engine.call("metodo", ...argomenti) → Promise;
 * - rete: il motore non ha accesso diretto (CSP senza connect-src); le sue
 *   richieste le esegue l'app, e solo verso l'origine del server configurato.
 */
import { createContext, ReactNode, useCallback, useContext, useMemo, useRef, useState } from "react";
import { View } from "react-native";
import { WebView, WebViewMessageEvent } from "react-native-webview";
import { ENGINE_HTML } from "./engineHtml";
import { getCached, isCacheable, lastSynced, markSynced, putCached, wipeOffline } from "./offlineCache";

/** Segnaposto per un argomento non specificato (ricostruito come undefined dal motore). */
export const UNDEFINED = "\u0000sc:undefined";

export class EngineError extends Error {
  constructor(message: string, public code?: string, public status?: number) {
    super(message);
    this.name = "EngineError";
  }
}

type Pending = { resolve: (v: unknown) => void; reject: (e: EngineError) => void; timer: ReturnType<typeof setTimeout> };

export interface Engine {
  ready: boolean;
  call<T = unknown>(method: string, ...args: unknown[]): Promise<T>;
  /** Origine a cui il motore può inviare richieste (impostata con init). */
  setAllowedOrigin(origin: string | null): void;
  /** true se l'ultima richiesta non ha raggiunto il server. */
  offline: boolean;
  /** Data dell'ultima sincronizzazione completa per l'uso offline. */
  lastSync: number | null;
  setOfflineEnabled(on: boolean): void;
  /** Scarica tutto ciò che serve per l'uso offline (con la rete disponibile). */
  syncForOffline(): Promise<boolean>;
  hasOfflineData(): Promise<boolean>;
  wipeOffline(): void;
  /** Chiamata quando il server risponde 401 fuori dall'accesso (sessione scaduta). */
  onUnauthorized(fn: (() => void) | null): void;
}

const EngineCtx = createContext<Engine | null>(null);
export const useEngine = (): Engine => {
  const e = useContext(EngineCtx);
  if (!e) throw new Error("EngineProvider mancante");
  return e;
};

function bytesToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function EngineProvider({ children }: { children: ReactNode }) {
  const web = useRef<WebView>(null);
  const pending = useRef(new Map<number, Pending>());
  const seq = useRef(0);
  const allowedOrigin = useRef<string | null>(null);
  const [ready, setReady] = useState(false);
  const [offline, setOffline] = useState(false);
  const [lastSync, setLastSync] = useState<number | null>(null);
  const offlineEnabled = useRef(true);
  const unauthorized = useRef<(() => void) | null>(null);
  const readyWaiters = useRef<(() => void)[]>([]);

  const send = (m: unknown) => web.current?.postMessage(JSON.stringify(m));

  /** Richiesta di rete per conto del motore, solo verso il server configurato. */
  const doFetch = async (m: { id: number; url: string; method: string; headers: Record<string, string>; body?: string; bodyType?: "text" | "base64" }) => {
    let origin: string;
    let key: string;
    let cacheable = false;
    try {
      const u = new URL(m.url);
      origin = u.origin;
      if (!allowedOrigin.current || origin !== allowedOrigin.current) throw new Error("Destinazione non consentita");
      key = `${u.pathname}${u.search}`;
      cacheable = offlineEnabled.current && isCacheable(m.method, key);
    } catch (e) {
      send({ type: "fetch-result", id: m.id, status: 0, headers: {}, body: "", error: (e as Error).message });
      return;
    }
    let r: Response;
    try {
      const body = m.body === undefined ? undefined : m.bodyType === "base64" ? b64ToBytes(m.body) : m.body;
      r = await fetch(m.url, { method: m.method, headers: m.headers, body: body as BodyInit | undefined });
    } catch {
      // Rete assente: per le letture si usa la copia salvata (dati cifrati).
      setOffline(true);
      const c = cacheable ? await getCached(origin, key).catch(() => null) : null;
      if (c) send({ type: "fetch-result", id: m.id, status: c.status, headers: { "content-type": c.contentType }, body: c.body });
      else send({ type: "fetch-result", id: m.id, status: 0, headers: {}, body: "", error: "Rete non raggiungibile" });
      return;
    }
    setOffline(false);
    if (r.status === 401 && !key.startsWith("/api/v1/auth/")) unauthorized.current?.();
    const ct = r.headers.get("content-type") ?? "";
    const body = bytesToB64(await r.arrayBuffer());
    if (cacheable && r.ok) await putCached(origin, key, { status: r.status, contentType: ct, body }).catch(() => undefined);
    send({ type: "fetch-result", id: m.id, status: r.status, headers: { "content-type": ct }, body });
  };

  const onMessage = (e: WebViewMessageEvent) => {
    let m: { type: string; id?: number; ok?: boolean; value?: unknown; error?: { message: string; code?: string; status?: number } };
    try {
      m = JSON.parse(e.nativeEvent.data);
    } catch {
      return;
    }
    if (m.type === "ready") {
      setReady(true);
      for (const w of readyWaiters.current.splice(0)) w();
    } else if (m.type === "result" && m.id !== undefined) {
      const p = pending.current.get(m.id);
      if (!p) return;
      pending.current.delete(m.id);
      clearTimeout(p.timer);
      if (m.ok) p.resolve(m.value);
      else p.reject(new EngineError(m.error?.message ?? "Errore", m.error?.code, m.error?.status));
    } else if (m.type === "fetch") {
      void doFetch(m as never);
    }
  };

  const call = useCallback(async <T,>(method: string, ...args: unknown[]): Promise<T> => {
    if (!ready) await new Promise<void>((r) => readyWaiters.current.push(r));
    const id = ++seq.current;
    return new Promise<T>((resolve, reject) => {
      // Argon2id con 256 MiB su telefoni lenti può richiedere qualche secondo.
      const timer = setTimeout(() => {
        pending.current.delete(id);
        reject(new EngineError("Il motore non risponde"));
      }, 120_000);
      pending.current.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      // JSON trasforma undefined in null: lo marchiamo perché il motore lo ricostruisca.
      send({ type: "call", id, method, args: args.map((a) => (a === undefined ? UNDEFINED : a)) });
    });
  }, [ready]);

  const engine = useMemo<Engine>(() => ({
    ready,
    call,
    offline,
    lastSync,
    setAllowedOrigin: (o) => {
      allowedOrigin.current = o;
      if (o) void lastSynced(o).then(setLastSync).catch(() => undefined);
    },
    setOfflineEnabled: (on) => { offlineEnabled.current = on; },
    syncForOffline: async () => {
      if (!allowedOrigin.current || !offlineEnabled.current) return false;
      try {
        await call("syncAll");
        await markSynced(allowedOrigin.current);
        setLastSync(Date.now());
        return true;
      } catch {
        return false;
      }
    },
    hasOfflineData: async () => !!allowedOrigin.current && !!(await getCached(allowedOrigin.current, "/api/v1/me").catch(() => null)),
    wipeOffline: () => { wipeOffline(); setLastSync(null); },
    onUnauthorized: (fn) => { unauthorized.current = fn; },
  }), [ready, call, offline, lastSync]);

  return (
    <EngineCtx.Provider value={engine}>
      {children}
      <View style={{ width: 0, height: 0, position: "absolute", opacity: 0 }} pointerEvents="none">
        <WebView
          ref={web}
          source={{ html: ENGINE_HTML, baseUrl: "about:blank" }}
          originWhitelist={["about:*"]}
          onMessage={onMessage}
          // Nessuna navigazione oltre la pagina iniziale del motore.
          onShouldStartLoadWithRequest={(r) => r.url === "about:blank" || r.url.startsWith("about:")}
          javaScriptEnabled
          domStorageEnabled={false}
          incognito
          cacheEnabled={false}
          allowFileAccess={false}
          setSupportMultipleWindows={false}
          mixedContentMode="never"
        />
      </View>
    </EngineCtx.Provider>
  );
}

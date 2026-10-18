/**
 * Motore di StartCredentials per Android: gira in una WebView nascosta (che
 * supporta WebAssembly) ed esegue lo stesso SDK dell'estensione. Le chiavi
 * restano solo qui, in memoria. L'app nativa:
 *   - chiama i metodi con {type:"call", id, method, args};
 *   - esegue per il motore le richieste di rete ({type:"fetch"}), così la
 *     WebView non contatta nessuno direttamente.
 */
import {
  Api, ApiError, effectiveTotpUri, enableMfa, Item, login, logout, ready, SecurityError, serverStatus,
  SerializedSession, setupMfa, trustDevice, Vault, verifyMfa,
} from "@startcredentials/client";

type Msg =
  | { type: "call"; id: number; method: string; args: unknown[] }
  | { type: "fetch-result"; id: number; status: number; headers: Record<string, string>; body: string; error?: string };

declare global {
  interface Window {
    ReactNativeWebView?: { postMessage(data: string): void };
    __scEngine?: { receive(raw: string): void };
  }
}

const post = (m: unknown) => window.ReactNativeWebView?.postMessage(JSON.stringify(m));

// ------------------------------------------------------------------ base64

function toB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ------------------------------------------------------------------ rete tramite l'app

let fetchSeq = 0;
const pendingFetch = new Map<number, (r: Extract<Msg, { type: "fetch-result" }>) => void>();

/** fetch compatibile con l'SDK: la richiesta la esegue l'app nativa. */
const bridgedFetch: typeof fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const body = init?.body;
  let payload: { body?: string; bodyType?: "text" | "base64" } = {};
  if (typeof body === "string") payload = { body, bodyType: "text" };
  else if (body instanceof Uint8Array) payload = { body: toB64(body), bodyType: "base64" };
  const id = ++fetchSeq;
  const res = await new Promise<Extract<Msg, { type: "fetch-result" }>>((resolve) => {
    pendingFetch.set(id, resolve);
    post({ type: "fetch", id, url, method: init?.method ?? "GET", headers: init?.headers ?? {}, ...payload });
  });
  if (res.error) throw new TypeError(res.error);
  return new Response(res.status === 204 ? null : (fromB64(res.body) as unknown as BodyInit), { status: res.status, headers: res.headers });
};

// ------------------------------------------------------------------ stato

let api: Api | null = null;
let vault: Vault | null = null;
let pinned: string | undefined;
const itemCache = new Map<string, Item>();

function needApi(): Api {
  if (!api) throw new Error("Server non configurato");
  return api;
}
function needVault(): Vault {
  if (!vault) throw new SecurityError("Cassaforte bloccata");
  return vault;
}
function remember(items: Item[]): Item[] {
  for (const i of items) itemCache.set(i.id, i);
  return items;
}

/** Metodi esposti all'app: solo questi, con argomenti serializzabili. */
const methods: Record<string, (...args: never[]) => unknown> = {
  async init(serverUrl: string, pinnedOrg?: string) {
    await ready();
    api = new Api({ baseUrl: serverUrl, fetch: bridgedFetch });
    pinned = pinnedOrg || undefined;
    return { ok: true };
  },
  status: async () => serverStatus(needApi()),
  setToken(token: string | null) { needApi().token = token ?? undefined; return true; },
  async login(email: string, password: string, deviceToken?: string) {
    const r = await login(needApi(), email, password, { deviceToken });
    return { state: r.state, trustedDevice: !!r.trustedDevice, token: r.token };
  },
  session: async () => needApi().get<{ state: string }>("/auth/session"),
  verifyMfa: async (code: string) => { await verifyMfa(needApi(), code); return true; },
  setupMfa: async () => setupMfa(needApi()),
  enableMfa: async (code: string) => enableMfa(needApi(), code),
  trustDevice: async (name: string) => trustDevice(needApi(), name),
  async unlock(password: string) {
    vault = await Vault.unlock(needApi(), password, { pinnedOrgSignPublic: pinned });
    await vault.ensureRecoveryCopy().catch(() => undefined);
    return { me: vault.me, fingerprint: vault.myFingerprint };
  },
  /** Sessione da custodire nell'archivio protetto da biometria del telefono. */
  serialize: () => ({ token: needApi().token, vault: needVault().serialize() }),
  async restore(s: { token: string; vault: SerializedSession }) {
    needApi().token = s.token;
    vault = await Vault.restore(needApi(), s.vault, { pinnedOrgSignPublic: pinned });
    return { me: vault.me, fingerprint: vault.myFingerprint };
  },
  lock() {
    vault?.lock();
    vault = null;
    itemCache.clear();
    return true;
  },
  async logout() {
    methods.lock();
    await logout(needApi()).catch(() => undefined);
    return true;
  },
  containers: async () => needVault().containers(),
  container: async (id: string) => needVault().container(id),
  items: async (id: string, trash?: boolean) => remember(await needVault().items(id, { trash: !!trash })),
  sharedWithMe: async () => remember(await needVault().sharedWithMe()),
  totp: async (uri: string) => Vault.totp(uri),
  effectiveTotp: (itemId: string) => {
    const it = itemCache.get(itemId);
    return it ? effectiveTotpUri(it.data) ?? null : null;
  },
  async downloadAttachment(itemId: string, attachmentId: string) {
    const it = itemCache.get(itemId);
    const att = it?.attachments.find((a) => a.id === attachmentId);
    if (!it || !att) throw new Error("Allegato non trovato");
    return { name: att.name, mime: att.mime, data: toB64(await needVault().downloadAttachment(it, att)) };
  },
  report: (action: Parameters<Vault["report"]>[0], containerId: string, itemId?: string) => { needVault().report(action, containerId, itemId); return true; },
  changes: async (since: number) => needVault().changes(since),
  devices: async () => needVault().devices(),
  revokeDevice: async (id: string) => { await needVault().revokeDevice(id); return true; },
  me: () => ({ me: needVault().me, fingerprint: needVault().myFingerprint }),
  /** Legge tutto ciò che serve offline: l'app ne conserva le risposte cifrate. */
  async syncAll() {
    const v = needVault();
    await v.refreshMe();
    await v.directory(true);
    let items = 0;
    const cs = await v.containers();
    for (const c of cs) {
      if (c.kind === "org") continue;
      await v.container(c.id);
      items += remember(await v.items(c.id)).length;
    }
    items += remember(await v.sharedWithMe()).length;
    await v.devices().catch(() => undefined);
    return { containers: cs.length, items };
  },
};

async function handle(m: Extract<Msg, { type: "call" }>) {
  const fn = methods[m.method];
  try {
    if (!fn) throw new Error(`Metodo sconosciuto: ${m.method}`);
    const value = await (fn as (...a: unknown[]) => unknown)(...(m.args ?? []));
    post({ type: "result", id: m.id, ok: true, value });
  } catch (e) {
    const err = e as Error & { code?: string; status?: number };
    post({
      type: "result", id: m.id, ok: false,
      error: { message: err.message, code: e instanceof ApiError ? err.code : e instanceof SecurityError ? "security" : err.code, status: err.status },
    });
  }
}

window.__scEngine = {
  receive(raw: string) {
    let m: Msg;
    try {
      m = JSON.parse(raw);
    } catch {
      return;
    }
    if (m.type === "call") void handle(m);
    else if (m.type === "fetch-result") {
      pendingFetch.get(m.id)?.(m);
      pendingFetch.delete(m.id);
    }
  },
};
// Messaggi dall'app (react-native-webview li consegna su window e, su Android, su document).
const onMessage = (e: Event) => window.__scEngine!.receive((e as MessageEvent).data);
window.addEventListener("message", onMessage);
document.addEventListener("message", onMessage as EventListener);
post({ type: "ready" });

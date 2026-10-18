/**
 * Test del motore Android: la pagina della WebView gira in jsdom, il ponte di
 * rete è simulato come lo fa l'app, il server e il database sono reali.
 * Uso (dalla radice): node mobile/engine/engine.test.mjs
 */
import { JSDOM } from "jsdom";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createHmac } from "node:crypto";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const root = new URL("../../", import.meta.url).pathname;
const { createPool, migrate } = await import(join(root, "app/dist/src/core.js"));
const { buildApp, APP_ROOT } = await import(join(root, "app/dist/src/server.js"));
const sdk = await import(join(root, "packages/client/dist/src/index.js"));
const { isCacheable } = await import(join(root, "mobile/src/engine/cachePolicy.ts"));

const db = createPool(process.env.TEST_DATABASE_URL ?? "postgres://sc:sc@127.0.0.1/sc");
await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
await migrate(db, join(APP_ROOT, "migrations"));
const bootstrapToken = randomBytes(24).toString("base64url");
const server = await buildApp({ databaseUrl: "", serverSecret: randomBytes(32), bootstrapToken, publicUrl: "http://127.0.0.1",
  attachmentsDir: mkdtempSync(join(tmpdir(), "sc-eng-")), port: 0, maxAttachmentBytes: 5e6, sessionHours: 12,
  authPerIpPerMinute: 10000, authPerKeyPerMinute: 10000, trustedDeviceDays: 30 }, db);
await server.listen({ host: "127.0.0.1", port: 0 });
const serverUrl = `http://127.0.0.1:${server.server.address().port}`;

// Dati di partenza creati con l'SDK (come farebbe l'estensione).
const b32 = (secret) => { const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, v = 0; const o = []; for (const c of secret) { v = (v << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(o); };
const totp = (secret) => { const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000))); const h = createHmac("sha1", b32(secret)).update(m).digest(); const f = h[19] & 15; return String((((h[f] & 127) << 24) | (h[f + 1] << 16) | (h[f + 2] << 8) | h[f + 3]) % 1e6).padStart(6, "0"); };
const FAST = { opsLimit: 2, memLimitBytes: 19 * 1024 * 1024 };
const a = new sdk.Api({ baseUrl: serverUrl });
await sdk.register(a, { token: bootstrapToken, email: "marco@azienda.it", displayName: "Marco", password: "password di marco", kdf: FAST });
const mfa = await sdk.setupMfa(a);
await sdk.enableMfa(a, totp(mfa.secret));
const v = await sdk.Vault.unlock(a, "password di marco");
await v.initOrg();
const cid = await v.createContainer({ name: "Cliente Mobile" });
await v.createFolder(cid, "Server");
const OTP = "otpauth://totp/X?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
await v.createItem(cid, { type: "login", name: "Router", username: "admin", password: "r0uter!", urls: ["https://router.mobile.it"], totpUri: OTP });
const [it] = await v.items(cid);
const pdf = new Uint8Array(120_000).map((_, i) => (i * 5) % 256);
await v.addAttachment(it, pdf, "schema.pdf", "application/pdf");
const resetCounter = () => db.query("UPDATE users SET mfa_last_counter = 0");

// Pagina della WebView.
const src = readFileSync(join(root, "mobile/src/engine/engineHtml.ts"), "utf8");
const html = JSON.parse(src.slice(src.indexOf("= ") + 2, src.lastIndexOf(";")));
let fetches = 0;
// Ponte di rete come quello dell'app: archivio offline delle letture e rete spegnibile.
let network = true;
const offlineCache = new Map();
const pending = new Map();
let seq = 0;
let readyResolve;
const readyP = new Promise((r) => (readyResolve = r));
const dom = new JSDOM(html, {
  runScripts: "dangerously",
  beforeParse(w) {
    Object.assign(w, { Response, Headers, WebAssembly });
    // TextEncoder/Decoder definiti nel contesto della pagina, come nella WebView vera.
    w.eval(`
      window.TextEncoder = class { encode(s = "") { const b = unescape(encodeURIComponent(s)); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; } };
      window.TextDecoder = class { constructor(label, opts) { this.fatal = !!(opts && opts.fatal); } decode(u) { if (!u) return ""; let s = ""; const a = new Uint8Array(u.buffer ? u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) : u); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return decodeURIComponent(escape(s)); } };
    `);
    Object.defineProperty(w, "crypto", { value: globalThis.crypto });
    w.ReactNativeWebView = { postMessage: (data) => onEngine(JSON.parse(data)) };
  },
});
const w = dom.window;
function onEngine(m) {
  if (m.type === "ready") return readyResolve();
  if (m.type === "result") { pending.get(m.id)?.(m); pending.delete(m.id); return; }
  if (m.type === "fetch") {
    fetches++;
    // Come l'app nativa: esegue la richiesta e restituisce il corpo in base64.
    (async () => {
      const u = new URL(m.url);
      const key = `${u.pathname}${u.search}`;
      const cacheable = isCacheable(m.method, key);
      const reply = (status, ct, body, error) => w.__scEngine.receive(JSON.stringify({ type: "fetch-result", id: m.id, status, headers: { "content-type": ct }, body, error }));
      try {
        if (!network) throw new TypeError("Network request failed");
        const body = m.bodyType === "base64" ? Buffer.from(m.body, "base64") : m.body;
        const r = await fetch(m.url, { method: m.method, headers: m.headers, body });
        const ct = r.headers.get("content-type") ?? "";
        const buf = Buffer.from(await r.arrayBuffer()).toString("base64");
        if (cacheable && r.ok) offlineCache.set(key, { status: r.status, ct, body: buf });
        reply(r.status, ct, buf);
      } catch (e) {
        const c = cacheable ? offlineCache.get(key) : null;
        if (c) reply(c.status, c.ct, c.body);
        else reply(0, "", "", "Rete non raggiungibile");
      }
    })();
  }
}
const call = (method, ...args) => new Promise((resolve, reject) => {
  const id = ++seq;
  pending.set(id, (m) => (m.ok ? resolve(m.value) : reject(Object.assign(new Error(m.error.message), m.error))));
  w.__scEngine.receive(JSON.stringify({ type: "call", id, method, args }));
});
const step = (s) => console.log(`✓ ${s}`);

try {
  await readyP;
  step("motore avviato nella WebView");
  await call("init", serverUrl);
  const l = await call("login", "marco@azienda.it", "password di marco");
  assert.equal(l.state, "mfa_pending");
  await resetCounter();
  await call("verifyMfa", totp(mfa.secret));
  const trust = await call("trustDevice", "Pixel 8 – Android");
  step("accesso OPAQUE e codice MFA tramite il ponte di rete");
  const u = await call("unlock", "password di marco");
  assert.equal(u.me.email, "marco@azienda.it");
  assert.match(u.fingerprint, /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
  step("sblocco con la master password (Argon2id nella WebView)");
  const cs = await call("containers");
  const c = cs.find((x) => x.meta.name === "Cliente Mobile");
  assert.ok(c);
  const det = await call("container", c.id);
  assert.deepEqual(det.folders.map((f) => f.name), ["Server"]);
  const items = await call("items", c.id);
  assert.equal(items[0].data.password, "r0uter!");
  const code = await call("totp", await call("effectiveTotp", items[0].id));
  assert.match(code.code, /^\d{6}$/);
  const file = await call("downloadAttachment", items[0].id, items[0].attachments[0].id);
  assert.deepEqual(new Uint8Array(Buffer.from(file.data, "base64")), pdf);
  step("clienti, cartelle, password, codice OTP e allegato decifrati");
  const saved = await call("serialize");
  await call("lock");
  await assert.rejects(call("containers"), (e) => e.code === "security");
  await call("restore", saved);
  assert.equal((await call("items", c.id))[0].data.username, "admin");
  step("blocco e ripresa della sessione (per lo sblocco con l'impronta)");
  // Nuovo accesso dallo stesso telefono: dispositivo attendibile, niente codice.
  await call("setToken", null);
  const l2 = await call("login", "marco@azienda.it", "password di marco", trust.deviceToken);
  assert.equal(l2.state, "active");
  step("dispositivo attendibile: nessun codice MFA al nuovo accesso");
  await assert.rejects(call("metodoInesistente"), /Metodo sconosciuto/);
  await assert.rejects(call("unlock", "password sbagliata"), (e) => e.code === "security");
  assert.ok(fetches > 10, "tutte le richieste passano dall'app");

  // ---------------------------------------------------------------- offline
  await call("unlock", "password di marco");
  const sync = await call("syncAll");
  assert.ok(sync.items >= 1);
  assert.ok([...offlineCache.keys()].every((k) => !k.includes("/auth/")), "mai dati di autenticazione nell'archivio");
  step("sincronizzazione completa per l'offline (solo letture, dati cifrati)");
  const sessionForBio = await call("serialize");
  network = false;
  await call("lock");
  await call("setToken", null);
  await assert.rejects(call("login", "marco@azienda.it", "password di marco"), (e) => !e.code && /Rete/.test(e.message));
  const off = await call("unlock", "password di marco");
  assert.equal(off.me.email, "marco@azienda.it");
  const offC = (await call("containers")).find((x) => x.meta.name === "Cliente Mobile");
  const offItems = await call("items", offC.id);
  assert.equal(offItems[0].data.password, "r0uter!");
  assert.match((await call("totp", await call("effectiveTotp", offItems[0].id))).code, /^\d{6}$/);
  const offFile = await call("downloadAttachment", offItems[0].id, offItems[0].attachments[0].id);
  assert.deepEqual(new Uint8Array(Buffer.from(offFile.data, "base64")), pdf);
  await assert.rejects(call("unlock", "password sbagliata"), (e) => e.code === "security");
  step("senza rete: sblocco con la master password, password, OTP e allegato dai dati salvati");
  await call("lock");
  await call("restore", sessionForBio);
  assert.equal((await call("items", offC.id))[0].data.username, "admin");
  step("senza rete: ripresa della sessione (sblocco con l'impronta)");
  network = true;
  step("solo i metodi previsti; master password errata respinta; rete solo tramite l'app");
  console.log("\nTest del motore Android superato.");
} catch (e) {
  console.error("✗", e);
  process.exitCode = 1;
} finally {
  await server.close();
  await db.end();
  setTimeout(() => process.exit(process.exitCode ?? 0), 100);
}

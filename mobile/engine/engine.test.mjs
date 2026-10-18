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
async function login(url, email, password) {
  return sdk.login(new sdk.Api({ baseUrl: url }), email, password);
}

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

  // ---------------------------------------------------------------- modifiche dal telefono
  await call("unlock", "password di marco");
  const fid = await call("createFolder", c.id, "Rete", null);
  const pw = await call("generatePassword", 24, true);
  assert.equal(pw.length, 24);
  const nid = await call("createItem", c.id, { type: "login", name: "Switch", username: "admin", password: pw, urls: ["https://switch.mobile.it"],
    fields: [{ label: "TimeOtp-Secret-Base32", value: "VECCHIOSEGRETOIMPORTATO", secret: true }] }, fid);
  let mine = (await call("items", c.id)).find((i) => i.id === nid);
  assert.equal(mine.folderId, fid);
  // Aggancio dell'OTP a una password esistente: chiave Base32 (con spazi, come la mostrano i servizi).
  const parsed = await call("parseTotp", "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "Switch");
  assert.match(parsed.uri, /^otpauth:\/\/totp\/Switch\?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ$/);
  assert.match(parsed.code, /^\d{6}$/);
  await call("updateItem", nid, { ...mine.data, totpUri: parsed.uri });
  mine = (await call("items", c.id)).find((i) => i.id === nid);
  assert.equal(mine.data.totpUri, parsed.uri);
  assert.ok(!(mine.data.fields ?? []).some((f) => f.label.startsWith("TimeOtp")), "i vecchi campi OTP importati vengono tolti");
  assert.equal((await call("totp", await call("effectiveTotp", nid))).code, parsed.code);
  // Link otpauth (da QR code) con parametri.
  const fromQr = await call("parseTotp", "otpauth://totp/Fortinet:admin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&algorithm=SHA256", "x");
  assert.match(fromQr.code, /^\d{8}$/);
  await assert.rejects(call("parseTotp", "non è una chiave", "x"), /Chiave non valida/);
  await call("updateItem", nid, { ...mine.data, password: "nuova!" }, null);
  mine = (await call("items", c.id)).find((i) => i.id === nid);
  assert.equal(mine.data.password, "nuova!");
  assert.equal(mine.folderId, null);
  await call("deleteItem", nid);
  assert.ok(!(await call("items", c.id)).some((i) => i.id === nid));
  step("modifiche dal telefono: cartella, nuova password, OTP agganciato (chiave o QR), modifica, eliminazione");

  // Autofill: dominio esatto, app associata, ricerca libera.
  const web = await call("lookup", "https://router.mobile.it/login");
  assert.equal(web.length, 1);
  assert.equal(web[0].item.data.username, "admin");
  assert.equal((await call("lookup", "https://router.mobile.it.evil.com/")).length, 0, "nessun dominio simile");
  assert.equal((await call("lookupApp", "com.fortinet.forticlient")).length, 0);
  const router = web[0].item;
  await call("updateItem", router.id, { ...router.data, urls: [...router.data.urls, "androidapp://com.fortinet.forticlient"] });
  const app = await call("lookupApp", "com.fortinet.forticlient");
  assert.equal(app.length, 1);
  assert.equal(app[0].canWrite, true);
  assert.ok((await call("allItems")).some((r) => r.item.data.name === "Router"));
  step("autofill: credenziali per dominio esatto (niente domini simili), per app associata, ricerca libera");

  // Cestino e cronologia.
  const tid = await call("createItem", c.id, { type: "login", name: "Temporanea", password: "v1" }, null);
  let tmp = (await call("items", c.id)).find((i) => i.id === tid);
  await call("updateItem", tid, { ...tmp.data, password: "v2" });
  await call("items", c.id);
  const versions = await call("itemVersions", tid);
  assert.equal(versions[0].data.password, "v1");
  await call("restoreVersion", tid, versions[0].revision);
  assert.equal((await call("items", c.id)).find((i) => i.id === tid).data.password, "v1");
  await call("deleteItem", tid);
  assert.ok((await call("items", c.id, true)).some((i) => i.id === tid), "nel cestino");
  await call("restoreItem", tid);
  assert.ok((await call("items", c.id)).some((i) => i.id === tid), "ripristinata");
  // Allegato caricato dal telefono.
  const up = new Uint8Array(50_000).map((_, i) => (i * 11) % 256);
  await call("addAttachment", tid, Buffer.from(up).toString("base64"), "foto.jpg", "image/jpeg");
  tmp = (await call("items", c.id)).find((i) => i.id === tid);
  const back = await call("downloadAttachment", tid, tmp.attachments[0].id);
  assert.deepEqual(new Uint8Array(Buffer.from(back.data, "base64")), up);
  await call("deleteAttachment", tmp.attachments[0].id);
  assert.equal((await call("items", c.id)).find((i) => i.id === tid).attachments.length, 0);
  step("dal telefono: cestino e ripristino, cronologia e ritorno a una versione, allegato caricato e tolto");

  // Condivisioni con un collega certificato.
  const inv = await v.invite("laura@azienda.it", "Laura", "user");
  const la = new sdk.Api({ baseUrl: serverUrl });
  const reg = await sdk.register(la, { token: inv.inviteToken, password: "password di laura", kdf: FAST });
  const lmfa = await sdk.setupMfa(la);
  await sdk.enableMfa(la, totp(lmfa.secret));
  const laura = await sdk.Vault.unlock(la, "password di laura");
  await v.certifyUser(reg.userId, laura.myFingerprint);
  const dir = await call("directory");
  assert.ok(dir.find((u) => u.id === reg.userId).verified);
  await call("share", c.id, reg.userId, "read");
  assert.ok((await call("members", c.id)).some((m) => m.userId === reg.userId && m.permission === "read"));
  assert.ok((await laura.containers()).some((x) => x.id === c.id));
  await call("revoke", c.id, reg.userId);
  assert.ok(!(await laura.containers()).some((x) => x.id === c.id));
  await call("items", c.id);
  await call("shareItem", tid, reg.userId);
  assert.ok((await laura.sharedWithMe()).some((i) => i.id === tid));
  assert.equal((await call("itemShares", tid)).length, 1);
  await call("unshareItem", tid, reg.userId);
  assert.ok(!(await laura.sharedWithMe()).some((i) => i.id === tid));
  step("condivisioni dal telefono: cliente con un collega e revoca, singola password e revoca con ricifratura");

  // Account e salute delle password (l'invito prima: il cambio di password chiude le altre sessioni).
  globalThis.__newInvite = await v.invite("paolo@azienda.it", "Paolo", "user");
  const h = await call("health");
  assert.ok(h.checked >= 1 && Array.isArray(h.reused));
  assert.equal((await call("mfaStatus")).backupCodesRemaining, 10);
  await resetCounter();
  const codes = await call("regenerateBackupCodes", totp(mfa.secret));
  assert.equal(codes.length, 10);
  await call("changePassword", "password di marco", "nuova password di marco", codes[0]);
  await assert.rejects(login(serverUrl, "marco@azienda.it", "password di marco"), /invalid_credentials|credenziali/i);
  step("account dal telefono: salute delle password, nuovi codici di riserva, cambio della master password");


  // ---------------------------------------------------------------- offline
  await call("unlock", "nuova password di marco");
  const sync = await call("syncAll");
  assert.ok(sync.items >= 1);
  assert.ok([...offlineCache.keys()].every((k) => !k.includes("/auth/")), "mai dati di autenticazione nell'archivio");
  step("sincronizzazione completa per l'offline (solo letture, dati cifrati)");
  const sessionForBio = await call("serialize");
  network = false;
  await call("lock");
  await call("setToken", null);
  await assert.rejects(call("login", "marco@azienda.it", "nuova password di marco"), (e) => !e.code && /Rete/.test(e.message));
  const off = await call("unlock", "nuova password di marco");
  assert.equal(off.me.email, "marco@azienda.it");
  const offC = (await call("containers")).find((x) => x.meta.name === "Cliente Mobile");
  const offRouter = (await call("items", offC.id)).find((i) => i.data.name === "Router");
  assert.equal(offRouter.data.password, "r0uter!");
  assert.match((await call("totp", await call("effectiveTotp", offRouter.id))).code, /^\d{6}$/);
  const offFile = await call("downloadAttachment", offRouter.id, offRouter.attachments[0].id);
  assert.deepEqual(new Uint8Array(Buffer.from(offFile.data, "base64")), pdf);
  await assert.rejects(call("unlock", "password sbagliata"), (e) => e.code === "security");
  await assert.rejects(call("createItem", offC.id, { type: "note", name: "offline" }, null), /Rete/);
  step("senza rete: sblocco con la master password, password, OTP e allegato dai dati salvati; modifiche rifiutate");
  await call("lock");
  await call("restore", sessionForBio);
  assert.equal((await call("items", offC.id)).find((i) => i.data.name === "Router").data.username, "admin");
  step("senza rete: ripresa della sessione (sblocco con l'impronta)");
  network = true;
  // Registrazione da invito direttamente dal telefono.
  await call("lock");
  await call("setToken", null);
  const r2 = await call("register", globalThis.__newInvite.inviteToken, "password di paolo");
  assert.equal(r2.state, "mfa_setup");
  const ps = await call("setupMfa");
  const pcodes = await call("enableMfa", totp(ps.secret));
  assert.equal(pcodes.length, 10);
  const pu = await call("unlock", "password di paolo");
  assert.equal(pu.me.email, "paolo@azienda.it");
  step("primo accesso da invito sul telefono: registrazione, MFA, sblocco");
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

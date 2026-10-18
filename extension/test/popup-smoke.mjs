/**
 * Test del popup: renderizzato in jsdom con le API chrome simulate, contro un
 * server reale. Verifica proposta di aggiornamento, salvataggio e compilazione.
 */
import { JSDOM } from "jsdom";
import { randomBytes, createHmac } from "node:crypto";
import { createRequire } from "node:module";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { build } from "esbuild";

process.env.NODE_ENV = "test";
const require = createRequire(import.meta.url);
const { createPool, migrate } = await import("../../app/dist/src/core.js");
const { buildApp, APP_ROOT } = await import("../../app/dist/src/server.js");
const sdk = await import("../../packages/client/dist/src/index.js");

for (const [entry, out] of [["src/popup.tsx", "popup.cjs"], ["src/inline-menu.tsx", "inline-menu.cjs"]]) {
  await build({ entryPoints: [entry], outfile: `test-build/${out}`, bundle: true, platform: "node", format: "cjs",
    target: "node22", jsx: "automatic", jsxImportSource: "preact", logLevel: "warning" });
}

const db = createPool(process.env.TEST_DATABASE_URL ?? "postgres://sc:sc@127.0.0.1/sc");
await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
await migrate(db, join(APP_ROOT, "migrations"));
const bootstrapToken = randomBytes(24).toString("base64url");
const server = await buildApp({ databaseUrl: "", serverSecret: randomBytes(32), bootstrapToken, publicUrl: "http://127.0.0.1",
  attachmentsDir: mkdtempSync(join(tmpdir(), "sc-pop-")), port: 0, maxAttachmentBytes: 5e6, sessionHours: 12, authPerIpPerMinute: 10000 }, db);
await server.listen({ host: "127.0.0.1", port: 0 });
const serverUrl = `http://127.0.0.1:${server.server.address().port}`;

const totp = (secret) => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, val = 0; const out = [];
  for (const c of secret) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", Buffer.from(out)).update(m).digest(); const o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, "0");
};
const api = new sdk.Api({ baseUrl: serverUrl });
await sdk.register(api, { token: bootstrapToken, email: "marco@azienda.it", displayName: "Marco", password: "password di marco", kdf: { opsLimit: 2, memLimitBytes: 19 * 1024 * 1024 } });
const s = await sdk.setupMfa(api);
await sdk.enableMfa(api, totp(s.secret));
const vault = await sdk.Vault.unlock(api, "password di marco");
await vault.initOrg();
const personal = await vault.ensurePersonal();
const client = await vault.createContainer({ name: "Cliente Portale" });
await vault.createItem(client, { type: "login", name: "Portale cliente", username: "mario", password: "vecchia", urls: ["https://portale.cliente.it"] });
const OTP_URI = "otpauth://totp/Portale?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
await vault.createItem(client, { type: "login", name: "Portale con OTP", username: "otpuser", password: "pw-otp", urls: ["https://portale.cliente.it"], totpUri: OTP_URI });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, what, ms = 20000) {
  const t0 = Date.now();
  for (;;) { const r = fn(); if (r) return r; if (Date.now() - t0 > ms) throw new Error(`Timeout: ${what}`); await sleep(50); }
}

/** Apre il popup con una scheda su portale.cliente.it ed eventuale accesso in attesa. */
async function openPopup(pendingSave, page = "popup", hash = "") {
  const dom = new JSDOM(`<!doctype html><body class="popup"><div id="root"></div></body>`, { url: `chrome-extension://testid/${page}.html${hash}`, pretendToBeVisual: true });
  const w = dom.window;
  for (const k of ["window", "document", "location", "history", "HTMLElement", "HTMLInputElement", "Node", "Event", "MouseEvent", "KeyboardEvent", "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame"]) {
    Object.defineProperty(globalThis, k, { value: w[k], configurable: true, writable: true });
  }
  Object.defineProperty(globalThis, "navigator", { value: w.navigator, configurable: true });
  Object.defineProperty(w.navigator, "clipboard", { value: { writeText: async () => undefined } });
  const area = (data) => ({
    data,
    get: async (k) => (typeof k === "string" ? (k in data ? { [k]: structuredClone(data[k]) } : {}) : { ...data }),
    set: async (o) => { Object.assign(data, structuredClone(o)); },
    remove: async (k) => { delete data[k]; },
    clear: async () => { for (const k of Object.keys(data)) delete data[k]; },
  });
  const injected = [];
  const session = { s: { token: api.token, vault: vault.serialize(), lastActivity: Date.now() } };
  if (pendingSave) session.pendingSave = pendingSave;
  const tab = { id: 7, windowId: 1, url: "https://portale.cliente.it/login" };
  globalThis.chrome = w.chrome = {
    storage: { local: area({ settings: { serverUrl, pinnedOrgSignPublic: vault.me.org.signPublic, autoLockMinutes: 15, clipboardSeconds: 30 } }), session: area(session) },
    runtime: { id: "testid", sendMessage: async () => undefined, getURL: (p) => `chrome-extension://testid/${p}` },
    tabs: { query: async () => [tab], get: async () => tab, getCurrent: async () => tab, create: async () => undefined },
    action: { setBadgeText: async () => undefined },
    scripting: { executeScript: async (o) => { injected.push(o); return [{ result: true }]; } },
  };
  w.close = () => undefined;
  const closed = [];
  Object.defineProperty(w, "parent", { value: { postMessage: (m) => closed.push(m) }, configurable: true });
  delete require.cache[require.resolve(`../test-build/${page}.cjs`)];
  require(`../test-build/${page}.cjs`);
  const text = () => w.document.body.textContent;
  const click = async (label) => {
    await sleep(40);
    const b = [...w.document.querySelectorAll("button")].find((x) => x.textContent.trim() === label && !x.disabled);
    assert.ok(b, `pulsante «${label}»`);
    b.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  };
  return { w, text, click, injected, closed, session: chrome.storage.session.data };
}

const pending = (username, password) => ({ tabId: 7, host: "portale.cliente.it", username, password, at: Date.now() });

// 1. Stesso utente, password diversa: proposta di aggiornamento.
{
  const p = await openPopup(pending("mario", "nuova-password"));
  await waitFor(() => p.text().includes("Aggiornare la password?"), "proposta di aggiornamento");
  await p.click("Aggiorna");
  await waitFor(() => p.text().includes("Password aggiornata"), "conferma aggiornamento");
  const [it] = await vault.items(client);
  assert.equal(it.data.password, "nuova-password");
  assert.equal(p.session.pendingSave, undefined, "accesso in attesa cancellato");
  console.log("✓ popup: aggiornamento della password di un accesso già salvato");
}
// 2. Utente nuovo: proposta di salvataggio nell'Area personale.
{
  const p = await openPopup(pending("luigi", "password-di-luigi"));
  await waitFor(() => p.text().includes("Salvare questo accesso?"), "proposta di salvataggio");
  await p.click("Salva");
  await waitFor(() => p.text().includes("Accesso salvato"), "conferma salvataggio");
  const saved = (await vault.items(personal)).find((i) => i.data.username === "luigi");
  assert.equal(saved.data.password, "password-di-luigi");
  assert.deepEqual(saved.data.urls, ["https://portale.cliente.it"]);
  console.log("✓ popup: salvataggio di un nuovo accesso");
}
// 3. Accesso già salvato identico: nessuna proposta. Compilazione con i dati giusti.
{
  const p = await openPopup(pending("mario", "nuova-password"));
  await waitFor(() => p.text().includes("Portale cliente"), "corrispondenza del sito");
  await sleep(300);
  assert.ok(!p.text().includes("Aggiornare") && !p.text().includes("Salvare questo"), "nessuna proposta per un accesso identico");
  await p.click("Compila");
  await waitFor(() => p.injected.length === 1, "compilazione");
  assert.deepEqual(JSON.parse(JSON.stringify(p.injected[0].args)), ["portale.cliente.it", "mario", "nuova-password", ""]);
  assert.deepEqual(JSON.parse(JSON.stringify(p.injected[0].target)), { tabId: 7, frameIds: [0] });
  console.log("✓ popup: nessuna proposta per un accesso identico; compilazione solo nel frame principale");
}
// 4. Menu sotto il campo di accesso: compila utente, password e OTP.
{
  const p = await openPopup(null, "inline-menu", "#field=login");
  await waitFor(() => p.text().includes("Portale con OTP"), "credenziali nel menu");
  const btn = [...p.w.document.querySelectorAll("button.im-item")].find((b) => b.textContent.includes("Portale con OTP"));
  btn.dispatchEvent(new p.w.MouseEvent("click", { bubbles: true }));
  await waitFor(() => p.injected.length === 1, "compilazione dal menu");
  const [h, u, pw, otp] = JSON.parse(JSON.stringify(p.injected[0].args));
  assert.deepEqual([h, u, pw], ["portale.cliente.it", "otpuser", "pw-otp"]);
  assert.equal(otp, (await sdk.Vault.totp(OTP_URI)).code);
  await waitFor(() => p.closed.some((m) => m.type === "sc-inline-close"), "menu chiuso dopo la compilazione");
  console.log("✓ menu sotto il campo: compila utente, password e codice OTP");
}
// 5. Menu sul campo OTP: solo gli elementi con OTP, compila solo il codice.
{
  const p = await openPopup(null, "inline-menu", "#field=otp");
  await waitFor(() => p.text().includes("Portale con OTP"), "codice OTP nel menu");
  assert.ok(!p.text().includes("Portale cliente"), "solo elementi con OTP");
  p.w.document.querySelector("button.im-item").dispatchEvent(new p.w.MouseEvent("click", { bubbles: true }));
  await waitFor(() => p.injected.length === 1, "compilazione del codice");
  const [h, u, pw, otp] = JSON.parse(JSON.stringify(p.injected[0].args));
  assert.deepEqual([h, u, pw], ["portale.cliente.it", "", ""]);
  assert.match(otp, /^\d{6}$/);
  console.log("✓ menu sul campo OTP: solo gli elementi con OTP, compila il codice corrente");
}
await server.close();
await db.end();
console.log("\nTest del popup superato.");
setTimeout(() => process.exit(0), 100);

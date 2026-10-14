/**
 * Test di fumo dell'interfaccia: l'app dell'estensione gira in jsdom con le
 * API chrome simulate e parla con un server StartCredentials reale.
 * Uso: node test/ui-smoke.mjs (richiede PostgreSQL di test).
 */
import { JSDOM } from "jsdom";
import { randomBytes, createHmac } from "node:crypto";
import { createRequire } from "node:module";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const require = createRequire(import.meta.url);
const { createPool, migrate } = await import("../../app/dist/src/core.js");
const { buildApp, APP_ROOT } = await import("../../app/dist/src/server.js");

// ---------------------------------------------------------------- server reale
const db = createPool(process.env.TEST_DATABASE_URL ?? "postgres://sc:sc@127.0.0.1/sc");
await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
await migrate(db, join(APP_ROOT, "migrations"));
const bootstrapToken = randomBytes(24).toString("base64url");
const server = await buildApp({
  databaseUrl: "", serverSecret: randomBytes(32), bootstrapToken, publicUrl: "http://127.0.0.1",
  attachmentsDir: mkdtempSync(join(tmpdir(), "sc-ui-")), port: 0, maxAttachmentBytes: 5e6, sessionHours: 12, authPerIpPerMinute: 10000,
}, db);
await server.listen({ host: "127.0.0.1", port: 0 });
const serverUrl = `http://127.0.0.1:${server.server.address().port}`;

// ---------------------------------------------------------------- browser simulato
const dom = new JSDOM(`<!doctype html><html><body class="app"><div id="root"></div></body></html>`, {
  url: "chrome-extension://testid/app.html", pretendToBeVisual: true,
});
const w = dom.window;
for (const k of ["window", "document", "location", "history", "HTMLElement", "HTMLInputElement", "Node", "Event", "KeyboardEvent", "MouseEvent", "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame"]) {
  Object.defineProperty(globalThis, k, { value: w[k], configurable: true, writable: true });
}
Object.defineProperty(globalThis, "navigator", { value: w.navigator, configurable: true });
let clipboard = "";
Object.defineProperty(w.navigator, "clipboard", { value: { writeText: async (t) => { clipboard = t; } } });
w.URL.createObjectURL = () => "blob:x";
w.URL.revokeObjectURL = () => undefined;

const area = () => {
  const data = {};
  return {
    data,
    get: async (k) => (typeof k === "string" ? (k in data ? { [k]: structuredClone(data[k]) } : {}) : { ...data }),
    set: async (o) => { for (const [k, v] of Object.entries(o)) data[k] = structuredClone(v); },
    clear: async () => { for (const k of Object.keys(data)) delete data[k]; },
  };
};
const messages = [];
globalThis.chrome = w.chrome = {
  storage: { local: area(), session: area() },
  permissions: { contains: async () => true, request: async () => true },
  runtime: { id: "testid", sendMessage: async (m) => { messages.push(m); }, getURL: (p) => `chrome-extension://testid/${p}` },
  tabs: { create: async () => undefined, query: async () => [] },
};

// ---------------------------------------------------------------- utilità
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const text = () => w.document.body.textContent;
async function waitFor(fn, what, ms = 30000) {
  const t0 = Date.now();
  for (;;) {
    const r = fn();
    if (r) return r;
    if (Date.now() - t0 > ms) {
      throw new Error(`Timeout in attesa di: ${what}\n--- pagina ---\n${text().slice(0, 1500)}`);
    }
    await sleep(50);
  }
}
const waitText = (s, ms) => waitFor(() => text().includes(s), `testo «${s}»`, ms);
const byLabel = (label) => {
  for (const l of w.document.querySelectorAll("label")) {
    if (l.textContent.trim().startsWith(label)) {
      const el = l.querySelector("input,select,textarea");
      if (el) return el;
    }
  }
  return w.document.querySelector(`[aria-label="${label}"]`);
};
function type(label, value) {
  const el = typeof label === "string" ? byLabel(label) : label;
  assert.ok(el, `campo «${label}» non trovato`);
  const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value").set;
  setter.call(el, value);
  el.dispatchEvent(new w.Event(el.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
}
function button(label) {
  const dialogs = w.document.querySelectorAll(".dialog");
  const scope = dialogs.length ? dialogs[dialogs.length - 1] : w.document;
  const b = [...scope.querySelectorAll("button, a")].find((x) => (x.textContent.trim() === label || x.getAttribute("aria-label") === label) && !x.disabled);
  assert.ok(b, `pulsante «${label}» non trovato`);
  return b;
}
const click = async (label) => { await sleep(40); button(label).dispatchEvent(new w.MouseEvent("click", { bubbles: true })); };
const totp = (secret) => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0; const out = [];
  for (const c of secret.replace(/\s/g, "")) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = createHmac("sha1", Buffer.from(out)).update(msg).digest();
  const o = mac[19] & 15;
  return String((((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]) % 1e6).padStart(6, "0");
};
// jsdom non emette hashchange quando l'hash viene cambiato da fuori: lo facciamo noi.
const nav = async (h) => { w.location.hash = h; await sleep(20); w.dispatchEvent(new w.HashChangeEvent("hashchange")); };
const step = (s) => console.log(`✓ ${s}`);

// ---------------------------------------------------------------- scenario
const errors = [];
w.addEventListener("error", (e) => errors.push(e.error ?? e.message));
process.on("unhandledRejection", (e) => errors.push(e));

try {
  require("../test-build/app.cjs");

  await waitText("Collega il server");
  type("Collegamento di invito o indirizzo", serverUrl);
  await click("Continua");
  await waitText("Crea l'amministratore");
  step("configurazione server e riconoscimento del primo avvio");

  type("Codice di attivazione", bootstrapToken);
  type("Nome e cognome", "Marco Ferri");
  type("Email", "marco@azienda.it");
  type("Master password", "una frase lunga per la cassaforte");
  type("Ripeti la master password", "una frase lunga per la cassaforte");
  await click("Crea account");
  await waitText("Proteggi l'accesso", 60000);
  step("registrazione amministratore (Argon2id 256 MiB)");

  const secret = await waitFor(() => [...w.document.querySelectorAll(".mono")].map((e) => e.textContent).find((t) => /^[A-Z2-7 ]{20,}$/.test(t)), "chiave MFA");
  type("Codice a 6 cifre", totp(secret));
  await click("Attiva");
  await waitText("inizializza l'organizzazione", 60000);
  step("MFA attivata e cassaforte sbloccata");

  await nav("#/admin/org");
  await waitText("Inizializza l'organizzazione");
  await click("Inizializza l'organizzazione");
  await waitText("Stampa le quote di recupero");
  const shares = [...w.document.querySelectorAll(".share-box")].map((e) => e.textContent);
  assert.equal(shares.length, 3);
  await click("Ho stampato e consegnato le quote");
  await waitText("Organizzazione attiva");
  step("organizzazione inizializzata, 3 quote di recupero");

  await nav("#/clienti");
  await waitText("Non hai ancora clienti");
  await click("Nuovo cliente");
  type("Nome del cliente", "Studio Legale Moretti");
  type("Settore e città", "Studio legale · Roma");
  await click("Crea cliente");
  await waitText("Nessun elemento");
  step("cliente creato e aperto");

  await click("Nuova cartella");
  type("Nome", "Cloud e posta");
  await click("Crea cartella");
  await waitText("Cloud e posta");
  await click("Nuovo elemento");
  type("Nome", "Microsoft 365 – amministratore");
  type("Nome utente", "admin@studiomoretti.it");
  type("Password", "xk7-Qw!2mRv9#LpZ");
  type("Indirizzi web", "https://admin.microsoft.com");
  type("OTP: URI otpauth:// o chiave segreta", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  type("Cartella", byLabel("Cartella").options[1].value);
  await click("Salva");
  await waitText("Salvato");
  await waitFor(() => w.document.querySelector(".otp-code"), "codice OTP");
  assert.match(w.document.querySelector(".otp-code").textContent, /^\d{3} \d{3}$/);
  step("elemento con password, URL e OTP salvato; codice OTP visibile");

  const copyBtn = [...w.document.querySelectorAll(".detail button")].find((b) => b.textContent === "Copia" && b.closest(".input-group")?.querySelector('input[type="password"]'));
  await sleep(40); copyBtn.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  await waitFor(() => clipboard === "xk7-Qw!2mRv9#LpZ", "copia della password");
  await waitFor(() => messages.some((m) => m.type === "clear-clipboard"), "svuotamento appunti programmato");
  step("copia negli appunti con svuotamento programmato");

  await click("Modifica");
  type("Password", "nuova-password-2026");
  await click("Salva");
  await waitText("revisione 2");
  await click("Cronologia");
  await waitText("Revisione 1");
  await click("Chiudi");
  step("modifica e cronologia");

  await nav("#/admin/utenti");
  await waitText("Invita utente");
  await click("Invita utente");
  type("Nome e cognome", "Laura Bassi");
  type("Email", "laura@azienda.it");
  await click("Crea invito");
  await waitText("Collegamento di invito");
  const invite = w.document.querySelector(".dialog input.mono").value;
  assert.match(invite, /#invite=/);
  await click("Fatto");
  await waitText("Invitato");
  step("invito utente con collegamento");

  // Laura attiva l'invito con l'SDK (come farebbe dalla sua estensione).
  const sdk = await import("../../packages/client/dist/src/index.js");
  const la = new sdk.Api({ baseUrl: serverUrl });
  const reg = await sdk.register(la, { token: invite.split("#invite=")[1], password: "laura master password", kdf: { opsLimit: 2, memLimitBytes: 19 * 1024 * 1024 } });
  const setup = await sdk.setupMfa(la);
  await sdk.enableMfa(la, totp(setup.secret));
  const laura = await sdk.Vault.unlock(la, "laura master password");
  await nav("#/admin/utenti");
  await waitText("Da verificare");
  await click("Certifica");
  type("Impronta comunicata dall'utente", "0000 0000 0000 0000 0000 0000 0000 0000");
  await click("Certifica");
  await waitText("L'impronta non corrisponde");
  type("Impronta comunicata dall'utente", laura.myFingerprint.toLowerCase());
  await click("Certifica");
  await waitText("Certificata");
  step("certificazione: impronta errata respinta, impronta corretta accettata");

  await nav("#/clienti");
  await waitText("Studio Legale Moretti");
  [...w.document.querySelectorAll(".client")][0].dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  await waitText("Condividi");
  await click("Condividi");
  await waitFor(() => [...(byLabel("Aggiungi un collega")?.options ?? [])].some((o) => o.value === reg.userId), "Laura nella rubrica");
  type("Aggiungi un collega", reg.userId);
  type("Permesso", "write");
  await waitText("Impronta della chiave di Laura Bassi");
  [...w.document.querySelectorAll(".dialog button")].find((b) => b.textContent === "Condividi").dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  await waitText("Accesso concesso");
  const lauraClients = await laura.containers();
  assert.ok(lauraClients.some((c) => c.meta.name === "Studio Legale Moretti" && c.permission === "write"));
  step("condivisione dal dialogo: Laura vede il cliente con permesso di modifica");

  await click("Rimuovi");
  await click("Rimuovi e ruota la chiave");
  await waitText("Accesso rimosso e chiave ruotata");
  assert.ok(!(await laura.containers()).some((c) => c.meta.name === "Studio Legale Moretti"));
  await click("Chiudi");
  step("revoca con rotazione della chiave dal dialogo");

  await nav("#/import");
  await waitText("Il file viene letto e cifrato solo su questo computer");
  step("pagina di import");

  await nav("#/admin/audit");
  await waitText("Registro attività");
  await click("Verifica integrità");
  await waitText("Catena integra");
  await waitText("Elemento modificato");
  step("registro attività e verifica della catena");

  await nav("#/impostazioni");
  await waitFor(() => /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/.test(w.document.querySelector(".share-box")?.textContent ?? ""), "impronta della chiave");
  step("impronta della chiave in impostazioni");

  await nav("#/generatore");
  await waitText("Generatore di password");
  assert.equal(byLabel("Password generata").value.length, 24);
  step("generatore");

  // Il blocco cancella le chiavi dalla sessione.
  const { lock } = await Promise.resolve({ lock: async () => { const s = chrome.storage.session.data.s; await chrome.storage.session.set({ s: { ...s, vault: undefined } }); } });
  await lock();
  assert.equal(chrome.storage.session.data.s.vault, undefined);
  assert.ok(!JSON.stringify(chrome.storage.local.data).includes("xk7"), "nessun segreto nello storage locale");
  step("nessun segreto nello storage persistente");

  if (errors.length) throw errors[0];
  console.log("\nTest di fumo dell'interfaccia superato.");
} catch (e) {
  console.error("\n✗", e);
  for (const x of errors) console.error("errore pagina:", x);
  process.exitCode = 1;
} finally {
  await server.close();
  await db.end();
  w.close();
  setTimeout(() => process.exit(process.exitCode ?? 0), 100);
}

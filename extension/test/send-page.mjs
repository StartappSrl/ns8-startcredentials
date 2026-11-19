/** Pagina pubblica dell'invio sicuro, in jsdom contro il server reale. */
import { JSDOM } from "jsdom";
import { randomBytes, createHmac } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const { createPool, migrate } = await import("../../app/dist/src/core.js");
const { buildApp, APP_ROOT } = await import("../../app/dist/src/server.js");
const sdk = await import("../../packages/client/dist/src/index.js");

const db = createPool(process.env.TEST_DATABASE_URL ?? "postgres://sc:sc@127.0.0.1/sc");
await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
await migrate(db, join(APP_ROOT, "migrations"));
const bootstrapToken = randomBytes(24).toString("base64url");
const server = await buildApp({ databaseUrl: "", serverSecret: randomBytes(32), bootstrapToken, publicUrl: "http://127.0.0.1",
  attachmentsDir: mkdtempSync(join(tmpdir(), "sc-send-")), port: 0, maxAttachmentBytes: 5e6, sessionHours: 12,
  authPerIpPerMinute: 10000, authPerKeyPerMinute: 10000, apiPerMinute: 100000, anonPerIpPerMinute: 100000, ipCeilingPerMinute: 100000 }, db,
  { mailer: { enabled: true, send: async () => true } });
await server.listen({ host: "127.0.0.1", port: 0 });
const serverUrl = `http://127.0.0.1:${server.server.address().port}`;
const b32 = (s) => { const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, v = 0; const o = []; for (const c of s) { v = (v << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(o); };
const totp = (secret) => { const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000))); const h = createHmac("sha1", b32(secret)).update(m).digest(); const f = h[19] & 15; return String((((h[f] & 127) << 24) | (h[f + 1] << 16) | (h[f + 2] << 8) | h[f + 3]) % 1e6).padStart(6, "0"); };

const api = new sdk.Api({ baseUrl: serverUrl });
await sdk.register(api, { token: bootstrapToken, email: "marco@azienda.it", displayName: "Marco Ferri", password: "password di marco", kdf: { opsLimit: 2, memLimitBytes: 19 * 1024 * 1024 } });
const m = await sdk.setupMfa(api);
await sdk.enableMfa(api, totp(m.secret));
const vault = await sdk.Vault.unlock(api, "password di marco");
await vault.initOrg();
const cid = await vault.createContainer({ name: "Cliente" });
const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
await vault.createItem(cid, { type: "login", name: "Portale cliente", username: "admin", password: "Segreta-42", urls: ["https://portale.cliente.it", "javascript:alert(1)"], totpUri: `otpauth://totp/P?secret=${SECRET}` });
const item = (await vault.items(cid))[0];
const send = await vault.createSecureSend(item, { recipientEmail: "ref@cliente.it", expiresInHours: 1, fields: { username: true, password: true, urls: true, otp: true } });
const token = send.link.split("#")[1];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, what, ms = 30000) { const t0 = Date.now(); for (;;) { const r = fn(); if (r) return r; if (Date.now() - t0 > ms) throw new Error(`Timeout: ${what}`); await sleep(50); } }

async function openPage() {
  const html = await (await fetch(`${serverUrl}/s`)).text();
  const js = await (await fetch(`${serverUrl}/send.js`)).text();
  const dom = new JSDOM(html, { url: `${serverUrl}/s#${token}`, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  Object.defineProperty(w, "crypto", { value: globalThis.crypto });
  w.fetch = (u, o) => fetch(new URL(u, serverUrl), o);
  w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
  const copied = [];
  Object.defineProperty(w.navigator, "clipboard", { value: { writeText: async (t) => { copied.push(t); } } });
  w.eval(js);
  return { w, $: (id) => w.document.getElementById(id), copied };
}

try {
  const p = await openPage();
  assert.equal(p.w.location.hash, "", "token tolto dalla barra degli indirizzi");
  p.$("sc-code").value = "AAAA-AAAA-AAAA-AAAA";
  p.$("sc-open").click();
  await waitFor(() => !p.$("sc-error").hidden && /errato/.test(p.$("sc-error").textContent), "codice errato");
  console.log("✓ codice errato respinto nel browser");
  p.$("sc-code").value = send.code.toLowerCase().replace(/-/g, " ");
  p.$("sc-open").click();
  await waitFor(() => !p.$("sc-result").hidden, "contenuto decifrato");
  const text = p.w.document.body.textContent;
  assert.ok(text.includes("Portale cliente") && text.includes("admin") && text.includes("Inviato da Marco Ferri"));
  assert.ok(!text.includes("Segreta-42"), "password nascosta finché non si preme Mostra");
  const pw = [...p.w.document.querySelectorAll(".send-field")].find((f) => f.textContent.startsWith("Password"));
  pw.querySelector("button").click();
  assert.ok(pw.textContent.includes("Segreta-42"));
  const links = [...p.w.document.querySelectorAll("a.send-value")].map((a) => a.getAttribute("href"));
  assert.deepEqual(links, ["https://portale.cliente.it"], "solo collegamenti http/https");
  const otpRow = [...p.w.document.querySelectorAll(".send-field")].find((f) => f.textContent.startsWith("Codice OTP"));
  await waitFor(() => /\d{3} \d{3}/.test(otpRow.textContent), "codice OTP");
  const shown = otpRow.querySelector(".send-value").textContent.slice(0, 7).replace(" ", "");
  const expected = totp(SECRET);
  assert.ok(shown === expected || shown === totp(SECRET), `OTP ${shown} atteso ${expected}`);
  assert.match(p.$("sc-left").textContent, /ultima apertura/);
  console.log("✓ apertura con il codice: password nascosta e mostrabile, OTP corretto, collegamenti non http esclusi");
  p.$("sc-close").click();
  assert.ok(!p.w.document.body.textContent.includes("Segreta-42"), "contenuto cancellato dalla pagina");

  const again = await openPage();
  again.$("sc-code").value = send.code;
  again.$("sc-open").click();
  await waitFor(() => /non è più disponibile/.test(again.$("sc-error").textContent), "seconda apertura respinta");
  console.log("✓ seconda apertura respinta: il messaggio è stato distrutto");
  console.log("\nTest della pagina di invio sicuro superato.");
} catch (e) {
  console.error("✗", e);
  process.exitCode = 1;
} finally {
  await server.close();
  await db.end();
  setTimeout(() => process.exit(process.exitCode ?? 0), 100);
}

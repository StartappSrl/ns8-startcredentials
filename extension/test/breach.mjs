/** Controllo violazioni: dal computer esce solo il prefisso di 5 caratteri dell'impronta SHA-1. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const { pwnedCounts, parseRange, sha1Hex, PWNED_RANGE_URL } = await import("../test-build/breach.mjs");

assert.equal(await sha1Hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");

const leaked = "password";
const safe = "Zq7!mV9#rT2$wLp8&nBx";
const h = (s) => createHash("sha1").update(s).digest("hex").toUpperCase();
const requests = [];
const fakeFetch = async (url, init) => {
  requests.push({ url, init });
  const prefix = url.slice(PWNED_RANGE_URL.length);
  assert.match(prefix, /^[0-9A-F]{5}$/, "solo 5 caratteri esadecimali");
  // Risposta con riempimento (conteggio 0) e, per il prefisso giusto, la password trapelata.
  let body = "0000000000000000000000000000000000A:0\r\n";
  if (prefix === h(leaked).slice(0, 5)) body += `${h(leaked).slice(5)}:9545824\r\n`;
  return { ok: true, status: 200, text: async () => body };
};

const r = await pwnedCounts([leaked, safe, leaked], { fetch: fakeFetch });
assert.equal(r.get(leaked), 9545824);
assert.equal(r.get(safe), 0);
assert.equal(requests.length, 2, "password ripetute interrogate una volta sola");
for (const { url, init } of requests) {
  const sent = url.slice(PWNED_RANGE_URL.length);
  assert.ok(url.startsWith(PWNED_RANGE_URL) && sent.length === 5, "solo il prefisso dopo l'indirizzo del servizio");
  assert.ok(!sent.includes(leaked) && !sent.includes(safe), "la password non esce mai");
  assert.ok(!JSON.stringify(init).includes(leaked) && !JSON.stringify(init).includes(safe), "nemmeno nelle intestazioni");
  assert.equal(init.headers["Add-Padding"], "true");
  assert.equal(init.credentials, "omit");
}
assert.deepEqual([...parseRange("ABC:1\nnot-a-line\n").keys()], [], "righe non valide ignorate");
await assert.rejects(pwnedCounts(["x"], { fetch: async () => ({ ok: false, status: 429, text: async () => "" }) }), /occupato/);
console.log("✓ controllo violazioni: solo il prefisso dell'impronta esce dal computer");

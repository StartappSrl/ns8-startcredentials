/**
 * Verifica gli import con il pacchetto costruito per il browser (stessa
 * configurazione dell'estensione): un file KDBX 4 reale, CSV e 1Password.
 */
import { build } from "esbuild";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { nodeStubs } from "../node-stubs.mjs";
import { zipSync, strToU8 } from "fflate";

const require = createRequire(import.meta.url);

// 1. Pacchetto per browser, con la stessa sostituzione dei moduli Node.
await build({
  entryPoints: ["test/import-entry.ts"], outfile: "test-build/import.mjs", bundle: true,
  format: "esm", platform: "browser", target: "chrome116", plugins: [nodeStubs], logLevel: "warning",
});
const src = readFileSync("test-build/import.mjs", "utf8");
assert.ok(!src.includes("Dynamic require"), "il pacchetto contiene ancora require dinamici");
// Come in una pagina dell'estensione: window con WebCrypto e nessun process.
globalThis.window = globalThis;
const realProcess = globalThis.process;
Object.defineProperty(globalThis, "process", { value: undefined, configurable: true, writable: true });
const lib = await import(`../test-build/import.mjs?${Date.now()}`);

await lib.importCsv("name,password\nx,y\n"); // forza l'inizializzazione
// 2. File KeePass reale (KDBX 4, Argon2d), creato con kdbxweb in Node.
const kdbxweb = require("kdbxweb");
const { argon2d, argon2id } = await import("hash-wasm");
kdbxweb.CryptoEngine.setArgon2Impl(async (pwd, salt, memory, iterations, length, parallelism, type) => {
  const fn = type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
  const out = await fn({ password: new Uint8Array(pwd), salt: new Uint8Array(salt), memorySize: memory, iterations, hashLength: length, parallelism, outputType: "binary" });
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
});
const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString("pass kdbx di prova")), "Clienti");
db.setKdf(kdbxweb.Consts.KdfId.Argon2d);
const root = db.getDefaultGroup();
const g = db.createGroup(root, "Studio Moretti");
const sub = db.createGroup(g, "Server");
const e = db.createEntry(sub);
e.fields.set("Title", "Firewall sede");
e.fields.set("UserName", "admin");
e.fields.set("Password", kdbxweb.ProtectedValue.fromString("Fw!segreta-2026"));
e.fields.set("URL", "https://192.168.10.1");
e.fields.set("otp", "otpauth://totp/FW:admin?secret=GEZDGNBVGY3TQOJQ");
e.fields.set("PIN dispositivo", kdbxweb.ProtectedValue.fromString("4821"));
const n = db.createEntry(root);
n.fields.set("Title", "Nota senza password");
n.fields.set("Notes", "contenuto della nota");
db.createRecycleBin();
const trashed = db.createEntry(root);
trashed.fields.set("Title", "Eliminato");
db.move(trashed, db.getGroup(db.meta.recycleBinUuid));
const file = await db.save();

const kp = await lib.importKeePass(file, "pass kdbx di prova");
assert.equal(kp.items.length, 2, "il cestino non va importato");
const fw = kp.items.find((i) => i.data.name === "Firewall sede");
assert.equal(fw.data.password, "Fw!segreta-2026");
assert.match(fw.data.totpUri, /^otpauth:\/\/totp\//);
assert.deepEqual(fw.data.fields, [{ label: "PIN dispositivo", value: "4821", secret: true }]);
assert.deepEqual(kp.folders.map((f) => f.name), ["Studio Moretti", "Server"]);
assert.equal(kp.folders[1].parentKey, kp.folders[0].key);
assert.equal(kp.items.find((i) => i.data.name === "Nota senza password").data.type, "note");
await assert.rejects(lib.importKeePass(file, "password sbagliata"), /password o file chiave errati/);
console.log("✓ KeePass KDBX 4 (Argon2d): cartelle annidate, OTP, campi riservati, cestino escluso");

async function kdbxWith(creds) {
  const d = kdbxweb.Kdbx.create(creds, "Passbolt");
  d.createEntry(d.getDefaultGroup()).fields.set("Title", "Da Passbolt");
  return d.save();
}
// Export senza password (come Passbolt quando non se ne imposta una): campo vuoto.
const noPw = await kdbxWith(new kdbxweb.Credentials(null));
assert.equal((await lib.importKeePass(noPw, "")).items[0].data.name, "Da Passbolt");
// Export con password vuota: anche questo con il campo vuoto.
const emptyPw = await kdbxWith(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString("")));
assert.equal((await lib.importKeePass(emptyPw, "")).items.length, 1);
// Export protetto da file chiave, senza password.
const keyFile = await kdbxweb.Credentials.createRandomKeyFile(2);
const withKey = await kdbxWith(new kdbxweb.Credentials(null, keyFile));
assert.equal((await lib.importKeePass(withKey, "", keyFile.buffer.slice(keyFile.byteOffset, keyFile.byteOffset + keyFile.byteLength))).items.length, 1);
await assert.rejects(lib.importKeePass(withKey, ""), /protetto: inserisci la password o il file chiave/);
console.log("✓ KeePass senza password, con password vuota e con file chiave");

// Campi OTP nativi di KeePass (export KDBX di Passbolt).
{
  const d = kdbxweb.Kdbx.create(new kdbxweb.Credentials(null), "Passbolt");
  const e1 = d.createEntry(d.getDefaultGroup());
  e1.fields.set("Title", "Portale SHA1");
  e1.fields.set("TimeOtp-Secret-Base32", kdbxweb.ProtectedValue.fromString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
  const e2 = d.createEntry(d.getDefaultGroup());
  e2.fields.set("Title", "Portale SHA256");
  // "12345678901234567890123456789012" in esadecimale, come la variante Hex di KeePass
  e2.fields.set("TimeOtp-Secret-Hex", kdbxweb.ProtectedValue.fromString(Buffer.from("12345678901234567890123456789012").toString("hex")));
  e2.fields.set("TimeOtp-Algorithm", "HMAC-SHA-256");
  e2.fields.set("TimeOtp-Length", "8");
  e2.fields.set("TimeOtp-Period", "30");
  const r = await lib.importKeePass(await d.save(), "");
  const p1 = r.items.find((i) => i.data.name === "Portale SHA1").data;
  const p2 = r.items.find((i) => i.data.name === "Portale SHA256").data;
  assert.ok(p1.totpUri?.startsWith("otpauth://totp/"));
  assert.ok(!(p1.fields ?? []).some((f) => f.label.startsWith("TimeOtp")), "i campi TimeOtp non restano come campi aggiuntivi");
  // Vettori RFC 6238 a t=59 s: SHA-1 (6 cifre) 287082, SHA-256 (8 cifre) 46119246
  assert.equal((await lib.Vault.totp(p1.totpUri, 59_000)).code, "287082");
  assert.equal((await lib.Vault.totp(p2.totpUri, 59_000)).code, "46119246");
  // Elemento importato con la versione precedente: OTP rimasto solo nei campi aggiuntivi.
  const legacy = { type: "login", name: "Vecchio import", fields: [{ label: "TimeOtp-Secret-Base32", value: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", secret: true }] };
  assert.equal((await lib.Vault.totp(lib.effectiveTotpUri(legacy), 59_000)).code, "287082");
  console.log("✓ OTP dai campi KeePass (TimeOtp-*): codici corretti secondo RFC 6238, anche per elementi già importati");
}

// 3. CSV in formato Passbolt (KeePass CSV) e LastPass.
const pb = lib.importCsv('"Group","Title","Username","Password","URL","Notes","TOTP"\n"Clienti/Rossi","PEC","rossi@pec.it","p1","https://pec.it","","GEZDGNBVGY3TQOJQ"\n', "passbolt");
assert.equal(pb.items[0].data.password, "p1");
assert.ok(pb.items[0].data.totpUri.startsWith("otpauth://"));
assert.deepEqual(pb.folders.map((f) => f.name), ["Clienti", "Rossi"]);
const lp = lib.importCsv("url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,testo nota,Nota LP,Personale,0\nhttps://a.it,u,p,,,Sito A,Lavoro,0\n", "lastpass");
assert.equal(lp.items[0].data.type, "note");
assert.equal(lp.items[1].data.urls[0], "https://a.it");
console.log("✓ CSV Passbolt e LastPass");

// 4. 1Password .1pux
const pux = zipSync({ "export.data": strToU8(JSON.stringify({ accounts: [{ vaults: [{ attrs: { name: "Clienti" }, items: [{
  overview: { title: "Router", url: "https://router.it" },
  details: { loginFields: [{ designation: "username", value: "root" }, { designation: "password", value: "r00t!" }],
    sections: [{ fields: [{ title: "OTP", value: { totp: "otpauth://totp/R?secret=GEZDGNBV" } }] }] },
}] }] }] })) });
const op = lib.import1Password(pux);
assert.equal(op.items[0].data.password, "r00t!");
assert.ok(op.items[0].data.totpUri);
console.log("✓ 1Password .1pux");
console.log("\nImport verificati con il pacchetto per browser.");

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

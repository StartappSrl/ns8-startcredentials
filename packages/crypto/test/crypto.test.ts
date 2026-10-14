import { test, before } from "node:test";
import assert from "node:assert/strict";
import {
  initCrypto, CryptoError, seal, open, newSymmetricKey, fromB64, toB64,
  newKdfParams, deriveMasterKey, MIN_OPS_LIMIT, MIN_MEM_LIMIT,
  generateUserKeys, wrapPrivateKeys, unwrapPrivateKeys, fingerprint,
  certifyUserKeys, verifyUserCertification,
  newContainerKey, grantContainerKey, openContainerKey,
  encryptItem, decryptItem, rewrapItemKey,
  newFileKey, encryptFile, decryptFile,
  hostHash, normalizeHost,
  base32Decode, parseOtpauthUri, generateTotp,
} from "../src/index.js";

const isCode = (code: string) => (e: unknown) => e instanceof CryptoError && e.code === code;
// Parametri minimi per velocità nei test; in produzione si usano i predefiniti.
const fastKdf = () => newKdfParams(MIN_OPS_LIMIT, MIN_MEM_LIMIT);

before(async () => { await initCrypto(); });

test("busta AEAD: andata e ritorno", () => {
  const k = newSymmetricKey();
  const env = seal(k, new TextEncoder().encode("segreto"), "ctx:a", "k1");
  assert.equal(new TextDecoder().decode(open(k, env, "ctx:a")), "segreto");
});

test("busta AEAD: contesto, chiave o byte alterati vengono rifiutati", () => {
  const k = newSymmetricKey();
  const env = seal(k, new Uint8Array([1, 2, 3]), "ctx:a", "k1");
  assert.throws(() => open(k, env, "ctx:b"), isCode("decryption_failed"));
  assert.throws(() => open(newSymmetricKey(), env, "ctx:a"), isCode("decryption_failed"));
  const raw = fromB64(env);
  raw[raw.length - 1]! ^= 1;
  assert.throws(() => open(k, toB64(raw), "ctx:a"), isCode("decryption_failed"));
  const hdr = fromB64(env);
  hdr[3]! ^= 1; // id chiave alterato: fa parte dei dati associati
  assert.throws(() => open(k, toB64(hdr), "ctx:a"), isCode("decryption_failed"));
});

test("Argon2id: deterministica, sensibile alla password, rifiuta parametri deboli", () => {
  const p = fastKdf();
  const a = deriveMasterKey("correct horse battery", p);
  assert.deepEqual(a, deriveMasterKey("correct horse battery", p));
  assert.notDeepEqual(a, deriveMasterKey("correct horse batterz", p));
  assert.throws(() => deriveMasterKey("corta", p), isCode("invalid_input"));
  assert.throws(() => deriveMasterKey("correct horse battery", { ...p, memLimitBytes: 1024 * 1024 }), isCode("weak_kdf_params"));
});

test("chiavi utente: cifrate con la master key, legate a utente e versione", () => {
  const mk = deriveMasterKey("una master password lunga", fastKdf());
  const keys = generateUserKeys();
  const wrapped = wrapPrivateKeys(mk, keys, "u1", 1);
  const back = unwrapPrivateKeys(mk, wrapped, "u1", 1);
  assert.deepEqual(back.boxPrivate, keys.boxPrivate);
  assert.deepEqual(back.signPrivate, keys.signPrivate);
  assert.throws(() => unwrapPrivateKeys(mk, wrapped, "u2", 1), isCode("decryption_failed"));
  assert.match(fingerprint(keys.publicKeys), /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
});

test("certificazione dell'organizzazione sulle chiavi pubbliche", () => {
  const org = generateUserKeys();
  const user = generateUserKeys();
  const cert = certifyUserKeys("u1", 1, user.publicKeys, org.signPrivate);
  verifyUserCertification("u1", 1, user.publicKeys, cert, org.publicKeys.sign);
  const impostor = generateUserKeys();
  assert.throws(() => verifyUserCertification("u1", 1, impostor.publicKeys, cert, org.publicKeys.sign), isCode("invalid_signature"));
});

test("condivisione: Marco consegna la CK a Laura, che la apre e legge l'elemento", () => {
  const marco = { userId: "marco", keys: generateUserKeys() };
  const laura = { userId: "laura", keys: generateUserKeys() };
  const ck = newContainerKey();
  const item = encryptItem(ck, 1, "c1", "i1", { type: "login", name: "Microsoft 365", username: "admin@studio.it", password: "xk7-Qw!2mRv9" });
  const grant = grantContainerKey({ containerKey: ck, containerId: "c1", keyVersion: 1, recipientId: "laura", recipientPublic: laura.keys.publicKeys, permission: "write", grantor: marco });
  const ckLaura = openContainerKey(grant, laura, marco.keys.publicKeys.sign);
  assert.equal(decryptItem(ckLaura, "c1", "i1", item).password, "xk7-Qw!2mRv9");
});

test("condivisione: permesso alterato o mittente falso vengono rifiutati", () => {
  const marco = { userId: "marco", keys: generateUserKeys() };
  const laura = { userId: "laura", keys: generateUserKeys() };
  const ck = newContainerKey();
  const grant = grantContainerKey({ containerKey: ck, containerId: "c1", keyVersion: 1, recipientId: "laura", recipientPublic: laura.keys.publicKeys, permission: "read", grantor: marco });
  assert.throws(() => openContainerKey({ ...grant, permission: "manage" }, laura, marco.keys.publicKeys.sign), isCode("invalid_signature"));
  const mallory = generateUserKeys();
  assert.throws(() => openContainerKey(grant, laura, mallory.publicKeys.sign), isCode("invalid_signature"));
  assert.throws(() => openContainerKey(grant, { userId: "sara", keys: generateUserKeys() }, marco.keys.publicKeys.sign), isCode("invalid_input"));
});

test("elementi: un blob spostato su un altro elemento non si decifra", () => {
  const ck = newContainerKey();
  const a = encryptItem(ck, 1, "c1", "i1", { type: "note", name: "A", notes: "uno" });
  assert.throws(() => decryptItem(ck, "c1", "i2", a), isCode("decryption_failed"));
  assert.throws(() => decryptItem(ck, "c2", "i1", a), isCode("decryption_failed"));
});

test("rotazione: dopo la revoca la vecchia CK non apre le nuove IK", () => {
  const oldCk = newContainerKey();
  const item = encryptItem(oldCk, 1, "c1", "i1", { type: "login", name: "PEC", password: "p" });
  const newCk = newContainerKey();
  const rotated = { ...item, ikEnc: rewrapItemKey(oldCk, newCk, 2, "c1", "i1", item.ikEnc) };
  assert.equal(decryptItem(newCk, "c1", "i1", rotated).password, "p");
  assert.throws(() => decryptItem(oldCk, "c1", "i1", rotated), isCode("decryption_failed"));
});

test("allegati: andata e ritorno su più blocchi, rileva alterazioni e troncamenti", () => {
  const fk = newFileKey();
  const data = new Uint8Array(2500).map((_, i) => i % 251);
  const enc = encryptFile(fk, "a1", data, 1000);
  assert.equal(enc.chunks.length, 3);
  assert.deepEqual(decryptFile(fk, "a1", enc), data);
  assert.throws(() => decryptFile(fk, "a1", { ...enc, chunks: enc.chunks.slice(0, 2) }), isCode("file_truncated"));
  assert.throws(() => decryptFile(fk, "a1", { ...enc, chunks: [enc.chunks[1]!, enc.chunks[0]!, enc.chunks[2]!] }), isCode("decryption_failed"));
  assert.throws(() => decryptFile(fk, "a2", enc), isCode("decryption_failed"));
  assert.deepEqual(decryptFile(fk, "a1", encryptFile(fk, "a1", new Uint8Array(0))), new Uint8Array(0));
});

test("hash domini: stabili, normalizzati e diversi tra contenitori", () => {
  const ck = newContainerKey();
  assert.equal(normalizeHost("https://Admin.Microsoft.com/path?x=1"), "admin.microsoft.com");
  assert.equal(hostHash(ck, "admin.microsoft.com"), hostHash(ck, "https://ADMIN.microsoft.com./"));
  assert.notEqual(hostHash(ck, "admin.microsoft.com"), hostHash(newContainerKey(), "admin.microsoft.com"));
  assert.notEqual(hostHash(ck, "admin.microsoft.com"), hostHash(ck, "admin.microsoft.com.evil.io"));
});

test("TOTP: vettori ufficiali RFC 6238 (SHA-1, SHA-256, SHA-512)", async () => {
  const ascii = (s: string) => new TextEncoder().encode(s);
  const seeds = {
    "SHA-1": ascii("12345678901234567890"),
    "SHA-256": ascii("12345678901234567890123456789012"),
    "SHA-512": ascii("1234567890123456789012345678901234567890123456789012345678901234"),
  } as const;
  const vectors: [number, string, string, string][] = [
    [59, "94287082", "46119246", "90693936"],
    [1111111109, "07081804", "68084774", "25091201"],
    [1111111111, "14050471", "67062674", "99943326"],
    [1234567890, "89005924", "91819424", "93441116"],
    [2000000000, "69279037", "90698825", "38618901"],
    [20000000000, "65353130", "77737706", "47863826"],
  ];
  for (const [t, s1, s256, s512] of vectors) {
    for (const [alg, want] of [["SHA-1", s1], ["SHA-256", s256], ["SHA-512", s512]] as const) {
      const { code } = await generateTotp({ secret: seeds[alg], algorithm: alg, digits: 8, period: 30 }, t * 1000);
      assert.equal(code, want, `${alg} a t=${t}`);
    }
  }
});

test("TOTP: parsing URI otpauth e Base32", async () => {
  const p = parseOtpauthUri("otpauth://totp/Microsoft:admin%40studio.it?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Microsoft");
  assert.equal(p.issuer, "Microsoft");
  assert.equal(p.account, "admin@studio.it");
  assert.equal(p.digits, 6);
  assert.deepEqual(p.secret, new TextEncoder().encode("12345678901234567890"));
  const { code, secondsLeft } = await generateTotp(p, 59_000);
  assert.equal(code, "287082");
  assert.equal(secondsLeft, 1);
  assert.deepEqual(base32Decode("gezd gnbv"), base32Decode("GEZDGNBV"));
  assert.throws(() => parseOtpauthUri("otpauth://hotp/x?secret=GEZD"), isCode("invalid_input"));
});

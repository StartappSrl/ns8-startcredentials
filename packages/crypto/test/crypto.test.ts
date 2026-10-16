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

test("gruppi: certificazione, consegna ai membri, contenitore condiviso col gruppo", async () => {
  const { generateGroupKeys, certifyGroup, verifyGroupCert, grantGroupMembership, openGroupMembership, grantContainerToGroup, openGroupContainerKey } = await import("../src/index.js");
  const org = generateUserKeys();
  const admin = { userId: "admin", keys: generateUserKeys() };
  const sara = { userId: "sara", keys: generateUserKeys() };
  const g = generateGroupKeys();
  const cert = certifyGroup("g1", 1, g.boxPublic, org.signPrivate);
  verifyGroupCert("g1", 1, g.boxPublic, cert, org.publicKeys.sign);
  assert.throws(() => verifyGroupCert("g1", 1, generateGroupKeys().boxPublic, cert, org.publicKeys.sign), isCode("invalid_signature"));

  const m = grantGroupMembership({ groupId: "g1", keyVersion: 1, groupPrivate: g.boxPrivate, userId: "sara", userBoxPublic: sara.keys.publicKeys.box, role: "member", grantor: admin });
  const priv = openGroupMembership(m, sara, admin.keys.publicKeys.sign, g.boxPublic);
  assert.deepEqual(priv, g.boxPrivate);
  assert.throws(() => openGroupMembership({ ...m, role: "manager" }, sara, admin.keys.publicKeys.sign, g.boxPublic), isCode("invalid_signature"));
  // Il server non può far accettare una chiave di gruppo diversa da quella certificata.
  assert.throws(() => openGroupMembership(m, sara, admin.keys.publicKeys.sign, generateGroupKeys().boxPublic), isCode("invalid_signature"));

  const ck = newContainerKey();
  const gg = grantContainerToGroup({ containerKey: ck, containerId: "c1", keyVersion: 3, groupId: "g1", groupKeyVersion: 1, groupBoxPublic: g.boxPublic, permission: "read", grantor: admin });
  assert.deepEqual(openGroupContainerKey(gg, g.boxPublic, priv, admin.keys.publicKeys.sign), ck);
  assert.throws(() => openGroupContainerKey({ ...gg, permission: "manage" }, g.boxPublic, priv, admin.keys.publicKeys.sign), isCode("invalid_signature"));
});

test("rotazione della chiave dell'organizzazione: catena firmata accettata, catena falsa respinta", async () => {
  const { orgRotationMessage, verifyOrgChain, sign } = await import("../src/index.js");
  const k1 = generateUserKeys(), k2 = generateUserKeys(), k3 = generateUserKeys(), evil = generateUserKeys();
  const rec = generateUserKeys().publicKeys.box;
  const step = (v: number, from: typeof k1, to: typeof k1) => {
    const r = { version: v, oldSignPublic: from.publicKeys.sign, newSignPublic: to.publicKeys.sign, newRecoveryPublic: rec };
    return { ...r, signature: sign(orgRotationMessage(r), from.signPrivate) };
  };
  const chain = [step(2, k1, k2), step(3, k2, k3)];
  assert.equal(verifyOrgChain(k1.publicKeys.sign, k3.publicKeys.sign, chain), true);
  assert.equal(verifyOrgChain(k2.publicKeys.sign, k3.publicKeys.sign, chain), true);
  assert.equal(verifyOrgChain(k1.publicKeys.sign, k1.publicKeys.sign, chain), true);
  // Un server compromesso non può inserire una chiave sua: la firma non viene dalla chiave fissata.
  const forged = { version: 2, oldSignPublic: k1.publicKeys.sign, newSignPublic: evil.publicKeys.sign, newRecoveryPublic: rec };
  assert.equal(verifyOrgChain(k1.publicKeys.sign, evil.publicKeys.sign, [{ ...forged, signature: sign(orgRotationMessage(forged), evil.signPrivate) }]), false);
  assert.equal(verifyOrgChain(k1.publicKeys.sign, evil.publicKeys.sign, []), false);
  // Nemmeno alterando la chiave di recupero annunciata.
  assert.equal(verifyOrgChain(k1.publicKeys.sign, k2.publicKeys.sign, [{ ...chain[0]!, newRecoveryPublic: evil.publicKeys.box }]), false);
});

test("condivisione di un singolo elemento: firma, versione della chiave, destinatario", async () => {
  const { shareItemKey, openItemShare, encryptItem, openItemKey } = await import("../src/index.js");
  const marco = { userId: "marco", keys: generateUserKeys() };
  const sara = { userId: "sara", keys: generateUserKeys() };
  const ck = newContainerKey();
  const enc = encryptItem(ck, 1, "c1", "i1", { type: "login", name: "x", password: "p" });
  const ik = openItemKey(ck, "c1", "i1", enc.ikEnc);
  const share = shareItemKey({ itemKey: ik, itemId: "i1", containerId: "c1", ikVersion: 1, userId: "sara", userBoxPublic: sara.keys.publicKeys.box, grantor: marco });
  assert.deepEqual(openItemShare(share, sara, marco.keys.publicKeys.sign), ik);
  assert.throws(() => openItemShare({ ...share, ikVersion: 2 }, sara, marco.keys.publicKeys.sign), isCode("invalid_signature"));
  assert.throws(() => openItemShare({ ...share, itemId: "altro" }, sara, marco.keys.publicKeys.sign), isCode("invalid_signature"));
  assert.throws(() => openItemShare(share, { userId: "sara", keys: generateUserKeys() }, marco.keys.publicKeys.sign), isCode("decryption_failed"));
});

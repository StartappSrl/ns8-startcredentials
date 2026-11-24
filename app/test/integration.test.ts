/**
 * Test end-to-end: server reale, PostgreSQL reale, SDK client reale.
 * Richiede TEST_DATABASE_URL (default postgres://sc:sc@127.0.0.1/sc).
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import {
  Api, ApiError, completeRecovery, decryptExport, enableMfa, importAsClients, importBitwarden, importCsv, importInto, importStartCredentials,
  decryptSend, login, passwordHealth, passwordPolicy, rotationStatus, planClientImport, PolicyError, register, trustDevice, SecurityError, serverStatus, setupMfa, Vault, verifyMfa,
} from "@startcredentials/client";
import { Config, createPool, Db, migrate, pruneAudit, totpAt } from "../src/core.js";
import { purgeExpiredSends } from "../src/routes/sends.js";
import { expireAccess } from "../src/routes/containers.js";
import { APP_ROOT, buildApp } from "../src/server.js";

process.env.NODE_ENV = "test";
const FAST = { opsLimit: 2, memLimitBytes: 19 * 1024 * 1024 };
const DB_URL = process.env.TEST_DATABASE_URL ?? "postgres://sc:sc@127.0.0.1/sc";

let db: Db;
let app: FastifyInstance;
let base: string;
const cfg: Config = {
  databaseUrl: DB_URL,
  serverSecret: randomBytes(32),
  bootstrapToken: randomBytes(24).toString("base64url"),
  publicUrl: "https://credenziali.example.com",
  attachmentsDir: mkdtempSync(join(tmpdir(), "sc-att-")),
  port: 0,
  maxAttachmentBytes: 5 * 1024 * 1024,
  sessionHours: 12,
  authPerIpPerMinute: 10_000,
  trustedDeviceDays: 30,
  authPerKeyPerMinute: 10_000,
  apiPerMinute: 100_000,
  anonPerIpPerMinute: 100_000,
  ipCeilingPerMinute: 100_000,
};

const api = (token?: string) => new Api({ baseUrl: base, token });

async function mfaCode(userId: string): Promise<string> {
  // Nei test più login cadono nello stesso intervallo di 30 s: azzeriamo il contatore anti-riuso.
  await db.query("UPDATE users SET mfa_last_counter = 0 WHERE id = $1", [userId]);
  const r = await db.query("SELECT mfa_secret_enc FROM users WHERE id = $1", [userId]);
  const { decryptServerSecret } = await import("../src/core.js");
  return totpAt(decryptServerSecret(cfg, r.rows[0].mfa_secret_enc), Math.floor(Date.now() / 30000));
}

async function onboard(a: Api, userId: string): Promise<string[]> {
  const setup = await setupMfa(a);
  assert.match(setup.otpauthUri, /^otpauth:\/\/totp\//);
  const codes = await enableMfa(a, totpAt(setup.secret, Math.floor(Date.now() / 30000)));
  assert.equal(codes.length, 10);
  assert.ok(codes.every((c) => /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(c)));
  return codes;
}

async function signIn(email: string, password: string, userId: string): Promise<Vault> {
  const a = api();
  const r = await login(a, email, password);
  assert.equal(r.state, "mfa_pending");
  await verifyMfa(a, await mfaCode(userId));
  return Vault.unlock(a, password);
}

async function rejects(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: unknown) => (e instanceof ApiError && e.code === code) || (e instanceof SecurityError && code === "security")
    || (e instanceof PolicyError && e.code === code));
}

const state: Record<string, any> = {};
const sentMail: { to: string; subject: string; text: string }[] = [];

before(async () => {
  db = createPool(DB_URL);
  await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await migrate(db, join(APP_ROOT, "migrations"));
  app = await buildApp(cfg, db, { mailer: { enabled: true, send: async (to, subject, text) => { sentMail.push({ to, subject, text }); return true; } } });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const addr = app.server.address();
  base = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
});

after(async () => {
  await app?.close();
  await db?.end();
});

describe("StartCredentials end-to-end", () => {
  test("bootstrap del primo amministratore, MFA obbligatoria e organizzazione", async () => {
    assert.equal((await serverStatus(api())).bootstrapped, false);
    const a = api();
    const reg = await register(a, { token: cfg.bootstrapToken, email: "marco@azienda.it", displayName: "Marco Ferri", password: "marco master password", kdf: FAST });
    assert.equal(reg.state, "mfa_setup");
    // Senza MFA nessun accesso ai dati.
    await rejects(a.get("/containers"), "mfa_setup_required");
    await onboard(a, reg.userId);
    const marco = await Vault.unlock(a, "marco master password");
    const org = await marco.initOrg(3, 2);
    assert.equal(org.shares.length, 3);
    assert.ok(org.shares.every((s) => s.startsWith("SCR1-")));
    state.marco = marco;
    state.marcoId = reg.userId;
    state.shares = org.shares;
    state.orgSign = marco.me.org!.signPublic;
    // Il token di bootstrap non è riutilizzabile.
    await rejects(register(api(), { token: cfg.bootstrapToken, email: "x@y.it", displayName: "X", password: "un'altra password", kdf: FAST }), "bootstrap_used");
  });

  test("invito, registrazione e certificazione con impronta", async () => {
    const marco: Vault = state.marco;
    const inv = await marco.invite("laura@azienda.it", "Laura Bassi", "user");
    assert.match(inv.inviteUrl, /^https:\/\/credenziali\.example\.com\/#invite=/);
    const a = api();
    const reg = await register(a, { token: inv.inviteToken, password: "laura master password", kdf: FAST });
    await onboard(a, reg.userId);
    const laura = await Vault.unlock(a, "laura master password", { pinnedOrgSignPublic: state.orgSign });
    assert.equal(laura.me.hasRecovery, true);
    // L'impronta sbagliata blocca la certificazione.
    await rejects(marco.certifyUser(reg.userId, "0000 0000 0000 0000 0000 0000 0000 0000"), "security");
    await marco.certifyUser(reg.userId, laura.myFingerprint);
    state.laura = laura;
    state.lauraId = reg.userId;
    // L'invito non è riutilizzabile.
    await rejects(register(api(), { token: inv.inviteToken, password: "altra password lunga", kdf: FAST }), "invalid_invite");
  });

  test("contenitore cliente, elemento con OTP e allegato, condivisione", async () => {
    const marco: Vault = state.marco;
    const laura: Vault = state.laura;
    const cid = await marco.createContainer({ name: "Studio Legale Moretti", sector: "Studio legale · Roma" });
    const folder = await marco.createFolder(cid, "Cloud e posta");
    const iid = await marco.createItem(cid, {
      type: "login", name: "Microsoft 365 – amministratore", username: "admin@studiomoretti.it", password: "xk7-Qw!2mRv9#LpZ",
      urls: ["https://admin.microsoft.com"], totpUri: "otpauth://totp/MS:admin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Microsoft",
    }, folder);
    let [item] = await marco.items(cid);
    const pdf = new Uint8Array(2_500_000).map((_, i) => (i * 7) % 256);
    await marco.addAttachment(item!, pdf, "Codici di recupero.pdf", "application/pdf");

    // Il server non vede nulla in chiaro.
    const raw = await db.query("SELECT data_enc FROM items WHERE id = $1", [iid]);
    assert.ok(!raw.rows[0].data_enc.includes("admin"));
    const cRaw = await db.query("SELECT meta_enc FROM containers WHERE id = $1", [cid]);
    assert.ok(!Buffer.from(cRaw.rows[0].meta_enc, "base64url").toString("latin1").includes("Moretti"));

    // Laura non vede il contenitore finché non è condiviso.
    assert.equal((await laura.containers()).filter((c) => c.kind === "client").length, 0);
    await marco.share(cid, state.lauraId, "write");
    const lc = (await laura.containers()).find((c) => c.id === cid)!;
    assert.equal(lc.meta.name, "Studio Legale Moretti");
    assert.equal(lc.permission, "write");
    const detail = await laura.container(cid);
    assert.deepEqual(detail.folders.map((f) => f.name), ["Cloud e posta"]);
    [item] = await laura.items(cid);
    assert.equal(item!.data.password, "xk7-Qw!2mRv9#LpZ");
    assert.equal((await Vault.totp(item!.data.totpUri!, 59_000)).code, "287082");
    const back = await laura.downloadAttachment(item!, item!.attachments[0]!);
    assert.deepEqual(back, pdf);
    assert.equal(item!.attachments[0]!.name, "Codici di recupero.pdf");

    // Autofill: solo corrispondenza esatta del nome host.
    assert.equal((await laura.lookup("https://admin.microsoft.com/login")).length, 1);
    assert.equal((await laura.lookup("https://admin.microsoft.com.evil.example")).length, 0);
    assert.equal((await laura.lookup("https://microsoft.com")).length, 0);

    // Modifica e conflitto di revisione.
    await laura.updateItem(item!, { ...item!.data, password: "nuova-password-1" });
    await rejects(marco.updateItem(item!, { ...item!.data, password: "sovrascrittura" }), "revision_conflict");
    const [fresh] = await marco.items(cid);
    assert.equal(fresh!.data.password, "nuova-password-1");
    const versions = await marco.itemVersions(fresh!);
    assert.equal(versions[0]!.data.password, "xk7-Qw!2mRv9#LpZ");
    state.cid = cid;
  });

  test("permessi: certificazione obbligatoria, sola lettura, firma verificata dal server", async () => {
    const marco: Vault = state.marco;
    const inv = await marco.invite("sara@azienda.it", "Sara Conti", "user");
    const a = api();
    const reg = await register(a, { token: inv.inviteToken, password: "sara master password", kdf: FAST });
    await onboard(a, reg.userId);
    const sara = await Vault.unlock(a, "sara master password");
    await rejects(marco.share(state.cid, reg.userId, "read"), "security");
    await marco.certifyUser(reg.userId, sara.myFingerprint);
    await marco.share(state.cid, reg.userId, "read");
    const [item] = await sara.items(state.cid);
    await rejects(sara.updateItem(item!, { ...item!.data, password: "x" }), "write_required");
    await rejects(sara.share(state.cid, reg.userId, "manage"), "manage_required");

    // Un client manomesso che altera il permesso nella consegna viene respinto dal server.
    const members = await marco.api.get<any[]>(`/containers/${state.cid}/members`);
    assert.equal(members.length, 3);
    const grantRow = await db.query("SELECT * FROM container_keys WHERE container_id = $1 AND user_id = $2", [state.cid, reg.userId]);
    const g = grantRow.rows[0];
    await rejects(marco.api.put(`/containers/${state.cid}/members`, {
      grant: { containerId: state.cid, keyVersion: g.key_version, recipientId: reg.userId, permission: "manage", sealedKey: g.sealed_key, grantedBy: state.marcoId, signature: g.signature },
    }), "invalid_grant_signature");
    state.sara = sara;
    state.saraId = reg.userId;
  });

  test("revoca con rotazione: chi è rimosso perde l'accesso, gli altri no", async () => {
    const marco: Vault = state.marco;
    const laura: Vault = state.laura;
    const sara: Vault = state.sara;
    await marco.deleteItem((await marco.items(state.cid))[0]!.id);
    await marco.restoreItem((await marco.items(state.cid, { trash: true }))[0]!.id);
    await marco.revoke(state.cid, state.saraId);
    await rejects(sara.items(state.cid), "container_not_found");
    const c = (await marco.containers()).find((x) => x.id === state.cid)!;
    assert.equal(c.keyVersion, 2);
    const fresh = await Vault.unlock(laura.api, "laura master password");
    const [item] = await fresh.items(state.cid);
    assert.equal(item!.data.password, "nuova-password-1");
    // Non si può rimuovere l'ultimo gestore.
    await rejects(marco.api.del(`/containers/${state.cid}/members/${state.marcoId}`), "last_manager");
  });

  test("area personale e import", async () => {
    const laura: Vault = state.laura;
    const pid = await laura.ensurePersonal();
    assert.equal(await laura.ensurePersonal(), pid);
    await rejects(state.marco.api.put(`/containers/${pid}/members`, { grant: {} }), "invalid_input");
    const csv = 'name,url,username,password,note\n"Hotel Ripetta, channel",https://channel.example.com,booking,"p,a""ss",nota\nPEC,https://pec.example.it,studio@pec.it,pec-pass,\n';
    const r = importCsv(csv, "chrome");
    assert.equal(r.items.length, 2);
    assert.equal(r.items[0]!.data.password, 'p,a"ss');
    await importInto(laura, pid, r);
    const bw = importBitwarden(JSON.stringify({
      encrypted: false, folders: [{ id: "f1", name: "Fornitori" }],
      items: [{ type: 1, name: "Fattura elettronica", folderId: "f1", login: { username: "u", password: "p", totp: "GEZDGNBVGY3TQOJQ", uris: [{ uri: "https://sdi.example.it" }] } },
              { type: 2, name: "Nota riservata", notes: "contenuto" }],
    }));
    await importInto(laura, pid, bw);
    const items = await laura.items(pid);
    assert.equal(items.length, 4);
    assert.ok(items.some((i) => i.data.totpUri?.startsWith("otpauth://totp/")));
    assert.deepEqual((await laura.container(pid)).folders.map((f) => f.name), ["Fornitori"]);
  });

  test("login: credenziali errate e utenti inesistenti danno lo stesso errore, OTP non riutilizzabile", async () => {
    await rejects(login(api(), "laura@azienda.it", "password sbagliata!!"), "invalid_credentials");
    await rejects(login(api(), "nessuno@azienda.it", "password sbagliata!!"), "invalid_credentials");
    const a = api();
    await login(a, "laura@azienda.it", "laura master password");
    const code = await mfaCode(state.lauraId);
    await verifyMfa(a, code);
    const b = api();
    await login(b, "laura@azienda.it", "laura master password");
    await rejects(verifyMfa(b, code), "invalid_code");
    await rejects(Vault.unlock(a, "laura master password", { pinnedOrgSignPublic: "chiave-diversa" }), "security");
  });

  test("recupero account con 2 quote su 3", async () => {
    const marco: Vault = state.marco;
    await assert.rejects(marco.startRecovery(state.lauraId, [state.shares[0]], FAST));
    const rec = await marco.startRecovery(state.lauraId, [state.shares[0], state.shares[2]], FAST);
    assert.match(rec.code, /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
    await assert.rejects(completeRecovery(api(), { token: rec.recoveryToken, code: "AAAA-BBBB", newPassword: "nuova master password", kdf: FAST }));
    await completeRecovery(api(), { token: rec.recoveryToken, code: rec.code, newPassword: "nuova master password", kdf: FAST });
    await rejects(login(api(), "laura@azienda.it", "laura master password"), "invalid_credentials");
    const laura = await signIn("laura@azienda.it", "nuova master password", state.lauraId);
    const [item] = await laura.items(state.cid);
    assert.equal(item!.data.password, "nuova-password-1");
    state.laura = laura;
  });

  test("codici MFA di riserva: monouso, rigenerabili; reset MFA da parte dell'amministratore", async () => {
    const sara: Vault = await signIn("sara@azienda.it", "sara master password", state.saraId);
    const codes = await sara.regenerateBackupCodes(await mfaCode(state.saraId));
    assert.equal((await sara.mfaStatus()).backupCodesRemaining, 10);
    const a = api();
    assert.equal((await login(a, "sara@azienda.it", "sara master password")).state, "mfa_pending");
    await verifyMfa(a, codes[3]!.toLowerCase());
    assert.equal((await sara.mfaStatus()).backupCodesRemaining, 9);
    const b = api();
    await login(b, "sara@azienda.it", "sara master password");
    await rejects(verifyMfa(b, codes[3]!), "invalid_code");
    // Telefono perso: l'amministratore azzera l'MFA, Sara la riconfigura al primo accesso.
    await state.marco.resetMfa(state.saraId);
    await rejects(sara.api.get("/me"), "unauthorized");
    const c = api();
    assert.equal((await login(c, "sara@azienda.it", "sara master password")).state, "mfa_setup");
    await onboard(c, state.saraId);
    state.sara = await Vault.unlock(c, "sara master password");
  });

  test("cambio della master password: serve quella attuale e il codice MFA", async () => {
    const sara: Vault = state.sara;
    await rejects(sara.changePassword("password sbagliata!!", "nuova password di sara", await mfaCode(state.saraId), FAST), "security");
    await rejects(sara.changePassword("sara master password", "nuova password di sara", "000000", FAST), "invalid_code");
    const other = api();
    await login(other, "sara@azienda.it", "sara master password");
    await sara.changePassword("sara master password", "nuova password di sara", await mfaCode(state.saraId), FAST);
    await rejects(other.get("/auth/session"), "unauthorized");
    await rejects(login(api(), "sara@azienda.it", "sara master password"), "invalid_credentials");
    const again = await signIn("sara@azienda.it", "nuova password di sara", state.saraId);
    assert.equal(again.myFingerprint, sara.myFingerprint);
    await sara.api.get("/me");
  });

  test("rotazione in sospeso: completata dal primo gestore che apre la cassaforte", async () => {
    const marco: Vault = state.marco;
    const cid = await marco.createContainer({ name: "Revoca interrotta" });
    await marco.createItem(cid, { type: "login", name: "x", password: "y" });
    await marco.share(cid, state.saraId, "read");
    // Revoca senza rotazione, come se il client si fosse chiuso a metà.
    await marco.api.del(`/containers/${cid}/members/${state.saraId}`);
    assert.equal((await marco.containers()).find((c) => c.id === cid)!.rotationRequired, true);
    const r = await marco.completePendingRotations();
    assert.ok(r.done.includes("Revoca interrotta"));
    const c = (await marco.containers()).find((x) => x.id === cid)!;
    assert.equal(c.rotationRequired, false);
    assert.equal(c.keyVersion, 2);
    assert.equal((await marco.items(cid))[0]!.data.password, "y");
  });

  test("uscita di un collega: accessi tolti ovunque e chiavi ruotate", async () => {
    const marco: Vault = state.marco;
    const laura = await signIn("laura@azienda.it", "nuova master password", state.lauraId);
    const solo = await marco.createContainer({ name: "Cliente solo di Laura" });
    await marco.createItem(solo, { type: "login", name: "z", password: "w" });
    await marco.share(solo, state.lauraId, "manage");
    await marco.api.del(`/containers/${solo}/members/${state.marcoId}`);
    await laura.rotate(solo);
    const before = (await marco.containers()).find((c) => c.id === state.cid)!.keyVersion;
    // Laura è l'unica gestrice di un cliente: l'uscita si ferma finché non si conferma.
    await rejects(marco.offboard(state.lauraId), "containers_without_manager");
    const r = await marco.offboard(state.lauraId, true);
    assert.equal(r.withoutManager.length, 1);
    assert.ok(r.rotated.includes("Studio Legale Moretti"));
    assert.equal((await marco.containers()).find((c) => c.id === state.cid)!.keyVersion, before + 1);
    await rejects(laura.api.get("/containers"), "unauthorized");
    await rejects(login(api(), "laura@azienda.it", "nuova master password"), "invalid_credentials");
    const keys = await db.query("SELECT count(*)::int AS n FROM container_keys k JOIN containers c ON c.id = k.container_id WHERE k.user_id = $1 AND c.kind <> 'personal'", [state.lauraId]);
    assert.equal(keys.rows[0].n, 0);
    await marco.setUser(state.lauraId, { status: "active" });
  });

  test("export cifrato, reimport e rapporto sulla salute delle password", async () => {
    const marco: Vault = state.marco;
    const pid = await marco.ensurePersonal();
    await marco.createItem(pid, { type: "login", name: "Debole", password: "abc123", urls: ["https://admin.example.com"] });
    await marco.createItem(pid, { type: "login", name: "Ripetuta 1", password: "Stessa-Password-2026!" });
    await marco.createItem(pid, { type: "login", name: "Ripetuta 2", password: "Stessa-Password-2026!" });
    const deb = (await marco.items(pid)).find((i) => i.data.name === "Debole")!;
    const pdf = new Uint8Array(1_500_000).map((_, i) => (i * 13) % 256);
    await marco.addAttachment(deb, pdf, "contratto.pdf", "application/pdf");
    const noAtt = await marco.exportEncrypted("passphrase export lunga", FAST);
    assert.ok(noAtt.attachmentsSkipped >= 1);
    const exp = await marco.exportEncrypted("passphrase export lunga", FAST, { includeAttachments: true });
    assert.ok(exp.attachments >= 1);
    assert.ok(!exp.file.includes("Stessa-Password"), "l'export deve essere cifrato");
    assert.ok(exp.items >= 4);
    await assert.rejects(decryptExport(exp.file, "passphrase sbagliata!!"), SecurityError);
    const res = await importStartCredentials(exp.file, "passphrase export lunga");
    assert.equal(res.items.length, exp.items);
    assert.ok(res.folders.some((f) => f.name === "Studio Legale Moretti"));
    const target = await marco.createContainer({ name: "Ripristino export" });
    await importInto(marco, target, res);
    const restored = await marco.items(target);
    assert.equal(restored.length, exp.items);
    const withPdf = restored.find((i) => i.data.name === "Debole")!;
    assert.equal(withPdf.attachments[0]!.name, "contratto.pdf");
    assert.deepEqual(await marco.downloadAttachment(withPdf, withPdf.attachments[0]!), pdf);

    const entries = [];
    for (const c of await marco.containers()) for (const item of await marco.items(c.id)) entries.push({ container: c, item });
    const h = passwordHealth(entries);
    assert.ok(h.weak.some((e) => e.item.data.name === "Debole"));
    assert.ok(h.reused.some((g) => g.some((e) => e.item.data.name === "Ripetuta 1")));
    assert.ok(h.missingOtp.some((e) => e.item.data.name === "Debole"));

    // Data del cambio password e promemoria di rotazione: restano anche se l'editor ricostruisce i dati.
    const rid = await marco.createItem(target, { type: "login", name: "Rotazione", password: "Prima-Password-Lunga-1!", rotateDays: 90 });
    let rot = (await marco.items(target)).find((i) => i.id === rid)!;
    const firstDate = rot.data.passwordChangedAt!;
    assert.ok(firstDate, "la data del cambio password si imposta alla creazione");
    await marco.updateItem(rot, { type: "login", name: "Rotazione rinominata", password: "Prima-Password-Lunga-1!" });
    rot = (await marco.items(target)).find((i) => i.id === rid)!;
    assert.equal(rot.data.passwordChangedAt, firstDate, "senza cambiare la password la data resta");
    assert.equal(rot.data.rotateDays, 90, "il promemoria resta");
    assert.equal(rotationStatus(rot)!.due, false);
    assert.equal(rotationStatus(rot, Date.now() + 91 * 86400_000)!.due, true);
    await new Promise((r) => setTimeout(r, 5));
    await marco.updateItem(rot, { ...rot.data, password: "Seconda-Password-Lunga-2!", rotateDays: undefined });
    rot = (await marco.items(target)).find((i) => i.id === rid)!;
    assert.ok(rot.data.passwordChangedAt! > firstDate, "cambiando la password la data si aggiorna");
    assert.equal(rot.data.rotateDays, undefined, "il promemoria si può togliere");
    const hc = passwordHealth(entries, { containerId: target });
    assert.ok(hc.weak.every((e) => e.container.id === target));
  });

  test("gruppi: accesso tramite gruppo, firma verificata, uscita dal gruppo con doppia rotazione", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    // Nuovo collega, certificato.
    const inv = await marco.invite("paolo@azienda.it", "Paolo Neri", "user");
    const pa = api();
    const reg = await register(pa, { token: inv.inviteToken, password: "paolo master password", kdf: FAST });
    await onboard(pa, reg.userId);
    const paolo = await Vault.unlock(pa, "paolo master password");
    await marco.certifyUser(reg.userId, paolo.myFingerprint);

    const gid = await marco.createGroup("Tecnici");
    await marco.setGroupMember(gid, state.saraId, "member");
    await marco.setGroupMember(gid, reg.userId, "member");
    const g = (await sara.groups()).find((x) => x.id === gid)!;
    assert.equal(g.verified, true);
    assert.equal(g.members, 3);
    assert.equal(g.myRole, "member");

    const cid = await marco.createContainer({ name: "Cliente del gruppo" });
    await marco.createItem(cid, { type: "login", name: "NAS", username: "admin", password: "nas-segreta", urls: ["https://nas.cliente.it"] });
    await marco.shareWithGroup(cid, gid, "write");

    const sc = (await sara.containers()).find((c) => c.id === cid)!;
    assert.deepEqual(sc.viaGroups, ["Tecnici"]);
    assert.equal(sc.permission, "write");
    const [it] = await sara.items(cid);
    assert.equal(it!.data.password, "nas-segreta");
    await sara.updateItem(it!, { ...it!.data, password: "nas-nuova" });
    assert.equal((await paolo.items(cid))[0]!.data.password, "nas-nuova");
    assert.equal((await sara.lookup("https://nas.cliente.it/login")).length, 1);

    // Un client manomesso non può alzare il permesso del gruppo: la firma non torna.
    const row = (await db.query("SELECT * FROM container_group_keys WHERE container_id = $1", [cid])).rows[0];
    await rejects(marco.api.put(`/containers/${cid}/groups`, { grant: {
      containerId: cid, keyVersion: row.key_version, groupId: gid, groupKeyVersion: row.group_key_version, permission: "manage",
      sealedKey: row.sealed_key, grantedBy: state.marcoId, signature: row.signature } }), "invalid_grant_signature");

    // Paolo esce dal gruppo: ruotano la chiave del gruppo e quella del cliente.
    const before = (await marco.containers()).find((c) => c.id === cid)!.keyVersion;
    const r = await marco.removeGroupMember(gid, reg.userId);
    assert.deepEqual(r.failed, []);
    assert.ok(r.done.includes("gruppo Tecnici") && r.done.includes("Cliente del gruppo"));
    assert.equal((await marco.groups()).find((x) => x.id === gid)!.keyVersion, 2);
    assert.equal((await marco.containers()).find((c) => c.id === cid)!.keyVersion, before + 1);
    await rejects(paolo.items(cid), "container_not_found");
    assert.equal((await sara.items(cid))[0]!.data.password, "nas-nuova");

    // Mentre la chiave del gruppo aspetta la rotazione, non si condivide nulla con il gruppo.
    await marco.setGroupMember(gid, reg.userId, "member");
    await marco.api.del(`/groups/${gid}/members/${reg.userId}`);
    const other = await marco.createContainer({ name: "Altro cliente" });
    await rejects(marco.shareWithGroup(other, gid, "read"), "security");
    await marco.completePendingRotations();
    await marco.shareWithGroup(other, gid, "read");
    assert.ok((await sara.containers()).some((c) => c.id === other && c.permission === "read"));
    // Solo gli amministratori gestiscono i gruppi.
    await rejects(sara.createGroup("Abusivo"), "security");
  });

  test("import con un cliente per ogni cartella principale", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    const rossi = await marco.createContainer({ name: "Ferramenta Rossi" });
    await marco.createFolder(rossi, "Server");
    // Cliente omonimo su cui Marco ha solo la lettura.
    await rejects(sara.createContainer({ name: "Non consentito" }), "admin_required");
    await marco.setUser(state.saraId, { role: "admin" });
    const saraAdmin = await signIn("sara@azienda.it", "nuova password di sara", state.saraId);
    const ro = await saraAdmin.createContainer({ name: "Solo Lettura Spa" });
    await saraAdmin.share(ro, state.marcoId, "read");
    await marco.setUser(state.saraId, { role: "user" });
    // La retrocessione chiude le sessioni: Sara rientra.
    state.sara = await signIn("sara@azienda.it", "nuova password di sara", state.saraId);
    const csv = [
      "name,username,password,url,notes,folder",
      "NAS,admin,nas-1,https://nas.rossi.it,,Ferramenta Rossi/Server",
      "Router,root,router-1,https://router.rossi.it,,ferramenta rossi",
      "PEC,bianchi@pec.it,pec-1,https://pec.it,,Bianchi Srl/Posta/PEC",
      "Gestionale,ro,ro-1,,,Solo lettura SPA",
      "Senza cartella,me,sc-1,,,",
    ].join("\n");
    const personal = await marco.ensurePersonal();
    const first = await importAsClients(marco, importCsv(csv, "passbolt"), { looseContainerId: personal });
    assert.deepEqual(first.created, ["Bianchi Srl"]);
    assert.deepEqual(first.reused, ["Ferramenta Rossi"]);
    assert.equal(first.imported, 4);
    assert.equal(first.loose, 1);
    assert.ok(first.skipped.some((x) => x.name === "Solo lettura SPA" && /sola lettura|solo la lettura/.test(x.reason)));

    const rossiDetail = await marco.container(rossi);
    assert.deepEqual(rossiDetail.folders.map((f) => f.name), ["Server"], "la cartella Server esistente va riusata");
    const rossiItems = await marco.items(rossi);
    assert.equal(rossiItems.find((i) => i.data.name === "NAS")!.folderId, rossiDetail.folders[0]!.id);
    assert.equal(rossiItems.find((i) => i.data.name === "Router")!.folderId, null);

    const bianchi = (await marco.containers()).find((c) => c.meta.name === "Bianchi Srl")!;
    const bd = await marco.container(bianchi.id);
    const posta = bd.folders.find((f) => f.name === "Posta")!;
    assert.equal(bd.folders.find((f) => f.name === "PEC")!.parentId, posta.id);
    assert.equal((await marco.items(bianchi.id))[0]!.data.password, "pec-1");
    assert.ok((await marco.items(personal)).some((i) => i.data.name === "Senza cartella"));
    assert.equal((await state.sara.items(ro)).length, 0, "nessun elemento nel cliente in sola lettura");

    // Secondo import identico: niente doppioni, nessun cliente nuovo.
    const again = await importAsClients(marco, importCsv(csv, "passbolt"), { looseContainerId: personal });
    assert.deepEqual(again.created, []);
    assert.equal(again.imported, 0);
    assert.equal(again.duplicates, 4);
    assert.equal((await marco.items(rossi)).length, 2);

    // Export racchiuso in un'unica cartella esterna: i clienti sono al secondo livello.
    const wrapped = importCsv([
      "name,username,password,url,notes,folder",
      "NAS,admin,nas-1,,,Passbolt/Ferramenta Rossi/Server",
      "Mail,info,m-1,,,Passbolt/Verdi Snc",
      "Radice,x,y,,,Passbolt",
    ].join("\n"), "passbolt");
    const lvl1 = planClientImport(wrapped, await marco.containers(), { level: 1 });
    assert.deepEqual(lvl1.clients.map((c) => c.name), ["Passbolt"]);
    const lvl2 = planClientImport(wrapped, await marco.containers(), { level: 2 });
    assert.deepEqual(lvl2.clients.map((c) => c.name), ["Ferramenta Rossi", "Verdi Snc"]);
    assert.deepEqual(lvl2.clients[0]!.folders.map((f) => f.name), ["Server"]);
    assert.equal(lvl2.loose.length, 1, "gli elementi nella cartella esterna restano senza cliente");

    // Un utente non amministratore non crea clienti: importa solo in quelli esistenti a cui può scrivere.
    await marco.share(rossi, state.saraId, "write");
    const plain = importCsv("name,username,password,url,notes,folder\nNuovo,u,p,,,Ferramenta Rossi\nAltro,u,p,,,Cliente Inesistente\n", "passbolt");
    const bySara = await importAsClients(state.sara, plain, { looseContainerId: null });
    assert.deepEqual(bySara.created, []);
    assert.deepEqual(bySara.reused, ["Ferramenta Rossi"]);
    assert.ok(bySara.skipped.some((x) => x.name === "Cliente Inesistente" && /amministratore/.test(x.reason)));
  });

  test("selezione multipla: cestino e ripristino di più elementi, controlli di permesso", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    const cid = await marco.createContainer({ name: "Pulizia in blocco" });
    const ids = [];
    for (const n of ["A", "B", "C", "D"]) ids.push(await marco.createItem(cid, { type: "login", name: n, password: n }));
    assert.equal(await marco.deleteItems(cid, ids.slice(0, 3)), 3);
    assert.deepEqual((await marco.items(cid)).map((i) => i.data.name), ["D"]);
    assert.equal((await marco.items(cid, { trash: true })).length, 3);
    assert.equal(await marco.restoreItems(cid, ids.slice(0, 2)), 2);
    assert.equal((await marco.items(cid)).length, 3);
    // Spostamento in cartella: solo la cartella cambia, i dati restano leggibili.
    const fid = await marco.createFolder(cid, "Archivio");
    assert.equal(await marco.moveItems(cid, ids.slice(0, 2), fid), 2);
    const moved = await marco.items(cid);
    assert.deepEqual(moved.filter((i) => i.folderId === fid).map((i) => i.data.name).sort(), ["A", "B"]);
    assert.equal(moved.find((i) => i.data.name === "A")!.data.password, "A");
    assert.equal(await marco.moveItems(cid, [ids[0]!], null), 1);
    const foreignFolder = await marco.createFolder(await marco.createContainer({ name: "Cartella estranea" }), "X");
    await rejects(marco.moveItems(cid, [ids[1]!], foreignFolder), "invalid_folder");
    // Un elemento di un altro contenitore nella stessa richiesta: rifiutata per intero.
    const other = await marco.createContainer({ name: "Altro" });
    const foreign = await marco.createItem(other, { type: "note", name: "estraneo" });
    await rejects(marco.deleteItems(cid, [ids[3]!, foreign]), "items_not_in_container");
    assert.equal((await marco.items(cid)).length, 3, "nessuna modifica parziale");
    // Sola lettura: niente cancellazioni.
    await marco.share(cid, state.saraId, "read");
    await rejects(sara.deleteItems(cid, [ids[3]!]), "write_required");
    const log = await marco.auditLog({ containerId: cid });
    assert.equal(log.filter((l) => l.action === "item.deleted").length, 3);
    assert.equal(log.filter((l) => l.action === "item.restored").length, 2);
  });

  test("rotazione della chiave dell'organizzazione: catena seguita dai client, quote nuove, certificazioni rinnovate", async () => {
    const marco: Vault = state.marco;
    const oldPin: string = marco.me.org!.signPublic;
    const oldShares: string[] = state.shares;
    const r = await marco.rotateOrgKeys(3, 2);
    assert.notEqual(marco.me.org!.signPublic, oldPin);
    assert.equal(r.shares.length, 3);

    // Sara riapre la cassaforte con la chiave vecchia fissata: la catena firmata viene accettata.
    const sara = await signIn("sara@azienda.it", "nuova password di sara", state.saraId).catch(async () => {
      const a = api();
      await login(a, "sara@azienda.it", "nuova password di sara");
      await verifyMfa(a, await mfaCode(state.saraId));
      return Vault.unlock(a, "nuova password di sara", { pinnedOrgSignPublic: oldPin });
    });
    const again = await Vault.unlock(sara.api, "nuova password di sara", { pinnedOrgSignPublic: oldPin });
    assert.equal(again.me.org!.signPublic, marco.me.org!.signPublic);
    // Le certificazioni nuove si verificano con la nuova chiave: accesso diretto e tramite gruppo funzionano.
    const dir = await again.directory(true);
    assert.ok(dir.find((u) => u.id === state.marcoId)!.verified);
    const viaGroup = (await again.containers()).find((c) => c.meta.name === "Cliente del gruppo");
    assert.ok(viaGroup, "cliente visibile tramite gruppo");
    assert.equal((await again.items(viaGroup!.id))[0]!.data.password, "nas-nuova");
    assert.ok((await again.groups()).every((g) => g.verified));

    // Copie di recupero: azzerate dalla rotazione, ricreate dal client con la nuova chiave.
    assert.equal(again.me.hasRecovery, false);
    assert.equal(await again.ensureRecoveryCopy(), true);
    await assert.rejects(marco.startRecovery(state.saraId, oldShares.slice(0, 2), FAST), SecurityError);
    const rec = await marco.startRecovery(state.saraId, r.shares.slice(0, 2), FAST);
    assert.ok(rec.code);

    // Una sessione già aperta segue la rotazione senza nuovo sblocco.
    const resumed = await Vault.restore(sara.api, again.serialize(), { pinnedOrgSignPublic: oldPin });
    assert.equal(resumed.me.org!.signPublic, marco.me.org!.signPublic);

    // Server compromesso: chiave diversa senza catena firmata dalla chiave fissata.
    const forged = { ...again.me, org: { ...again.me.org!, signPublic: "chiave-falsa", rotations: [] } };
    await rejects(Vault.restore(api(), { v: 1, me: forged, keys: again.serialize().keys }, { pinnedOrgSignPublic: oldPin, refresh: false }), "security");
    state.shares = r.shares;
  });

  test("condivisione di una singola password: sola lettura, revoca con ricifratura", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    // Come fa l'estensione alla ripresa della sessione: rilegge l'organizzazione (ruotata in un test precedente).
    await sara.refreshMe();
    const paoloId = (await db.query("SELECT id FROM users WHERE email = 'paolo@azienda.it'")).rows[0].id;
    const paolo = await signIn("paolo@azienda.it", "paolo master password", paoloId);
    const cid = await marco.createContainer({ name: "Cliente riservato" });
    const iid = await marco.createItem(cid, { type: "login", name: "Router riservato", username: "admin", password: "solo-questa", urls: ["https://router.riservato.it"] });
    let [item] = await marco.items(cid);
    await marco.updateItem(item!, { ...item!.data, password: "solo-questa-2" });
    [item] = await marco.items(cid);
    const doc = new Uint8Array(300_000).map((_, i) => (i * 7) % 256);
    await marco.addAttachment(item!, doc, "schema.pdf", "application/pdf");
    [item] = await marco.items(cid);
    await marco.shareItem(item!, state.saraId);
    await marco.shareItem(item!, paoloId);
    assert.equal((await marco.itemShares(iid)).length, 2);

    // Sara vede solo quell'elemento, non il cliente.
    assert.ok(!(await sara.containers()).some((c) => c.id === cid));
    await rejects(sara.items(cid), "container_not_found");
    const got = (await sara.sharedWithMe()).find((i) => i.id === iid)!;
    assert.equal(got.data.password, "solo-questa-2");
    assert.equal(got.sharedBy, "Marco Ferri");
    assert.deepEqual(await sara.downloadAttachment(got, got.attachments[0]!), doc);
    assert.equal((await sara.lookup("https://router.riservato.it/login")).length, 1);

    // Revoca: nuova chiave per dati, versioni, allegati; Paolo la riceve, Sara no.
    const before = (await marco.items(cid))[0]!.ikVersion;
    await marco.unshareItem((await marco.items(cid))[0]!, state.saraId);
    const after = (await marco.items(cid))[0]!;
    assert.equal(after.ikVersion, before + 1);
    assert.ok(!(await sara.sharedWithMe()).some((i) => i.id === iid));
    await rejects(sara.downloadAttachment(got, got.attachments[0]!), "container_not_found");
    const p2 = (await paolo.sharedWithMe()).find((i) => i.id === iid)!;
    assert.equal(p2.data.password, "solo-questa-2");
    assert.deepEqual(await paolo.downloadAttachment(p2, p2.attachments[0]!), doc);
    assert.equal((await marco.itemVersions(after))[0]!.data.password, "solo-questa");
    assert.deepEqual(await marco.downloadAttachment(after, after.attachments[0]!), doc);

    // Una consegna vecchia (chiave precedente) non viene più accettata.
    const old = (await db.query("SELECT * FROM item_shares WHERE item_id = $1 AND user_id = $2", [iid, paoloId])).rows[0];
    await rejects(marco.api.post(`/items/${iid}/shares`, { share: {
      itemId: iid, containerId: cid, ikVersion: before, userId: state.saraId, sealedKey: old.sealed_key, grantedBy: state.marcoId, signature: old.signature } }), "stale_item_key");
    // Chi non gestisce il cliente non può condividere.
    await marco.share(cid, state.saraId, "write");
    const asWriter = (await sara.items(cid))[0]!;
    await rejects(sara.shareItem(asWriter, paoloId), "manage_required");
  });

  test("aggiornamenti: un collega vede i cambiamenti dei clienti che può leggere, e solo quelli", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    const shared = await marco.createContainer({ name: "Condiviso per aggiornamenti" });
    const secret = await marco.createContainer({ name: "Non condiviso" });
    await marco.share(shared, state.saraId, "read");
    const { latest } = await sara.changes(0);
    await marco.createItem(shared, { type: "note", name: "nuova" });
    await marco.createItem(secret, { type: "note", name: "riservata" });
    const ch = await sara.changes(latest);
    assert.deepEqual(ch.containers, [shared], "solo i clienti visibili a Sara");
    assert.ok(ch.latest > latest);
    // Accesso tolto: Sara deve ricaricare l'elenco dei clienti.
    const before = (await sara.changes(0)).latest;
    await marco.revoke(shared, state.saraId);
    const ch2 = await sara.changes(before);
    assert.equal(ch2.membership, true);
    assert.ok(!ch2.containers.includes(secret));
  });

  test("accesso d'emergenza: consegna trattenuta, richiesta, rifiuto, attesa, rotazione, firma e concessione", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    await sara.refreshMe();
    const cid = await marco.createContainer({ name: "Cliente Emergenza", sector: "Prova" });
    const iid = await marco.createItem(cid, { type: "login", name: "Router", password: "Segreto-Emergenza-1!" });
    await marco.designateEmergency(cid, state.saraId, "write", 48);
    // Il designato vede il nome del cliente (sigillato per lui) ma non ha accesso.
    const mine = (await sara.myEmergencyAccess()).find((e) => e.containerId === cid)!;
    assert.equal(mine.name, "Cliente Emergenza");
    assert.equal(mine.status, "idle");
    assert.ok(!(await sara.containers()).some((c) => c.id === cid));
    await assert.rejects(sara.claimEmergency(mine.id), (e: { code?: string }) => e.code === "emergency_not_ready");
    // La consegna trattenuta non viene mai restituita al designato.
    const sealed = (await db.query("SELECT sealed_key FROM emergency_access WHERE id = $1", [mine.id])).rows[0].sealed_key;
    assert.ok(!JSON.stringify(await sara.api.get("/emergency")).includes(sealed));
    // Richiesta: gestori e amministratori avvisati, senza il nome del cliente.
    sentMail.length = 0;
    await sara.requestEmergency(mine.id);
    assert.ok(sentMail.some((m) => m.to === "marco@azienda.it" && /accesso d'emergenza/.test(m.text)));
    assert.ok(sentMail.every((m) => !m.text.includes("Cliente Emergenza")), "il nome del cliente non va nelle email");
    assert.ok((await marco.pendingEmergencies()).some((p) => p.containerId === cid && p.userId === state.saraId));
    await assert.rejects(sara.requestEmergency(mine.id), (e: { code?: string }) => e.code === "already_requested");
    // Una designazione con richiesta in corso non si può sovrascrivere senza decidere.
    await assert.rejects(marco.designateEmergency(cid, state.saraId, "manage", 24), (e: { code?: string }) => e.code === "emergency_pending");
    // Rifiuto: niente nuove richieste finché un gestore non la riattiva.
    await marco.rejectEmergency(cid, state.saraId);
    await assert.rejects(sara.requestEmergency(mine.id), (e: { code?: string }) => e.code === "rejected");
    await marco.designateEmergency(cid, state.saraId, "write", 48);
    await sara.requestEmergency(mine.id);
    // Attesa minima di 24 ore imposta dal server.
    await assert.rejects(sara.api.put(`/containers/${cid}/emergency`, { grant: {}, labelEnc: "x", waitHours: 1 }));
    // Una rotazione nel frattempo rinnova la consegna con la nuova chiave.
    await marco.rotate(cid);
    assert.equal((await marco.emergencyDesignations(cid))[0]!.status, "pending");
    await db.query("UPDATE emergency_access SET requested_at = now() - interval '49 hours' WHERE id = $1", [mine.id]);
    // Un permesso alterato sul server invalida la firma: niente accesso.
    await db.query("UPDATE emergency_access SET permission = 'manage' WHERE id = $1", [mine.id]);
    await assert.rejects(sara.claimEmergency(mine.id), (e: { code?: string }) => e.code === "emergency_stale");
    await db.query("UPDATE emergency_access SET permission = 'write' WHERE id = $1", [mine.id]);
    assert.equal(await sara.claimEmergency(mine.id), cid);
    assert.equal((await sara.items(cid)).find((i) => i.id === iid)!.data.password, "Segreto-Emergenza-1!");
    assert.equal((await sara.containers()).find((c) => c.id === cid)!.permission, "write");
    assert.ok(!(await sara.myEmergencyAccess()).some((e) => e.containerId === cid), "la designazione è consumata");
    const log = await marco.auditLog({ containerId: cid });
    for (const a of ["emergency.designated", "emergency.requested", "emergency.rejected", "emergency.granted"]) assert.ok(log.some((l) => l.action === a), a);
    // Approvazione anticipata da un gestore.
    const cid2 = await marco.createContainer({ name: "Cliente Emergenza 2" });
    await marco.designateEmergency(cid2, state.saraId, "read", 72);
    const m2 = (await sara.myEmergencyAccess()).find((e) => e.containerId === cid2)!;
    await sara.requestEmergency(m2.id);
    await marco.approveEmergency(cid2, state.saraId);
    assert.equal((await sara.containers()).find((c) => c.id === cid2)!.permission, "read");
    // Chi viene tolto dal cliente perde la designazione, anche se ne aveva una per un permesso più alto.
    await marco.designateEmergency(cid2, state.saraId, "manage", 24);
    await marco.revoke(cid2, state.saraId);
    assert.equal((await marco.emergencyDesignations(cid2)).length, 0);
    assert.ok(!(await sara.myEmergencyAccess()).some((e) => e.containerId === cid2));
  });

  test("accessi a tempo: scadenza conservata alla rotazione, accesso tolto alla scadenza, chiave da ruotare", async () => {
    const marco: Vault = state.marco;
    const sara: Vault = state.sara;
    await sara.refreshMe();
    const cid = await marco.createContainer({ name: "Cliente a tempo" });
    const in3days = new Date(Date.now() + 3 * 86400_000).toISOString();
    await rejects(marco.share(cid, state.saraId, "manage", { expiresAt: in3days }), "manage_cannot_expire");
    await rejects(marco.share(cid, state.saraId, "read", { expiresAt: new Date(Date.now() - 1000).toISOString() }), "invalid_expiry");
    await marco.share(cid, state.saraId, "read", { expiresAt: in3days });
    const exp = () => marco.members(cid).then((m) => m.find((x) => x.userId === state.saraId)?.expiresAt ?? null);
    assert.equal(new Date((await exp())!).getTime(), new Date(in3days).getTime());
    assert.ok((await sara.containers()).some((c) => c.id === cid));
    // Cambiare il permesso non toglie la scadenza; la rotazione la conserva.
    await marco.share(cid, state.saraId, "write");
    assert.ok(await exp());
    await marco.rotate(cid);
    assert.ok(await exp(), "la scadenza resta dopo la rotazione");
    // Scaduta: niente accesso subito, anche prima della pulizia periodica.
    await db.query("UPDATE container_keys SET expires_at = now() - interval '1 minute' WHERE container_id = $1 AND user_id = $2", [cid, state.saraId]);
    assert.ok(!(await sara.containers()).some((c) => c.id === cid));
    await assert.rejects(sara.items(cid));
    assert.ok(!(await marco.members(cid)).some((m) => m.userId === state.saraId), "non risulta più tra i membri");
    // Pulizia: accesso eliminato, chiave da ruotare, avviso all'interessato, evento nel registro.
    sentMail.length = 0;
    const n = await expireAccess({ db, cfg, mailer: { enabled: true, send: async (to: string, subject: string, text: string) => { sentMail.push({ to, subject, text }); return true; } } } as never);
    assert.equal(n, 1);
    assert.ok(sentMail.some((m) => m.to === "sara@azienda.it" && /scaduto/.test(m.text) && !m.text.includes("Cliente a tempo")));
    assert.ok((await marco.containers()).find((c) => c.id === cid)!.rotationRequired);
    assert.ok((await marco.auditLog({ containerId: cid })).some((l) => l.action === "container.member_expired"));
    const done = await marco.completePendingRotations();
    assert.ok(done.done.includes("Cliente a tempo"));
    // Togliere la scadenza.
    await marco.share(cid, state.saraId, "read", { expiresAt: in3days });
    await marco.share(cid, state.saraId, "read", { expiresAt: null });
    assert.equal(await exp(), null);
  });

  test("avvisi email: tentativi di accesso falliti, codice MFA errato, export e raffica di rapporti", async () => {
    const marco: Vault = state.marco;
    sentMail.length = 0;
    for (let i = 0; i < 6; i++) await assert.rejects(login(api(), "sara@azienda.it", "password sbagliata"));
    const failed = sentMail.filter((m) => m.to === "sara@azienda.it" && m.subject === "Tentativi di accesso non riusciti");
    assert.equal(failed.length, 1, "un solo avviso per raffica");
    assert.ok(!failed[0]!.text.includes("password sbagliata"));
    // Export e rapporti: avvisati gli altri amministratori.
    await marco.setUser(state.saraId, { role: "admin" });
    const cid = await marco.createContainer({ name: "Cliente esportato" });
    sentMail.length = 0;
    await marco.api.post("/audit/events", { action: "container.export", containerId: cid });
    await marco.api.post("/audit/events", { action: "container.export", containerId: cid });
    assert.equal(sentMail.filter((m) => m.to === "sara@azienda.it" && m.subject === "Export dei dati su StartCredentials").length, 1);
    for (let i = 0; i < 6; i++) await marco.api.post("/audit/events", { action: "container.report", containerId: cid });
    assert.equal(sentMail.filter((m) => m.to === "sara@azienda.it" && m.subject === "Molti rapporti generati su StartCredentials").length, 1);
    assert.ok(sentMail.every((m) => !m.text.includes("Cliente esportato")), "niente nomi dei clienti nelle email");
    await marco.setUser(state.saraId, { role: "user" });
  });

  test("notifiche email: nuovo accesso a un cliente e ingresso in un gruppo, senza nomi dei clienti", async () => {
    const marco: Vault = state.marco;
    sentMail.length = 0;
    const cid = await marco.createContainer({ name: "Cliente Segretissimo" });
    await marco.share(cid, state.saraId, "read");
    assert.equal(sentMail.length, 1);
    assert.equal(sentMail[0]!.to, "sara@azienda.it");
    assert.match(sentMail[0]!.text, /Marco Ferri ti ha dato accesso a un cliente/);
    assert.match(sentMail[0]!.text, /sola lettura/);
    assert.ok(!sentMail[0]!.text.includes("Segretissimo"), "il nome del cliente non va nelle email");
    // Cambio di permesso: nessuna nuova email.
    await marco.share(cid, state.saraId, "write");
    assert.equal(sentMail.length, 1);
    const gid = await marco.createGroup("Reperibilità");
    await marco.setGroupMember(gid, state.saraId, "member");
    assert.equal(sentMail.length, 2);
    assert.match(sentMail[1]!.subject, /gruppo Reperibilità/);
  });

  test("dispositivo attendibile: niente codice MFA per 30 giorni, revoca manuale e automatica", async () => {
    const paoloId = (await db.query("SELECT id FROM users WHERE email = 'paolo@azienda.it'")).rows[0].id;
    const a = api();
    assert.equal((await login(a, "paolo@azienda.it", "paolo master password")).state, "mfa_pending");
    await verifyMfa(a, await mfaCode(paoloId));
    const t = await trustDevice(a, "PC di Paolo – Chrome");
    assert.equal(t.days, 30);
    // Stesso dispositivo: basta la master password.
    const b = api();
    const r = await login(b, "paolo@azienda.it", "paolo master password", { deviceToken: t.deviceToken });
    assert.equal(r.state, "active");
    assert.equal(r.trustedDevice, true);
    await Vault.unlock(b, "paolo master password");
    // Password sbagliata: il token non basta.
    await rejects(login(api(), "paolo@azienda.it", "password sbagliata!!", { deviceToken: t.deviceToken }), "invalid_credentials");
    // Token falso o di un altro utente: si chiede il codice.
    assert.equal((await login(api(), "paolo@azienda.it", "paolo master password", { deviceToken: "falso-falso-falso-falso" })).state, "mfa_pending");
    assert.equal((await login(api(), "sara@azienda.it", "nuova password di sara", { deviceToken: t.deviceToken })).state, "mfa_pending");
    // Revoca dalle impostazioni.
    const paolo = await Vault.unlock(b, "paolo master password");
    const list = await paolo.devices();
    assert.equal(list.devices.length, 1);
    await paolo.revokeDevice(list.devices[0]!.id);
    assert.equal((await login(api(), "paolo@azienda.it", "paolo master password", { deviceToken: t.deviceToken })).state, "mfa_pending");
    // Revoca automatica al cambio della master password.
    const t2 = await trustDevice(b, "PC di Paolo – Edge");
    await paolo.changePassword("paolo master password", "paolo password nuova", await mfaCode(paoloId), FAST);
    assert.equal((await login(api(), "paolo@azienda.it", "paolo password nuova", { deviceToken: t2.deviceToken })).state, "mfa_pending");
  });

  test("condivisione di più clienti insieme: colleghi e gruppi, nessun declassamento, revoca con rotazione", async () => {
    const marco: Vault = state.marco;
    await state.sara.refreshMe();
    const paoloId = (await db.query("SELECT id FROM users WHERE email = 'paolo@azienda.it'")).rows[0].id;
    const ids: string[] = [];
    for (const n of ["Blocco Uno", "Blocco Due", "Blocco Tre"]) ids.push(await marco.createContainer({ name: n }));
    await marco.share(ids[0]!, state.saraId, "manage");
    await marco.share(ids[1]!, paoloId, "read");
    const gid = await marco.createGroup("Squadra blocco");
    const progress: number[] = [];
    const r = await marco.shareMany(ids, { userIds: [state.saraId, paoloId], groupIds: [gid] }, "read", { onProgress: (d) => progress.push(d) });
    assert.deepEqual(r.failed, []);
    assert.equal(r.unchanged, 2, "Sara gestore su Uno e Paolo già lettore su Due restano come sono");
    assert.equal(r.done, 7);
    assert.equal(progress.at(-1), 9);
    assert.equal((await marco.members(ids[0]!)).find((m) => m.userId === state.saraId)!.permission, "manage", "nessun declassamento");
    for (const id of ids) {
      assert.ok((await marco.members(id)).some((m) => m.userId === paoloId));
      assert.equal((await marco.containerGroups(id)).length, 1);
    }
    // Con overwrite il permesso viene allineato a quello scelto.
    await marco.shareMany([ids[0]!], { userIds: [state.saraId] }, "write", { overwrite: true });
    assert.equal((await marco.members(ids[0]!)).find((m) => m.userId === state.saraId)!.permission, "write");

    // Revoca in blocco: Paolo esce da tutti e tre, ogni chiave viene ruotata una volta.
    const before: Record<string, number> = Object.fromEntries((await marco.containers()).filter((c) => ids.includes(c.id)).map((c) => [c.id, c.keyVersion]));
    const rv = await marco.revokeMany(ids, { userIds: [paoloId] });
    assert.deepEqual(rv.failed, []);
    assert.equal(rv.done, 3);
    for (const c of (await marco.containers()).filter((x) => ids.includes(x.id))) {
      assert.equal(c.keyVersion, before[c.id]! + 1);
      assert.ok(!(await marco.members(c.id)).some((m) => m.userId === paoloId));
    }
    // Un cliente su cui non si è gestori finisce tra gli errori, senza fermare gli altri.
    const foreign = await (await signIn("sara@azienda.it", "nuova password di sara", state.saraId)).ensurePersonal();
    const mixed = await marco.shareMany([foreign, ids[2]!], { userIds: [paoloId] }, "read");
    assert.equal(mixed.failed.length, 1);
    assert.equal(mixed.done, 1);
  });

  test("regola della master password: pubblicata dal server, applicata dai client", async () => {
    const marco: Vault = state.marco;
    assert.equal((await passwordPolicy(api())).minPasswordLength, 12);
    cfg.minPasswordLength = 24;
    try {
      assert.equal((await passwordPolicy(api())).minPasswordLength, 24);
      const sara = await signIn("sara@azienda.it", "nuova password di sara", state.saraId);
      await rejects(sara.changePassword("nuova password di sara", "lunga ma non abbastanza", await mfaCode(state.saraId), FAST), "password_policy");
      const inv = await marco.invite("breve@azienda.it", "Breve", "user");
      await rejects(register(api(), { token: inv.inviteToken, password: "solo venti caratteri!", kdf: FAST }), "password_policy");
      // L'invito non è stato consumato: con una password adeguata la registrazione riesce.
      const ok = await register(api(), { token: inv.inviteToken, password: "una frase lunga a sufficienza per la regola", kdf: FAST });
      assert.equal(ok.state, "mfa_setup");
    } finally {
      cfg.minPasswordLength = 12;
    }
  });

  test("recupero: collegamento inviato fino a due indirizzi, codice mai per email, avvisi sull'indirizzo principale", async () => {
    const marco: Vault = state.marco;
    const sara = await signIn("sara@azienda.it", "nuova password di sara", state.saraId);
    sentMail.length = 0;
    await rejects(sara.setRecoveryEmail("SARA@azienda.it"), "same_as_primary");
    await sara.setRecoveryEmail("sara.personale@example.org");
    assert.equal(sentMail.length, 1);
    assert.equal(sentMail[0]!.to, "sara@azienda.it");
    assert.match(sentMail[0]!.text, /sara\.personale@example\.org/);
    const listed = (await marco.users()).find((u) => u.id === state.saraId)!;
    assert.equal(listed.recoveryEmail, "sara.personale@example.org");

    // Due indirizzi: principale e di recupero.
    sentMail.length = 0;
    const r = await marco.startRecovery(state.saraId, state.shares.slice(0, 2), FAST, { sendTo: ["sara@azienda.it", "sara.personale@example.org"] });
    assert.deepEqual(r.emailed.sort(), ["sara.personale@example.org", "sara@azienda.it"]);
    assert.equal(sentMail.length, 2);
    for (const m of sentMail) {
      assert.ok(m.text.includes(r.recoveryUrl), "collegamento nell'email");
      assert.ok(!m.text.includes(r.code) && !m.text.includes(r.code.replace(/-/g, "")), "il codice non va mai per email");
    }
    // Solo l'indirizzo di recupero: il principale riceve comunque un avviso.
    sentMail.length = 0;
    await marco.startRecovery(state.saraId, state.shares.slice(0, 2), FAST, { sendTo: ["sara.personale@example.org"] });
    assert.deepEqual(sentMail.map((m) => m.to), ["sara.personale@example.org", "sara@azienda.it"]);
    assert.match(sentMail[1]!.subject, /Avviato il recupero/);
    // Più di due indirizzi: rifiutato dal server.
    await assert.rejects(marco.api.post(`/users/${state.saraId}/recovery`, { blob: { data: "x", kdfParams: {} }, sendTo: ["a@x.it", "b@x.it", "c@x.it"] }));
    const log = await marco.auditLog({ limit: 20 });
    assert.ok(log.some((l) => l.action === "user.recovery_started" && JSON.stringify(l.details).includes("sara.personale@example.org")));
    await sara.setRecoveryEmail(null);
  });

  test("invio sicuro: email con il solo collegamento, codice mai al server, apertura singola, revoca, scadenza, regole", async () => {
    const marco: Vault = state.marco;
    const cid = await marco.createContainer({ name: "Cliente invii" });
    const OTP = "otpauth://totp/Portale?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    await marco.createItem(cid, { type: "login", name: "Portale cliente", username: "admin", password: "Segreta-Davvero-42", urls: ["https://portale.cliente.it"], totpUri: OTP, notes: "nota interna" });
    const item = (await marco.items(cid))[0]!;
    const open = async (token: string) => {
      const r = await fetch(`${base}/api/v1/sends/open`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
      return { status: r.status, body: await r.json() as any };
    };
    sentMail.length = 0;
    const send = await marco.createSecureSend(item, { recipientEmail: "Referente@Cliente.it", expiresInHours: 24, fields: { username: true, password: true, urls: true, otp: true } });
    assert.match(send.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.equal(send.emailed, true);
    const mail = sentMail.find((m) => m.to === "referente@cliente.it")!;
    assert.ok(mail.text.includes(send.link), "collegamento nell'email");
    for (const secret of [send.code, send.code.replace(/-/g, ""), "Segreta-Davvero-42", "GEZDGNBV"]) assert.ok(!mail.text.includes(secret), "nessun segreto nell'email");
    const token = send.link.split("#")[1]!;
    // Nel database solo il pacchetto cifrato.
    const row = (await db.query("SELECT envelope FROM secure_sends WHERE id = $1", [send.id])).rows[0];
    assert.ok(!row.envelope.includes("Segreta-Davvero-42"));

    const first = await open(token);
    assert.equal(first.status, 200);
    assert.equal(first.body.sender, "Marco Ferri");
    assert.equal(first.body.viewsLeft, 0);
    await assert.rejects(decryptSend(first.body.envelope, "AAAA-AAAA-AAAA-AAAA"));
    const data = await decryptSend(first.body.envelope, send.code.toLowerCase());
    assert.equal(data.password, "Segreta-Davvero-42");
    assert.equal(data.username, "admin");
    assert.equal(data.totpUri, OTP);
    assert.equal(data.notes, undefined, "solo i campi scelti");
    // Apertura singola: poi il pacchetto non esiste più, e il mittente viene avvisato.
    assert.equal((await open(token)).status, 404);
    assert.equal((await db.query("SELECT envelope FROM secure_sends WHERE id = $1", [send.id])).rows[0].envelope, null);
    assert.ok(sentMail.some((m) => m.to === "marco@azienda.it" && /aperto/.test(m.subject)));

    // Due aperture, poi revoca.
    const s2 = await marco.createSecureSend(item, { recipientEmail: "a@cliente.it", expiresInHours: 2, maxViews: 2, fields: { password: true } });
    const t2 = s2.link.split("#")[1]!;
    assert.equal((await open(t2)).body.viewsLeft, 1);
    await marco.revokeSecureSend(s2.id);
    assert.equal((await open(t2)).status, 404);
    // Scadenza e pulizia.
    const s3 = await marco.createSecureSend(item, { recipientEmail: "b@cliente.it", expiresInHours: 1, fields: { password: true } });
    await db.query("UPDATE secure_sends SET expires_at = now() - interval '1 minute' WHERE id = $1", [s3.id]);
    assert.equal((await open(s3.link.split("#")[1]!)).status, 404);
    assert.ok(await purgeExpiredSends(db) >= 1);
    const list = await marco.secureSends();
    assert.deepEqual([send.id, s2.id, s3.id].map((id) => list.find((x) => x.id === id)!.status), ["consumed", "revoked", "expired"]);
    await rejects(marco.revokeSecureSend(s2.id), "not_found");

    // Regole dell'amministratore: domini ammessi, durata massima, funzione disattivata.
    cfg.secureSend = { enabled: true, maxHours: 48, domains: ["cliente.it"] };
    try {
      await rejects(marco.createSecureSend(item, { recipientEmail: "x@altro.com", expiresInHours: 1, fields: { password: true } }), "recipient_domain_not_allowed");
      await marco.createSecureSend(item, { recipientEmail: "x@uff.cliente.it", expiresInHours: 1, fields: { password: true } });
      await rejects(marco.createSecureSend(item, { recipientEmail: "x@cliente.it", expiresInHours: 72, fields: { password: true } }), "expiry_too_long");
      cfg.secureSend = { enabled: false, maxHours: 48, domains: [] };
      await rejects(marco.createSecureSend(item, { recipientEmail: "x@cliente.it", expiresInHours: 1, fields: { password: true } }), "secure_send_disabled");
    } finally {
      cfg.secureSend = { enabled: true, maxHours: 168, domains: [] };
    }
    // Chi ha solo la lettura non invia all'esterno.
    await marco.share(cid, state.saraId, "read");
    const sara = await signIn("sara@azienda.it", "nuova password di sara", state.saraId);
    await rejects(sara.createSecureSend((await sara.items(cid))[0]!, { recipientEmail: "x@cliente.it", expiresInHours: 1, fields: { password: true } }), "write_required");
    // Token falsi: nessuna informazione.
    assert.equal((await open("token-inventato-0123456789")).status, 404);
    const log = await marco.auditLog({ limit: 60 });
    for (const a of ["send.created", "send.opened", "send.revoked"]) assert.ok(log.some((l) => l.action === a), `manca ${a}`);

    // Pagina pubblica: script solo dallo stesso server, niente in linea.
    const page = await fetch(`${base}/s`);
    const csp = page.headers.get("content-security-policy") ?? "";
    assert.match(csp, /script-src 'self'/);
    assert.ok(!csp.includes("unsafe"));
    assert.equal(page.headers.get("referrer-policy"), "no-referrer");
    const html = await page.text();
    assert.ok(!/<script>|style=|<style/i.test(html), "nessuno script o stile in linea");
    assert.equal((await fetch(`${base}/send.js?v=x`)).status, 200);
  });

  test("intestazioni di sicurezza: CSP senza eccezioni e cache corretta (rilievi del vulnerability assessment)", async () => {
    for (const path of ["/", "/privacy"]) {
      const r = await fetch(`${base}${path}`);
      assert.equal(r.status, 200);
      const csp = r.headers.get("content-security-policy") ?? "";
      assert.ok(!csp.includes("unsafe-inline") && !csp.includes("unsafe-eval"), `${path}: CSP senza eccezioni`);
      assert.match(csp, /default-src 'none'/);
      assert.match(csp, /style-src 'self'/);
      assert.match(csp, /frame-ancestors 'none'/);
      assert.equal(r.headers.get("cache-control"), "no-store");
      const html = await r.text();
      assert.ok(!/<style|style=|<script/i.test(html), `${path}: nessuno stile o script in linea`);
      for (const ref of html.match(/(?:href|src)="(\/[^"]+)"/g) ?? []) {
        const url = ref.replace(/^(?:href|src)="/, "").replace(/"$/, "");
        if (!url.includes("?v=")) continue;
        const a = await fetch(`${base}${url}`);
        assert.equal(a.status, 200, url);
        assert.equal(a.headers.get("cache-control"), "public, max-age=31536000, immutable", url);
      }
    }
    const api = await fetch(`${base}/api/v1/health`);
    assert.equal(api.headers.get("cache-control"), "no-store");
    assert.match(api.headers.get("strict-transport-security") ?? "", /max-age=63072000/);
    assert.equal(api.headers.get("x-content-type-options"), "nosniff");
  });

  test("sospensione e registro di audit a prova di manomissione", async () => {
    const marco: Vault = state.marco;
    await marco.setUser(state.lauraId, { status: "suspended" });
    await rejects(state.laura.api.get("/containers"), "unauthorized");
    await marco.setUser(state.lauraId, { status: "active" });
    const log = await marco.auditLog({ limit: 500 });
    for (const action of ["org.initialized", "user.key_certified", "container.key_rotated", "container.imported", "user.recovery_completed", "auth.login_failed",
                          "auth.mfa_backup_used", "user.mfa_reset", "user.password_changed", "user.offboarded", "container.export",
                          "group.created", "group.member_set", "group.member_removed", "group.key_rotated", "container.group_set", "org.key_rotated",
                          "item.shared", "item.unshared", "item.rekeyed", "auth.device_trusted", "auth.device_revoked"]) {
      assert.ok(log.some((l) => l.action === action), `manca ${action}`);
    }
    assert.equal((await marco.verifyAudit()).ok, true);
    // Conservazione: le righe più vecchie spariscono, la catena resta verificabile dall'ancora.
    const total = Number((await db.query("SELECT count(*) AS n FROM audit_log")).rows[0].n);
    const cut = (await db.query("SELECT at FROM audit_log ORDER BY id OFFSET $1 LIMIT 1", [Math.floor(total / 2)])).rows[0].at;
    const pruned = await pruneAudit(db, new Date(cut));
    assert.ok(pruned > 0 && pruned < total);
    const after = await marco.verifyAudit();
    assert.equal(after.ok, true);
    assert.ok(after.prunedUpTo);
    assert.ok((await marco.auditLog({ limit: 5 })).some((l) => l.action === "audit.pruned"));
    for (const n of ["Dopo la pulizia 1", "Dopo la pulizia 2"]) await marco.createContainer({ name: n });
    assert.equal((await marco.verifyAudit()).ok, true);
    await db.query("UPDATE audit_log SET details = '{\"falso\":true}' WHERE id = (SELECT min(id) + 3 FROM audit_log)");
    const v = await marco.verifyAudit();
    assert.equal(v.ok, false);
    assert.ok(v.brokenAt);
  });
});

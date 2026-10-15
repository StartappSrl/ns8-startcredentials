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
  login, passwordHealth, register, SecurityError, serverStatus, setupMfa, Vault, verifyMfa,
} from "@startcredentials/client";
import { Config, createPool, Db, migrate, totpAt } from "../src/core.js";
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
  await assert.rejects(p, (e: unknown) => (e instanceof ApiError && e.code === code) || (e instanceof SecurityError && code === "security"));
}

const state: Record<string, any> = {};

before(async () => {
  db = createPool(DB_URL);
  await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await migrate(db, join(APP_ROOT, "migrations"));
  app = await buildApp(cfg, db);
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
    const solo = await laura.createContainer({ name: "Cliente solo di Laura" });
    await laura.createItem(solo, { type: "login", name: "z", password: "w" });
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
    const exp = await marco.exportEncrypted("passphrase export lunga", FAST);
    assert.ok(!exp.file.includes("Stessa-Password"), "l'export deve essere cifrato");
    assert.ok(exp.items >= 4);
    await assert.rejects(decryptExport(exp.file, "passphrase sbagliata!!"), SecurityError);
    const res = await importStartCredentials(exp.file, "passphrase export lunga");
    assert.equal(res.items.length, exp.items);
    assert.ok(res.folders.some((f) => f.name === "Studio Legale Moretti"));
    const target = await marco.createContainer({ name: "Ripristino export" });
    await importInto(marco, target, res);
    assert.equal((await marco.items(target)).length, exp.items);

    const entries = [];
    for (const c of await marco.containers()) for (const item of await marco.items(c.id)) entries.push({ container: c, item });
    const h = passwordHealth(entries);
    assert.ok(h.weak.some((e) => e.item.data.name === "Debole"));
    assert.ok(h.reused.some((g) => g.some((e) => e.item.data.name === "Ripetuta 1")));
    assert.ok(h.missingOtp.some((e) => e.item.data.name === "Debole"));
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
    const ro = await sara.createContainer({ name: "Solo Lettura Spa" });
    await sara.share(ro, state.marcoId, "read");
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
    assert.equal((await sara.items(ro)).length, 0, "nessun elemento nel cliente in sola lettura");

    // Secondo import identico: niente doppioni, nessun cliente nuovo.
    const again = await importAsClients(marco, importCsv(csv, "passbolt"), { looseContainerId: personal });
    assert.deepEqual(again.created, []);
    assert.equal(again.imported, 0);
    assert.equal(again.duplicates, 4);
    assert.equal((await marco.items(rossi)).length, 2);
  });

  test("sospensione e registro di audit a prova di manomissione", async () => {
    const marco: Vault = state.marco;
    await marco.setUser(state.lauraId, { status: "suspended" });
    await rejects(state.laura.api.get("/containers"), "unauthorized");
    await marco.setUser(state.lauraId, { status: "active" });
    const log = await marco.auditLog();
    for (const action of ["org.initialized", "user.key_certified", "container.key_rotated", "container.imported", "user.recovery_completed", "auth.login_failed",
                          "auth.mfa_backup_used", "user.mfa_reset", "user.password_changed", "user.offboarded", "container.export",
                          "group.created", "group.member_set", "group.member_removed", "group.key_rotated", "container.group_set"]) {
      assert.ok(log.some((l) => l.action === action), `manca ${action}`);
    }
    assert.equal((await marco.verifyAudit()).ok, true);
    await db.query("UPDATE audit_log SET details = '{\"falso\":true}' WHERE id = (SELECT min(id) + 3 FROM audit_log)");
    const v = await marco.verifyAudit();
    assert.equal(v.ok, false);
    assert.ok(v.brokenAt);
  });
});

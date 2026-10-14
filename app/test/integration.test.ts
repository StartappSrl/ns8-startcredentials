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
  Api, ApiError, completeRecovery, enableMfa, importBitwarden, importCsv, importInto, login, register,
  SecurityError, serverStatus, setupMfa, Vault, verifyMfa,
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

async function onboard(a: Api, userId: string) {
  const setup = await setupMfa(a);
  assert.match(setup.otpauthUri, /^otpauth:\/\/totp\//);
  await enableMfa(a, totpAt(setup.secret, Math.floor(Date.now() / 30000)));
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

  test("sospensione e registro di audit a prova di manomissione", async () => {
    const marco: Vault = state.marco;
    await marco.setUser(state.lauraId, { status: "suspended" });
    await rejects(state.laura.api.get("/containers"), "unauthorized");
    await marco.setUser(state.lauraId, { status: "active" });
    const log = await marco.auditLog();
    for (const action of ["org.initialized", "user.key_certified", "container.key_rotated", "container.imported", "user.recovery_completed", "auth.login_failed"]) {
      assert.ok(log.some((l) => l.action === action), `manca ${action}`);
    }
    assert.equal((await marco.verifyAudit()).ok, true);
    await db.query("UPDATE audit_log SET details = '{\"falso\":true}' WHERE id = (SELECT min(id) + 3 FROM audit_log)");
    const v = await marco.verifyAudit();
    assert.equal(v.ok, false);
    assert.ok(v.brokenAt);
  });
});

import { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { CryptoError, orgRotationMessage, verify, verifyGroupCert, verifyUserCertification } from "@startcredentials/crypto";
import { audit, badRequest, conflict, forbidden, HttpError, newToken, notFound, tokenHash, tx, verifyAuditChain } from "../core.js";
import { Ctx, requireAdmin, requireAuth } from "../server.js";
import { schemas } from "./auth.js";
import { ACCESSIBLE_CONTAINERS, insertGrant, grantSchema, permissionOf } from "./containers.js";
import * as opaque from "@serenity-kit/opaque";
import { newBackupCodes, verifySecondFactor } from "./auth.js";

const { b64, envelope, kdfParams } = schemas;

export async function userRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db, cfg } = ctx;

  app.get("/api/v1/me", async (req) => {
    const a = requireAuth(req);
    const r = await db.query(
      `SELECT u.id, u.email, u.display_name, u.role, u.key_version,
              k.box_public, k.sign_public, k.private_enc, k.kdf_params, k.certification, (k.recovery_enc IS NOT NULL) AS has_recovery
         FROM users u JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version
        WHERE u.id = $1`, [a.id]);
    const u = r.rows[0];
    const org = await db.query("SELECT sign_public, recovery_public, container_id, key_version FROM org WHERE id = 1");
    const rotations = await db.query("SELECT version, old_sign_public, new_sign_public, new_recovery_public, signature FROM org_rotations ORDER BY version");
    return {
      id: u.id, email: u.email, displayName: u.display_name, role: u.role,
      keyVersion: u.key_version,
      publicKeys: { box: u.box_public, sign: u.sign_public },
      privateEnc: u.private_enc, kdfParams: u.kdf_params,
      certification: u.certification, hasRecovery: u.has_recovery,
      org: org.rows[0] ? {
        signPublic: org.rows[0].sign_public, recoveryPublic: org.rows[0].recovery_public, keyVersion: org.rows[0].key_version,
        containerId: u.role === "admin" ? org.rows[0].container_id : undefined,
        rotations: rotations.rows.map((r) => ({
          version: r.version, oldSignPublic: r.old_sign_public, newSignPublic: r.new_sign_public, newRecoveryPublic: r.new_recovery_public, signature: r.signature,
        })),
      } : null,
    };
  });

  app.put("/api/v1/me/recovery", async (req) => {
    const a = requireAuth(req);
    const { recoveryEnc } = z.object({ recoveryEnc: b64 }).parse(req.body);
    await db.query("UPDATE user_keys k SET recovery_enc = $2 FROM users u WHERE u.id = $1 AND k.user_id = u.id AND k.version = u.key_version", [a.id, recoveryEnc]);
    return { ok: true };
  });

  // ------------------------------------------------------------ cambio master password

  // Il client ha già verificato la vecchia password aprendo le proprie chiavi;
  // qui registra le nuove credenziali OPAQUE e la nuova copia cifrata delle chiavi.
  app.post("/api/v1/me/password/start", async (req) => {
    const a = requireAuth(req);
    const { registrationRequest } = z.object({ registrationRequest: b64 }).parse(req.body);
    ctx.keyLimiter.check(`pw:${a.id}`);
    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: ctx.serverSetup, userIdentifier: a.id, registrationRequest,
    });
    return { registrationResponse };
  });

  app.post("/api/v1/me/password/finish", async (req) => {
    const a = requireAuth(req);
    const body = z.object({ registrationRecord: b64, privateEnc: envelope, kdfParams, code: z.string().max(20) }).parse(req.body);
    ctx.keyLimiter.check(`pw:${a.id}`);
    return tx(db, async (c) => {
      // Una sessione rubata non basta: serve anche il secondo fattore.
      if (!(await verifySecondFactor(c, ctx, a.id, body.code))) throw badRequest("invalid_code");
      const u = await c.query("SELECT key_version FROM users WHERE id = $1", [a.id]);
      await c.query("UPDATE user_keys SET private_enc = $3, kdf_params = $4 WHERE user_id = $1 AND version = $2",
        [a.id, u.rows[0].key_version, body.privateEnc, body.kdfParams]);
      await c.query("UPDATE users SET opaque_record = $2 WHERE id = $1", [a.id, body.registrationRecord]);
      const r = await c.query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2", [a.id, a.sessionId]);
      await c.query("UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [a.id]);
      await audit(c, { actorId: a.id, action: "user.password_changed", targetType: "user", targetId: a.id, ip: req.ip, details: { sessionsClosed: r.rowCount } });
      return { ok: true, sessionsClosed: r.rowCount };
    });
  });

  app.post("/api/v1/me/mfa/backup-codes", async (req) => {
    const a = requireAuth(req);
    const { code } = z.object({ code: z.string().max(20) }).parse(req.body);
    ctx.keyLimiter.check(`mfa:${a.id}`);
    return tx(db, async (c) => {
      if (!(await verifySecondFactor(c, ctx, a.id, code))) throw badRequest("invalid_code");
      const backup = newBackupCodes(ctx);
      await c.query("UPDATE users SET mfa_backup_codes = $2 WHERE id = $1", [a.id, JSON.stringify(backup.hashes)]);
      await audit(c, { actorId: a.id, action: "auth.mfa_backup_regenerated", ip: req.ip });
      return { backupCodes: backup.codes };
    });
  });

  app.get("/api/v1/me/mfa", async (req) => {
    const a = requireAuth(req);
    const r = await db.query("SELECT mfa_backup_codes FROM users WHERE id = $1", [a.id]);
    return { backupCodesRemaining: (r.rows[0]?.mfa_backup_codes ?? []).length };
  });

  // Rubrica: chiavi pubbliche e certificazioni per poter condividere.
  app.get("/api/v1/users/directory", async (req) => {
    requireAuth(req);
    // Anche gli utenti sospesi: servono a verificare le firme delle consegne che hanno fatto.
    const r = await db.query(
      `SELECT u.id, u.email, u.display_name, u.role, u.status, u.key_version, k.box_public, k.sign_public, k.certification
         FROM users u JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version
        WHERE u.status IN ('active', 'suspended') ORDER BY u.display_name`);
    return r.rows.map((u) => ({
      id: u.id, email: u.email, displayName: u.display_name, role: u.role, status: u.status, keyVersion: u.key_version,
      publicKeys: { box: u.box_public, sign: u.sign_public }, certification: u.certification,
    }));
  });

  app.get("/api/v1/users", async (req) => {
    requireAdmin(req);
    const r = await db.query(
      `SELECT u.id, u.email, u.display_name, u.role, u.status, u.mfa_enabled, u.created_at, u.key_version,
              k.box_public, k.sign_public, k.certification, (k.recovery_enc IS NOT NULL) AS has_recovery,
              (u.recovery_token_hash IS NOT NULL AND u.recovery_expires_at > now()) AS recovery_pending
         FROM users u LEFT JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version
        ORDER BY u.display_name`);
    return r.rows.map((u) => ({
      id: u.id, email: u.email, displayName: u.display_name, role: u.role, status: u.status,
      mfaEnabled: u.mfa_enabled, createdAt: u.created_at, keyVersion: u.key_version,
      publicKeys: u.box_public ? { box: u.box_public, sign: u.sign_public } : null,
      certified: !!u.certification, hasRecovery: u.has_recovery, recoveryPending: u.recovery_pending,
    }));
  });

  app.post("/api/v1/users/invite", async (req) => {
    const a = requireAdmin(req);
    const body = z.object({ email: z.string().email().max(200), displayName: z.string().min(1).max(100), role: z.enum(["admin", "user"]) }).parse(req.body);
    const token = newToken();
    const userId = await tx(db, async (c) => {
      const ex = await c.query("SELECT id, status FROM users WHERE lower(email) = lower($1)", [body.email]);
      let id: string;
      if (ex.rows[0]) {
        if (ex.rows[0].status !== "invited") throw conflict("email_taken");
        id = ex.rows[0].id;
        await c.query("UPDATE users SET display_name = $2, role = $3, invite_token_hash = $4, invite_expires_at = now() + interval '72 hours' WHERE id = $1",
          [id, body.displayName, body.role, tokenHash(cfg, token)]);
      } else {
        id = randomUUID();
        await c.query(
          `INSERT INTO users (id, email, display_name, role, status, invite_token_hash, invite_expires_at)
           VALUES ($1,$2,$3,$4,'invited',$5, now() + interval '72 hours')`,
          [id, body.email, body.displayName, body.role, tokenHash(cfg, token)]);
      }
      await audit(c, { actorId: a.id, action: "user.invited", targetType: "user", targetId: id, ip: req.ip, details: { email: body.email, role: body.role } });
      return id;
    });
    const inviteUrl = `${cfg.publicUrl}/#invite=${token}`;
    const emailed = await ctx.mailer.send(body.email, "Invito a StartCredentials",
      `Sei stato invitato a StartCredentials.\n\nInstalla l'estensione per Chrome o Edge, poi apri questo collegamento entro 72 ore:\n${inviteUrl}\n\nCodice di invito: ${token}\n`);
    return { userId, inviteToken: token, inviteUrl, emailed };
  });

  app.patch("/api/v1/users/:id", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const body = z.object({ status: z.enum(["active", "suspended"]).optional(), role: z.enum(["admin", "user"]).optional() }).parse(req.body);
    if (id === a.id) throw forbidden("cannot_modify_self");
    return tx(db, async (c) => {
      const u = await c.query("SELECT status FROM users WHERE id = $1 FOR UPDATE", [id]);
      if (!u.rows[0]) throw notFound();
      if (u.rows[0].status === "invited") throw conflict("user_not_registered");
      if (body.status) await c.query("UPDATE users SET status = $2 WHERE id = $1", [id, body.status]);
      if (body.role) await c.query("UPDATE users SET role = $2 WHERE id = $1", [id, body.role]);
      if (body.status === "suspended" || body.role === "user") await c.query("DELETE FROM sessions WHERE user_id = $1", [id]);
      if (body.role === "user") {
        // Un ex amministratore perde l'accesso alla chiave dell'organizzazione.
        await c.query("DELETE FROM container_keys WHERE user_id = $1 AND container_id = (SELECT container_id FROM org WHERE id = 1)", [id]);
      }
      await audit(c, { actorId: a.id, action: "user.updated", targetType: "user", targetId: id, ip: req.ip, details: body });
      return { ok: true };
    });
  });

  app.post("/api/v1/users/:id/certify", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const body = z.object({ keyVersion: z.number().int().min(1), certification: b64 }).parse(req.body);
    return tx(db, async (c) => {
      const org = await c.query("SELECT sign_public FROM org WHERE id = 1");
      if (!org.rows[0]) throw conflict("org_not_initialized");
      const k = await c.query("SELECT box_public, sign_public FROM user_keys WHERE user_id = $1 AND version = $2", [id, body.keyVersion]);
      if (!k.rows[0]) throw notFound();
      try {
        verifyUserCertification(id, body.keyVersion, { box: k.rows[0].box_public, sign: k.rows[0].sign_public }, body.certification, org.rows[0].sign_public);
      } catch (e) {
        if (e instanceof CryptoError) throw badRequest("invalid_certification");
        throw e;
      }
      await c.query("UPDATE user_keys SET certification = $3, certified_by = $4 WHERE user_id = $1 AND version = $2", [id, body.keyVersion, body.certification, a.id]);
      await audit(c, { actorId: a.id, action: "user.key_certified", targetType: "user", targetId: id, ip: req.ip, details: { keyVersion: body.keyVersion } });
      return { ok: true };
    });
  });

  // ------------------------------------------------------------ MFA e uscita (lato admin)

  /** Telefono perso: azzera il secondo fattore; al prossimo accesso l'utente lo riconfigura. */
  app.post("/api/v1/users/:id/mfa-reset", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    if (id === a.id) throw forbidden("cannot_modify_self");
    return tx(db, async (c) => {
      const r = await c.query(
        "UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL, mfa_backup_codes = NULL, mfa_last_counter = 0 WHERE id = $1 AND status = 'active' RETURNING id", [id]);
      if (!r.rows[0]) throw notFound();
      await c.query("DELETE FROM sessions WHERE user_id = $1", [id]);
      await c.query("UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [id]);
      await audit(c, { actorId: a.id, action: "user.mfa_reset", targetType: "user", targetId: id, ip: req.ip });
      return { ok: true };
    });
  });

  /**
   * Uscita di un collega: sospende l'account, chiude le sessioni ed elimina
   * subito tutte le sue chiavi dei contenitori. Le chiavi vanno poi ruotate:
   * il server non può farlo (non le conosce), quindi segna i contenitori e
   * il primo gestore che apre la cassaforte completa la rotazione.
   */
  app.post("/api/v1/users/:id/offboard", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const { force } = z.object({ force: z.boolean().default(false) }).parse(req.body ?? {});
    if (id === a.id) throw forbidden("cannot_modify_self");
    return tx(db, async (c) => {
      const u = await c.query("SELECT status FROM users WHERE id = $1 FOR UPDATE", [id]);
      if (!u.rows[0]) throw notFound();
      // Contenitori condivisi in cui l'utente era l'unico gestore: segnalati, non bloccati.
      const orphan = await c.query(
        `SELECT k.container_id FROM container_keys k JOIN containers ct ON ct.id = k.container_id AND ct.key_version = k.key_version
          WHERE k.user_id = $1 AND k.permission = 'manage' AND ct.kind <> 'personal' AND ct.deleted_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM container_keys o WHERE o.container_id = k.container_id AND o.key_version = ct.key_version
                            AND o.user_id <> $1 AND o.permission = 'manage')`, [id]);
      if (orphan.rowCount && !force) {
        throw new HttpError(409, "containers_without_manager",
          `${orphan.rowCount} clienti hanno questa persona come unico gestore: nomina prima un altro gestore, oppure conferma per renderli non più gestibili`);
      }
      const touched = await c.query(
        `UPDATE containers SET rotation_required = true
          WHERE kind <> 'personal' AND id IN (SELECT container_id FROM container_keys WHERE user_id = $1) RETURNING id`, [id]);
      await c.query("DELETE FROM container_keys k USING containers ct WHERE k.container_id = ct.id AND ct.kind <> 'personal' AND k.user_id = $1", [id]);
      // Gruppi: la sua copia della chiave del gruppo sparisce; gruppo e clienti condivisi col gruppo vanno ruotati.
      const groups = await c.query("WITH d AS (DELETE FROM group_members WHERE user_id = $1 RETURNING group_id) SELECT DISTINCT group_id FROM d", [id]);
      const groupIds = [...new Set(groups.rows.map((g) => g.group_id as string))];
      if (groupIds.length) {
        await c.query("UPDATE groups SET rotation_required = true WHERE id = ANY($1::uuid[])", [groupIds]);
        await c.query(
          `UPDATE containers SET rotation_required = true WHERE id IN (
             SELECT gk.container_id FROM container_group_keys gk WHERE gk.group_id = ANY($1::uuid[]))`, [groupIds]);
      }
      await c.query("UPDATE users SET status = 'suspended', role = 'user' WHERE id = $1", [id]);
      await c.query("UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [id]);
      await c.query("DELETE FROM sessions WHERE user_id = $1", [id]);
      await audit(c, { actorId: a.id, action: "user.offboarded", targetType: "user", targetId: id, ip: req.ip,
        details: { containers: touched.rowCount, withoutManager: orphan.rowCount } });
      return { containers: touched.rowCount, withoutManager: orphan.rows.map((r) => r.container_id) };
    });
  });

  // ------------------------------------------------------------ recupero (lato admin)

  app.get("/api/v1/users/:id/recovery-material", async (req) => {
    requireAdmin(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const r = await db.query(
      `SELECT u.key_version, k.recovery_enc, k.box_public, k.sign_public FROM users u
         JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = $1 AND u.status = 'active'`, [id]);
    if (!r.rows[0]?.recovery_enc) throw notFound("no_recovery_material");
    return { keyVersion: r.rows[0].key_version, recoveryEnc: r.rows[0].recovery_enc, publicKeys: { box: r.rows[0].box_public, sign: r.rows[0].sign_public } };
  });

  app.post("/api/v1/users/:id/recovery", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const body = z.object({ blob: z.object({ data: envelope, kdfParams }) }).parse(req.body);
    if (id === a.id) throw forbidden("cannot_recover_self");
    const token = newToken();
    await tx(db, async (c) => {
      const u = await c.query(
        "UPDATE users SET recovery_token_hash = $2, recovery_blob = $3, recovery_expires_at = now() + interval '24 hours' WHERE id = $1 AND status = 'active' RETURNING id",
        [id, tokenHash(cfg, token), body.blob]);
      if (!u.rows[0]) throw notFound();
      await audit(c, { actorId: a.id, action: "user.recovery_started", targetType: "user", targetId: id, ip: req.ip });
    });
    return { recoveryToken: token, recoveryUrl: `${cfg.publicUrl}/#recover=${token}` };
  });

  // ------------------------------------------------------------ organizzazione

  app.get("/api/v1/org", async (req) => {
    const a = requireAuth(req);
    const r = await db.query("SELECT * FROM org WHERE id = 1");
    const o = r.rows[0];
    if (!o) return { initialized: false };
    return {
      initialized: true, signPublic: o.sign_public, recoveryPublic: o.recovery_public,
      recoveryThreshold: o.recovery_threshold, recoveryShares: o.recovery_shares,
      containerId: a.role === "admin" ? o.container_id : undefined,
    };
  });

  app.post("/api/v1/org/init", async (req) => {
    const a = requireAdmin(req);
    const body = z.object({
      signPublic: b64,
      recoveryPublic: b64,
      recoveryThreshold: z.number().int().min(1).max(10),
      recoveryShares: z.number().int().min(1).max(10),
      container: z.object({ id: z.string().uuid(), metaKeyEnc: envelope, metaEnc: envelope, grant: grantSchema }),
      item: z.object({ id: z.string().uuid(), ikEnc: envelope, dataEnc: envelope }),
      selfCertification: z.object({ keyVersion: z.number().int().min(1), certification: b64 }),
    }).parse(req.body);
    if (body.recoveryThreshold > body.recoveryShares) throw badRequest("invalid_threshold");
    return tx(db, async (c) => {
      await c.query("LOCK TABLE org IN EXCLUSIVE MODE");
      if ((await c.query("SELECT 1 FROM org")).rowCount) throw conflict("org_already_initialized");
      const k = await c.query("SELECT box_public, sign_public FROM user_keys WHERE user_id = $1 AND version = $2", [a.id, body.selfCertification.keyVersion]);
      try {
        verifyUserCertification(a.id, body.selfCertification.keyVersion, { box: k.rows[0].box_public, sign: k.rows[0].sign_public }, body.selfCertification.certification, body.signPublic);
      } catch {
        throw badRequest("invalid_certification");
      }
      await c.query("UPDATE user_keys SET certification = $3, certified_by = $1 WHERE user_id = $1 AND version = $2", [a.id, body.selfCertification.keyVersion, body.selfCertification.certification]);
      await c.query("INSERT INTO containers (id, kind, meta_key_enc, meta_enc, key_version, created_by) VALUES ($1,'org',$2,$3,1,$4)",
        [body.container.id, body.container.metaKeyEnc, body.container.metaEnc, a.id]);
      if (body.container.grant.containerId !== body.container.id || body.container.grant.recipientId !== a.id || body.container.grant.permission !== "manage") {
        throw badRequest("invalid_grant");
      }
      await insertGrant(c, body.container.grant, a.id);
      await c.query(
        `INSERT INTO items (id, container_id, type, ik_enc, ik_key_version, data_enc, created_by, updated_by)
         VALUES ($1,$2,'note',$3,1,$4,$5,$5)`, [body.item.id, body.container.id, body.item.ikEnc, body.item.dataEnc, a.id]);
      await c.query(
        `INSERT INTO org (id, sign_public, recovery_public, recovery_threshold, recovery_shares, container_id, created_by)
         VALUES (1,$1,$2,$3,$4,$5,$6)`,
        [body.signPublic, body.recoveryPublic, body.recoveryThreshold, body.recoveryShares, body.container.id, a.id]);
      await audit(c, { actorId: a.id, action: "org.initialized", ip: req.ip, details: { threshold: body.recoveryThreshold, shares: body.recoveryShares } });
      return { ok: true };
    });
  });

  /**
   * Rotazione della chiave dell'organizzazione (es. dopo l'uscita di un
   * amministratore). Firmata con la chiave attuale; ricertifica in blocco
   * utenti e gruppi e aggiorna la chiave privata custodita nel contenitore
   * dell'organizzazione. Le copie di recupero vengono azzerate: ogni client le
   * rigenera con la nuova chiave di recupero al successivo sblocco.
   */
  app.post("/api/v1/org/rotate", async (req) => {
    const a = requireAdmin(req);
    const body = z.object({
      newSignPublic: b64,
      newRecoveryPublic: b64,
      recoveryThreshold: z.number().int().min(1).max(10),
      recoveryShares: z.number().int().min(1).max(10),
      signature: b64,
      certifications: z.array(z.object({ userId: z.string().uuid(), keyVersion: z.number().int().min(1), certification: b64 })).max(10_000),
      groupCertifications: z.array(z.object({ groupId: z.string().uuid(), keyVersion: z.number().int().min(1), certification: b64 })).max(10_000),
      orgItem: z.object({ id: z.string().uuid(), revision: z.number().int().min(1), dataEnc: envelope }),
    }).parse(req.body);
    if (body.recoveryThreshold > body.recoveryShares) throw badRequest("invalid_threshold");
    return tx(db, async (c) => {
      await c.query("LOCK TABLE org IN EXCLUSIVE MODE");
      const o = (await c.query("SELECT * FROM org WHERE id = 1")).rows[0];
      if (!o) throw conflict("org_not_initialized");
      const version = o.key_version + 1;
      const rotation = { version, oldSignPublic: o.sign_public, newSignPublic: body.newSignPublic, newRecoveryPublic: body.newRecoveryPublic };
      if (!verify(orgRotationMessage(rotation), body.signature, o.sign_public)) throw badRequest("invalid_rotation_signature");

      // Tutti gli utenti oggi certificati vanno ricertificati con la nuova chiave.
      const certified = await c.query(
        `SELECT k.user_id, k.version, k.box_public, k.sign_public FROM users u
           JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE k.certification IS NOT NULL`);
      if (certified.rowCount !== body.certifications.length) throw badRequest("certifications_must_match");
      for (const cert of body.certifications) {
        const k = certified.rows.find((r) => r.user_id === cert.userId && r.version === cert.keyVersion);
        if (!k) throw badRequest("certifications_must_match");
        try {
          verifyUserCertification(cert.userId, cert.keyVersion, { box: k.box_public, sign: k.sign_public }, cert.certification, body.newSignPublic);
        } catch {
          throw badRequest("invalid_certification");
        }
        await c.query("UPDATE user_keys SET certification = $3, certified_by = $4 WHERE user_id = $1 AND version = $2", [cert.userId, cert.keyVersion, cert.certification, a.id]);
      }
      const groups = await c.query("SELECT id, key_version, box_public FROM groups WHERE deleted_at IS NULL");
      if (groups.rowCount !== body.groupCertifications.length) throw badRequest("group_certifications_must_match");
      for (const gc of body.groupCertifications) {
        const g = groups.rows.find((r) => r.id === gc.groupId && r.key_version === gc.keyVersion);
        if (!g) throw badRequest("group_certifications_must_match");
        try {
          verifyGroupCert(gc.groupId, gc.keyVersion, g.box_public, gc.certification, body.newSignPublic);
        } catch {
          throw badRequest("invalid_group_certification");
        }
        await c.query("UPDATE groups SET certification = $2 WHERE id = $1", [gc.groupId, gc.certification]);
      }
      // Nuova chiave privata nel contenitore dell'organizzazione, senza conservare la versione precedente.
      const item = await c.query("SELECT revision FROM items WHERE id = $1 AND container_id = $2 FOR UPDATE", [body.orgItem.id, o.container_id]);
      if (!item.rows[0]) throw badRequest("org_item_not_found");
      if (item.rows[0].revision !== body.orgItem.revision) throw conflict("revision_conflict");
      await c.query("UPDATE items SET data_enc = $2, revision = revision + 1, updated_by = $3, updated_at = now() WHERE id = $1", [body.orgItem.id, body.orgItem.dataEnc, a.id]);
      await c.query("DELETE FROM item_versions WHERE item_id = $1", [body.orgItem.id]);

      await c.query(
        "UPDATE org SET sign_public = $1, recovery_public = $2, recovery_threshold = $3, recovery_shares = $4, key_version = $5 WHERE id = 1",
        [body.newSignPublic, body.newRecoveryPublic, body.recoveryThreshold, body.recoveryShares, version]);
      await c.query(
        "INSERT INTO org_rotations (version, old_sign_public, new_sign_public, new_recovery_public, signature, rotated_by) VALUES ($1,$2,$3,$4,$5,$6)",
        [version, o.sign_public, body.newSignPublic, body.newRecoveryPublic, body.signature, a.id]);
      await c.query("UPDATE user_keys SET recovery_enc = NULL");
      await audit(c, { actorId: a.id, action: "org.key_rotated", ip: req.ip, details: { keyVersion: version, users: body.certifications.length, groups: body.groupCertifications.length } });
      return { ok: true, keyVersion: version };
    });
  });

  // ------------------------------------------------------------ audit

  app.get("/api/v1/audit", async (req) => {
    const a = requireAuth(req);
    const q = z.object({
      containerId: z.string().uuid().optional(),
      before: z.coerce.number().int().optional(),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }).parse(req.query);
    if (a.role !== "admin") {
      if (!q.containerId) throw forbidden("admin_required");
      const p = await permissionOf(db, q.containerId, a.id);
      if (p?.permission !== "manage") throw forbidden();
    }
    const r = await db.query(
      `SELECT l.id, l.at, l.actor_id, u.display_name AS actor_name, l.action, l.target_type, l.target_id, l.container_id, l.ip, l.details
         FROM audit_log l LEFT JOIN users u ON u.id = l.actor_id
        WHERE ($1::uuid IS NULL OR l.container_id = $1) AND ($2::bigint IS NULL OR l.id < $2)
        ORDER BY l.id DESC LIMIT $3`, [q.containerId ?? null, q.before ?? null, q.limit]);
    return r.rows.map((l) => ({
      id: Number(l.id), at: l.at, actorId: l.actor_id, actorName: l.actor_name, action: l.action,
      targetType: l.target_type, targetId: l.target_id, containerId: l.container_id, ip: l.ip, details: l.details,
    }));
  });

  /**
   * Cambiamenti dopo l'evento `since`, limitati ai contenitori visibili all'utente
   * (o in cui ha appena ricevuto o perso l'accesso). Il client lo interroga
   * periodicamente per aggiornare le viste senza ricaricare.
   */
  app.get("/api/v1/changes", async (req) => {
    const a = requireAuth(req);
    const { since } = z.object({ since: z.coerce.number().int().min(0).default(0) }).parse(req.query);
    const latest = Number((await db.query("SELECT coalesce(max(id), 0) AS id FROM audit_log")).rows[0].id);
    if (!since) return { latest, containers: [], membership: false };
    const r = await db.query(
      `SELECT DISTINCT l.container_id FROM audit_log l
        WHERE l.id > $2 AND l.container_id IS NOT NULL
          AND (l.container_id IN (${ACCESSIBLE_CONTAINERS}) OR (l.target_type = 'user' AND l.target_id = $1::text))
        LIMIT 500`, [a.id, since]);
    // Accessi ricevuti o tolti (anche tramite gruppo): serve ricaricare l'elenco dei clienti.
    const m = await db.query(
      `SELECT 1 FROM audit_log WHERE id > $2 AND (
         (target_type = 'user' AND target_id = $1::text) OR action IN ('container.group_set', 'container.group_removed', 'group.key_rotated', 'group.deleted', 'org.key_rotated')
       ) LIMIT 1`, [a.id, since]);
    return { latest, containers: r.rows.map((x) => x.container_id as string), membership: !!m.rowCount };
  });

  app.get("/api/v1/audit/verify", async (req) => {
    requireAdmin(req);
    return verifyAuditChain(db);
  });

  // Eventi che avvengono solo sul client (mostra, copia, compila) vengono registrati qui.
  app.post("/api/v1/audit/events", async (req) => {
    const a = requireAuth(req);
    const body = z.object({ action: z.enum(["item.reveal", "item.copy", "item.fill", "item.totp_copy", "container.export"]), itemId: z.string().uuid().optional(), containerId: z.string().uuid() }).parse(req.body);
    const p = await permissionOf(db, body.containerId, a.id);
    const viaShare = !p && body.itemId
      ? (await db.query("SELECT 1 FROM item_shares sh JOIN items i ON i.id = sh.item_id AND sh.ik_version = i.ik_version WHERE sh.item_id = $1 AND sh.user_id = $2 AND i.container_id = $3", [body.itemId, a.id, body.containerId])).rowCount
      : 0;
    if (!p && !viaShare) throw forbidden();
    if (body.itemId) {
      const it = await db.query("SELECT 1 FROM items WHERE id = $1 AND container_id = $2", [body.itemId, body.containerId]);
      if (!it.rowCount) throw notFound();
    }
    await tx(db, (c) => audit(c, { actorId: a.id, action: body.action, targetType: body.itemId ? "item" : "container", targetId: body.itemId ?? body.containerId, containerId: body.containerId, ip: req.ip }));
    return { ok: true };
  });
}

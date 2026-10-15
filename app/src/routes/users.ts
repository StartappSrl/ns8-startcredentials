import { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { CryptoError, verifyUserCertification } from "@startcredentials/crypto";
import { audit, badRequest, conflict, forbidden, HttpError, newToken, notFound, tokenHash, tx, verifyAuditChain } from "../core.js";
import { Ctx, requireAdmin, requireAuth } from "../server.js";
import { schemas } from "./auth.js";
import { insertGrant, grantSchema, permissionOf } from "./containers.js";
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
    const org = await db.query("SELECT sign_public, recovery_public, container_id FROM org WHERE id = 1");
    return {
      id: u.id, email: u.email, displayName: u.display_name, role: u.role,
      keyVersion: u.key_version,
      publicKeys: { box: u.box_public, sign: u.sign_public },
      privateEnc: u.private_enc, kdfParams: u.kdf_params,
      certification: u.certification, hasRecovery: u.has_recovery,
      org: org.rows[0] ? { signPublic: org.rows[0].sign_public, recoveryPublic: org.rows[0].recovery_public, containerId: u.role === "admin" ? org.rows[0].container_id : undefined } : null,
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
      await c.query("UPDATE users SET status = 'suspended', role = 'user' WHERE id = $1", [id]);
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

  app.get("/api/v1/audit/verify", async (req) => {
    requireAdmin(req);
    return verifyAuditChain(db);
  });

  // Eventi che avvengono solo sul client (mostra, copia, compila) vengono registrati qui.
  app.post("/api/v1/audit/events", async (req) => {
    const a = requireAuth(req);
    const body = z.object({ action: z.enum(["item.reveal", "item.copy", "item.fill", "item.totp_copy", "container.export"]), itemId: z.string().uuid().optional(), containerId: z.string().uuid() }).parse(req.body);
    const p = await permissionOf(db, body.containerId, a.id);
    if (!p) throw forbidden();
    if (body.itemId) {
      const it = await db.query("SELECT 1 FROM items WHERE id = $1 AND container_id = $2", [body.itemId, body.containerId]);
      if (!it.rowCount) throw notFound();
    }
    await tx(db, (c) => audit(c, { actorId: a.id, action: body.action, targetType: body.itemId ? "item" : "container", targetId: body.itemId ?? body.containerId, containerId: body.containerId, ip: req.ip }));
    return { ok: true };
  });
}

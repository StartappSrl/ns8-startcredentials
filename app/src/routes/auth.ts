import { FastifyInstance, FastifyRequest } from "fastify";
import { randomBytes, randomUUID } from "node:crypto";
import { z } from "zod";
import * as opaque from "@serenity-kit/opaque";
import {
  audit, badRequest, base32Encode, conflict, decryptServerSecret, encryptServerSecret, forbidden, notFound,
  getSetting, newToken, safeEqual, setSetting, tokenHash, Tx, tx, unauthorized, verifyTotp,
} from "../core.js";
import { Ctx, requireAuth } from "../server.js";

const b64 = z.string().min(1).max(20_000).regex(/^[A-Za-z0-9_-]+$/);
const kdfParams = z.object({
  algorithm: z.literal("argon2id13"),
  salt: b64,
  opsLimit: z.number().int().min(2).max(20),
  memLimitBytes: z.number().int().min(19 * 1024 * 1024).max(2 * 1024 * 1024 * 1024),
});
const envelope = z.string().min(10).max(200_000).regex(/^[A-Za-z0-9_-]+$/);

export const schemas = { b64, kdfParams, envelope };

export async function createSession(c: Tx, ctx: Ctx, userId: string, state: "mfa_setup" | "mfa_pending" | "active", req: FastifyRequest) {
  const token = newToken();
  await c.query(
    `INSERT INTO sessions (id, token_hash, user_id, state, ip, user_agent, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6, now() + make_interval(hours => $7))`,
    [randomUUID(), tokenHash(ctx.cfg, token), userId, state, req.ip, (req.headers["user-agent"] ?? "").slice(0, 300), ctx.cfg.sessionHours],
  );
  return token;
}

async function orgPublic(c: Tx | Ctx["db"]) {
  const r = await c.query("SELECT sign_public, recovery_public FROM org WHERE id = 1");
  return r.rows[0] ? { signPublic: r.rows[0].sign_public as string, recoveryPublic: r.rows[0].recovery_public as string } : null;
}

const BACKUP_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/** Dieci codici di riserva XXXX-XXXX; sul server restano solo gli HMAC. */
export function newBackupCodes(ctx: Ctx): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  for (let i = 0; i < 10; i++) {
    const b = randomBytes(8);
    const raw = [...b].map((x) => BACKUP_ALPHABET[x % BACKUP_ALPHABET.length]).join("");
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return { codes, hashes: codes.map((c) => tokenHash(ctx.cfg, c.replace("-", ""))) };
}

/**
 * Verifica un secondo fattore: codice TOTP (anti-riuso) oppure codice di
 * riserva (consumato). Va chiamata dentro una transazione.
 */
export async function verifySecondFactor(c: Tx, ctx: Ctx, userId: string, code: string): Promise<"totp" | "backup" | null> {
  const u = await c.query("SELECT mfa_secret_enc, mfa_last_counter, mfa_backup_codes FROM users WHERE id = $1 FOR UPDATE", [userId]);
  const row = u.rows[0];
  if (!row?.mfa_secret_enc) return null;
  const clean = code.trim().toUpperCase().replace(/\s/g, "");
  if (/^\d{6}$/.test(clean)) {
    const counter = verifyTotp(decryptServerSecret(ctx.cfg, row.mfa_secret_enc), clean, Number(row.mfa_last_counter));
    if (counter === null) return null;
    await c.query("UPDATE users SET mfa_last_counter = $2 WHERE id = $1", [userId, counter]);
    return "totp";
  }
  const norm = clean.replace(/-/g, "");
  if (!/^[A-Z0-9]{8}$/.test(norm)) return null;
  const hashes: string[] = row.mfa_backup_codes ?? [];
  const h = tokenHash(ctx.cfg, norm);
  const idx = hashes.findIndex((x) => safeEqual(x, h));
  if (idx < 0) return null;
  hashes.splice(idx, 1);
  await c.query("UPDATE users SET mfa_backup_codes = $2 WHERE id = $1", [userId, JSON.stringify(hashes)]);
  await audit(c, { actorId: userId, action: "auth.mfa_backup_used", details: { remaining: hashes.length } });
  return "backup";
}

export async function authRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db, cfg } = ctx;
  const limit = (req: FastifyRequest, extra?: string) => {
    ctx.authLimiter.check(`auth-ip:${req.ip}`);
    if (extra) ctx.keyLimiter.check(`auth-key:${extra.toLowerCase()}`);
  };

  // Stato del server: serve al client per sapere se esiste già un amministratore.
  app.get("/api/v1/auth/status", async () => ({
    bootstrapped: (await getSetting(db, "bootstrap_used")) === "1",
    org: await orgPublic(db),
  }));

  // ------------------------------------------------------------ registrazione

  app.post("/api/v1/auth/register/start", async (req) => {
    const body = z.object({
      token: z.string().min(16).max(200),
      email: z.string().email().max(200).optional(),
      displayName: z.string().min(1).max(100).optional(),
      registrationRequest: b64,
    }).parse(req.body);
    limit(req, body.token);

    const userId = await tx(db, async (c) => {
      if (safeEqual(body.token, cfg.bootstrapToken)) {
        if ((await getSetting(c, "bootstrap_used")) === "1") throw forbidden("bootstrap_used");
        if (!body.email || !body.displayName) throw badRequest("email_required");
        const existing = await c.query("SELECT id, status FROM users WHERE lower(email) = lower($1)", [body.email]);
        if (existing.rows[0]) {
          if (existing.rows[0].status !== "invited") throw conflict("email_taken");
          await c.query("UPDATE users SET invite_token_hash = $2, invite_expires_at = now() + interval '1 hour' WHERE id = $1",
            [existing.rows[0].id, tokenHash(cfg, body.token)]);
          return existing.rows[0].id as string;
        }
        const id = randomUUID();
        await c.query(
          `INSERT INTO users (id, email, display_name, role, status, invite_token_hash, invite_expires_at)
           VALUES ($1,$2,$3,'admin','invited',$4, now() + interval '1 hour')`,
          [id, body.email, body.displayName, tokenHash(cfg, body.token)],
        );
        return id;
      }
      const r = await c.query("SELECT id FROM users WHERE invite_token_hash = $1 AND invite_expires_at > now() AND status = 'invited'", [tokenHash(cfg, body.token)]);
      if (!r.rows[0]) throw forbidden("invalid_invite");
      return r.rows[0].id as string;
    });

    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: ctx.serverSetup, userIdentifier: userId, registrationRequest: body.registrationRequest,
    });
    const u = await db.query("SELECT email, display_name, role FROM users WHERE id = $1", [userId]);
    return { registrationResponse, userId, email: u.rows[0].email, displayName: u.rows[0].display_name, role: u.rows[0].role, org: await orgPublic(db) };
  });

  app.post("/api/v1/auth/register/finish", async (req) => {
    const body = z.object({
      token: z.string().min(16).max(200),
      registrationRecord: b64,
      keys: z.object({ boxPublic: b64, signPublic: b64, privateEnc: envelope, kdfParams, recoveryEnc: b64.optional() }),
    }).parse(req.body);
    limit(req, body.token);

    return tx(db, async (c) => {
      const r = await c.query("SELECT id, role FROM users WHERE invite_token_hash = $1 AND invite_expires_at > now() AND status = 'invited' FOR UPDATE", [tokenHash(cfg, body.token)]);
      const user = r.rows[0];
      if (!user) throw forbidden("invalid_invite");
      const isBootstrap = safeEqual(body.token, cfg.bootstrapToken);
      if (isBootstrap) {
        if ((await getSetting(c, "bootstrap_used")) === "1") throw forbidden("bootstrap_used");
        await setSetting(c, "bootstrap_used", "1");
      }
      await c.query(
        `UPDATE users SET opaque_record = $2, status = 'active', key_version = 1, invite_token_hash = NULL, invite_expires_at = NULL WHERE id = $1`,
        [user.id, body.registrationRecord],
      );
      await c.query(
        `INSERT INTO user_keys (user_id, version, box_public, sign_public, private_enc, kdf_params, recovery_enc)
         VALUES ($1, 1, $2, $3, $4, $5, $6)`,
        [user.id, body.keys.boxPublic, body.keys.signPublic, body.keys.privateEnc, body.keys.kdfParams, body.keys.recoveryEnc ?? null],
      );
      await audit(c, { actorId: user.id, action: "user.registered", targetType: "user", targetId: user.id, ip: req.ip, details: { bootstrap: isBootstrap } });
      const token = await createSession(c, ctx, user.id, "mfa_setup", req);
      return { token, state: "mfa_setup", userId: user.id };
    });
  });

  // ------------------------------------------------------------ login

  app.post("/api/v1/auth/login/start", async (req) => {
    const body = z.object({ email: z.string().email().max(200), startLoginRequest: b64 }).parse(req.body);
    limit(req, body.email);
    const r = await db.query("SELECT id, opaque_record FROM users WHERE lower(email) = lower($1) AND status = 'active'", [body.email]);
    const user = r.rows[0];
    // Utente inesistente: risposta fittizia indistinguibile, niente enumerazione degli account.
    const { serverLoginState, loginResponse } = opaque.server.startLogin({
      serverSetup: ctx.serverSetup,
      userIdentifier: user?.id ?? `unknown:${body.email.toLowerCase()}`,
      registrationRecord: user?.opaque_record ?? null,
      startLoginRequest: body.startLoginRequest,
    });
    const loginId = randomBytes(18).toString("base64url");
    const now = Date.now();
    for (const [k, v] of ctx.pendingLogins) if (v.expires < now) ctx.pendingLogins.delete(k);
    ctx.pendingLogins.set(loginId, { state: serverLoginState, userId: user?.id ?? null, email: body.email, expires: now + 120_000 });
    return { loginId, loginResponse };
  });

  app.post("/api/v1/auth/login/finish", async (req) => {
    const body = z.object({ loginId: z.string().max(100), finishLoginRequest: b64, deviceToken: z.string().max(200).optional() }).parse(req.body);
    limit(req);
    const pending = ctx.pendingLogins.get(body.loginId);
    ctx.pendingLogins.delete(body.loginId);
    if (!pending || pending.expires < Date.now()) throw unauthorized("login_expired");
    let ok = false;
    try {
      ok = !!opaque.server.finishLogin({ finishLoginRequest: body.finishLoginRequest, serverLoginState: pending.state })?.sessionKey;
    } catch {
      ok = false;
    }
    if (!ok || !pending.userId) {
      await tx(db, (c) => audit(c, { actorId: pending.userId, action: "auth.login_failed", ip: req.ip, details: { email: pending.email } }));
      throw unauthorized("invalid_credentials");
    }
    return tx(db, async (c) => {
      const u = await c.query("SELECT mfa_enabled FROM users WHERE id = $1 AND status = 'active'", [pending.userId]);
      if (!u.rows[0]) throw unauthorized("invalid_credentials");
      let state: "mfa_pending" | "mfa_setup" | "active" = u.rows[0].mfa_enabled ? "mfa_pending" : "mfa_setup";
      // Dispositivo attendibile dello stesso utente, non scaduto né revocato: niente codice MFA.
      let trusted = false;
      if (state === "mfa_pending" && body.deviceToken && cfg.trustedDeviceDays) {
        const d = await c.query(
          `UPDATE trusted_devices SET last_used_at = now()
            WHERE token_hash = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now() RETURNING id`,
          [tokenHash(cfg, body.deviceToken), pending.userId]);
        if (d.rowCount) { state = "active"; trusted = true; }
      }
      const token = await createSession(c, ctx, pending.userId!, state, req);
      await audit(c, { actorId: pending.userId, action: "auth.login", ip: req.ip, details: trusted ? { trustedDevice: true } : {} });
      return { token, state, trustedDevice: trusted };
    });
  });

  app.get("/api/v1/auth/session", async (req) => {
    const a = requireAuth(req, ["mfa_setup", "mfa_pending", "active"]);
    return { state: a.state, userId: a.id, role: a.role };
  });

  app.post("/api/v1/auth/logout", async (req) => {
    const a = requireAuth(req, ["mfa_setup", "mfa_pending", "active"]);
    await db.query("DELETE FROM sessions WHERE id = $1", [a.sessionId]);
    return { ok: true };
  });

  // ------------------------------------------------------------ MFA (TOTP)

  app.post("/api/v1/auth/mfa/setup", async (req) => {
    const a = requireAuth(req, ["mfa_setup"]);
    const secret = base32Encode(randomBytes(20));
    const u = await db.query("UPDATE users SET mfa_secret_enc = $2 WHERE id = $1 AND NOT mfa_enabled RETURNING email", [a.id, encryptServerSecret(cfg, secret)]);
    if (!u.rows[0]) throw conflict("mfa_already_enabled");
    const label = encodeURIComponent(`StartCredentials:${u.rows[0].email}`);
    return { secret, otpauthUri: `otpauth://totp/${label}?secret=${secret}&issuer=StartCredentials&algorithm=SHA1&digits=6&period=30` };
  });

  app.post("/api/v1/auth/mfa/enable", async (req) => {
    const a = requireAuth(req, ["mfa_setup"]);
    const { code } = z.object({ code: z.string().max(10) }).parse(req.body);
    limit(req, `mfa:${a.id}`);
    return tx(db, async (c) => {
      const u = await c.query("SELECT mfa_secret_enc, mfa_last_counter FROM users WHERE id = $1 FOR UPDATE", [a.id]);
      if (!u.rows[0]?.mfa_secret_enc) throw badRequest("mfa_not_started");
      const counter = verifyTotp(decryptServerSecret(cfg, u.rows[0].mfa_secret_enc), code, Number(u.rows[0].mfa_last_counter));
      if (counter === null) throw badRequest("invalid_code");
      const backup = newBackupCodes(ctx);
      await c.query("UPDATE users SET mfa_enabled = true, mfa_last_counter = $2, mfa_backup_codes = $3 WHERE id = $1", [a.id, counter, JSON.stringify(backup.hashes)]);
      await c.query("UPDATE sessions SET state = 'active' WHERE id = $1", [a.sessionId]);
      await audit(c, { actorId: a.id, action: "auth.mfa_enabled", ip: req.ip });
      return { state: "active", backupCodes: backup.codes };
    });
  });

  app.post("/api/v1/auth/mfa/verify", async (req) => {
    const a = requireAuth(req, ["mfa_pending"]);
    const { code } = z.object({ code: z.string().max(20) }).parse(req.body);
    limit(req, `mfa:${a.id}`);
    const ok = await tx(db, async (c) => {
      const kind = await verifySecondFactor(c, ctx, a.id, code);
      if (!kind) return false;
      await c.query("UPDATE sessions SET state = 'active' WHERE id = $1", [a.sessionId]);
      return true;
    });
    if (!ok) {
      await tx(db, (c) => audit(c, { actorId: a.id, action: "auth.mfa_failed", ip: req.ip }));
      throw badRequest("invalid_code");
    }
    return { state: "active" };
  });

  // ------------------------------------------------------------ dispositivi attendibili

  app.post("/api/v1/auth/devices/trust", async (req) => {
    const a = requireAuth(req);
    const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body);
    if (!cfg.trustedDeviceDays) throw forbidden("trusted_devices_disabled");
    const token = newToken();
    return tx(db, async (c) => {
      const count = await c.query("SELECT count(*)::int AS n FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()", [a.id]);
      if (count.rows[0].n >= 20) throw conflict("too_many_devices", "Troppi dispositivi attendibili: revocane qualcuno dalle impostazioni");
      const r = await c.query(
        `INSERT INTO trusted_devices (id, user_id, token_hash, name, expires_at) VALUES ($1,$2,$3,$4, now() + make_interval(days => $5)) RETURNING id, expires_at`,
        [randomUUID(), a.id, tokenHash(cfg, token), name, cfg.trustedDeviceDays]);
      await audit(c, { actorId: a.id, action: "auth.device_trusted", ip: req.ip, details: { name, days: cfg.trustedDeviceDays } });
      return { deviceToken: token, deviceId: r.rows[0].id, expiresAt: r.rows[0].expires_at, days: cfg.trustedDeviceDays };
    });
  });

  app.get("/api/v1/me/devices", async (req) => {
    const a = requireAuth(req);
    const r = await db.query(
      `SELECT id, name, created_at, last_used_at, expires_at FROM trusted_devices
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC`, [a.id]);
    return { days: cfg.trustedDeviceDays ?? 0, devices: r.rows.map((d) => ({ id: d.id, name: d.name, createdAt: d.created_at, lastUsedAt: d.last_used_at, expiresAt: d.expires_at })) };
  });

  app.delete("/api/v1/me/devices/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    return tx(db, async (c) => {
      const r = await c.query("UPDATE trusted_devices SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL", [id, a.id]);
      if (!r.rowCount) throw notFound();
      await audit(c, { actorId: a.id, action: "auth.device_revoked", ip: req.ip, details: { deviceId: id } });
      return { ok: true };
    });
  });

  // ------------------------------------------------------------ recupero account

  app.post("/api/v1/auth/recover/start", async (req) => {
    const body = z.object({ token: z.string().min(16).max(200), registrationRequest: b64 }).parse(req.body);
    limit(req, body.token);
    const r = await db.query(
      "SELECT id, email, recovery_blob FROM users WHERE recovery_token_hash = $1 AND recovery_expires_at > now() AND status = 'active'",
      [tokenHash(cfg, body.token)],
    );
    const u = r.rows[0];
    if (!u) throw forbidden("invalid_recovery");
    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: ctx.serverSetup, userIdentifier: u.id, registrationRequest: body.registrationRequest,
    });
    return { registrationResponse, userId: u.id, email: u.email, blob: u.recovery_blob };
  });

  app.post("/api/v1/auth/recover/finish", async (req) => {
    const body = z.object({ token: z.string().min(16).max(200), registrationRecord: b64, privateEnc: envelope, kdfParams }).parse(req.body);
    limit(req, body.token);
    return tx(db, async (c) => {
      const r = await c.query(
        "SELECT id, key_version FROM users WHERE recovery_token_hash = $1 AND recovery_expires_at > now() AND status = 'active' FOR UPDATE",
        [tokenHash(cfg, body.token)],
      );
      const u = r.rows[0];
      if (!u) throw forbidden("invalid_recovery");
      await c.query("UPDATE user_keys SET private_enc = $3, kdf_params = $4 WHERE user_id = $1 AND version = $2", [u.id, u.key_version, body.privateEnc, body.kdfParams]);
      await c.query(
        "UPDATE users SET opaque_record = $2, recovery_token_hash = NULL, recovery_blob = NULL, recovery_expires_at = NULL WHERE id = $1",
        [u.id, body.registrationRecord],
      );
      await c.query("DELETE FROM sessions WHERE user_id = $1", [u.id]);
      await c.query("UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [u.id]);
      await audit(c, { actorId: u.id, action: "user.recovery_completed", targetType: "user", targetId: u.id, ip: req.ip });
      return { ok: true };
    });
  });
}

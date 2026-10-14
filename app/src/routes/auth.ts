import { FastifyInstance, FastifyRequest } from "fastify";
import { randomBytes, randomUUID } from "node:crypto";
import { z } from "zod";
import * as opaque from "@serenity-kit/opaque";
import {
  audit, badRequest, base32Encode, conflict, decryptServerSecret, encryptServerSecret, forbidden,
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
    const body = z.object({ loginId: z.string().max(100), finishLoginRequest: b64 }).parse(req.body);
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
      const state = u.rows[0].mfa_enabled ? "mfa_pending" : "mfa_setup";
      const token = await createSession(c, ctx, pending.userId!, state, req);
      await audit(c, { actorId: pending.userId, action: "auth.login", ip: req.ip });
      return { token, state };
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
      await c.query("UPDATE users SET mfa_enabled = true, mfa_last_counter = $2 WHERE id = $1", [a.id, counter]);
      await c.query("UPDATE sessions SET state = 'active' WHERE id = $1", [a.sessionId]);
      await audit(c, { actorId: a.id, action: "auth.mfa_enabled", ip: req.ip });
      return { state: "active" };
    });
  });

  app.post("/api/v1/auth/mfa/verify", async (req) => {
    const a = requireAuth(req, ["mfa_pending"]);
    const { code } = z.object({ code: z.string().max(10) }).parse(req.body);
    limit(req, `mfa:${a.id}`);
    return tx(db, async (c) => {
      const u = await c.query("SELECT mfa_secret_enc, mfa_last_counter FROM users WHERE id = $1 FOR UPDATE", [a.id]);
      const counter = verifyTotp(decryptServerSecret(cfg, u.rows[0].mfa_secret_enc), code, Number(u.rows[0].mfa_last_counter));
      if (counter === null) {
        await audit(c, { actorId: a.id, action: "auth.mfa_failed", ip: req.ip });
        throw badRequest("invalid_code");
      }
      await c.query("UPDATE users SET mfa_last_counter = $2 WHERE id = $1", [a.id, counter]);
      await c.query("UPDATE sessions SET state = 'active' WHERE id = $1", [a.sessionId]);
      return { state: "active" };
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
      await audit(c, { actorId: u.id, action: "user.recovery_completed", targetType: "user", targetId: u.id, ip: req.ip });
      return { ok: true };
    });
  });
}

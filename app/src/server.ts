import Fastify, { FastifyInstance, FastifyRequest } from "fastify";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ZodError } from "zod";
import * as opaque from "@serenity-kit/opaque";
import { initCrypto } from "@startcredentials/crypto";
import { Config, Db, getSetting, HttpError, RateLimiter, setSetting, tokenHash, unauthorized, forbidden } from "./core.js";
import { authRoutes } from "./routes/auth.js";
import { userRoutes } from "./routes/users.js";
import { containerRoutes } from "./routes/containers.js";
import { itemRoutes } from "./routes/items.js";
import { groupRoutes } from "./routes/groups.js";
import { createMailer, Mailer } from "./mail.js";

export interface AuthUser {
  id: string;
  role: "admin" | "user";
  sessionId: string;
  state: "mfa_setup" | "mfa_pending" | "active";
}

declare module "fastify" {
  interface FastifyRequest {
    auth?: AuthUser;
  }
}

export interface Ctx {
  cfg: Config;
  db: Db;
  serverSetup: string;
  mailer: Mailer;
  authLimiter: RateLimiter;
  keyLimiter: RateLimiter;
  apiLimiter: RateLimiter;
  /** Stati OPAQUE temporanei del login (scadono dopo 2 minuti). */
  pendingLogins: Map<string, { state: string; userId: string | null; email: string; expires: number }>;
}

const here = dirname(fileURLToPath(import.meta.url));
export const APP_ROOT = join(here, "..", "..");
export const VERSION = JSON.parse(readFileSync(join(APP_ROOT, "package.json"), "utf8")).version as string;

export async function buildApp(cfg: Config, db: Db): Promise<FastifyInstance> {
  await initCrypto();
  await opaque.ready;

  let serverSetup = await getSetting(db, "opaque_server_setup");
  if (!serverSetup) {
    serverSetup = opaque.server.createSetup();
    await setSetting(db, "opaque_server_setup", serverSetup);
  }

  const ctx: Ctx = {
    cfg, db, serverSetup,
    mailer: createMailer(cfg),
    authLimiter: new RateLimiter(cfg.authPerIpPerMinute ?? 30, 60_000),
    keyLimiter: new RateLimiter(10, 60_000),
    apiLimiter: new RateLimiter(600, 60_000),
    pendingLogins: new Map(),
  };

  const app = Fastify({
    logger: process.env.NODE_ENV === "test" ? false : { level: "info", redact: ["req.headers.authorization"] },
    bodyLimit: 20 * 1024 * 1024,
    trustProxy: "127.0.0.1",
  });

  ctx.mailer = createMailer(cfg, (e) => app.log.error({ err: e, smtpHost: cfg.smtp?.host, from: cfg.smtp?.from }, "Invio email non riuscito"));
  if (!cfg.smtp) app.log.warn("Smarthost non configurato: gli inviti vanno inviati a mano");

  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer", bodyLimit: 2 * 1024 * 1024 }, (_r, body, done) => done(null, body));

  app.addHook("onSend", async (_req, reply, payload) => {
    if (!reply.hasHeader("Cache-Control")) reply.header("Cache-Control", "no-store");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
    if (!reply.hasHeader("Content-Security-Policy")) {
      reply.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    }
    return payload;
  });

  app.addHook("onRequest", async (req) => {
    ctx.apiLimiter.check(`ip:${req.ip}`);
    const h = req.headers.authorization;
    if (!h?.startsWith("Bearer ")) return;
    const r = await db.query(
      `UPDATE sessions s SET last_seen_at = now()
         FROM users u
        WHERE s.token_hash = $1 AND s.expires_at > now() AND u.id = s.user_id AND u.status = 'active'
        RETURNING s.id, s.state, u.id AS user_id, u.role`,
      [tokenHash(cfg, h.slice(7))],
    );
    const row = r.rows[0];
    if (row) req.auth = { id: row.user_id, role: row.role, sessionId: row.id, state: row.state };
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof HttpError) return reply.status(err.status).send({ error: err.code, message: err.message });
    if (err instanceof ZodError) return reply.status(400).send({ error: "invalid_input", message: err.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") });
    const e = err as { statusCode?: number; code?: string; message?: string };
    if (e.statusCode && e.statusCode < 500) return reply.status(e.statusCode).send({ error: e.code ?? "bad_request", message: e.message });
    req.log.error(err);
    return reply.status(500).send({ error: "internal_error" });
  });

  app.get("/api/v1/health", async () => ({ ok: true }));
  app.get("/api/v1/version", async () => ({ version: VERSION, api: 1 }));

  await authRoutes(app, ctx);
  await userRoutes(app, ctx);
  await containerRoutes(app, ctx);
  await itemRoutes(app, ctx);
  await groupRoutes(app, ctx);

  const landing = readFileSync(join(APP_ROOT, "public", "index.html"));
  app.get("/", async (_req, reply) => reply
    .type("text/html; charset=utf-8")
    .header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    .send(landing));
  const logo = readFileSync(join(APP_ROOT, "public", "startapp-logo.png"));
  app.get("/startapp-logo.png", async (_req, reply) => reply.type("image/png").header("Cache-Control", "public, max-age=86400").send(logo));
  const privacy = readFileSync(join(APP_ROOT, "public", "privacy.html"));
  app.get("/privacy", async (_req, reply) => reply
    .type("text/html; charset=utf-8")
    .header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    .send(privacy));
  app.get("/download/startcredentials-extension.zip", async (_req, reply) => {
    try {
      const zip = readFileSync(join(APP_ROOT, "public", "startcredentials-extension.zip"));
      return reply.type("application/zip").header("Content-Disposition", "attachment; filename=startcredentials-extension.zip").send(zip);
    } catch {
      return reply.status(404).send({ error: "not_found" });
    }
  });

  return app;
}

/** Richiede una sessione; per default completamente autenticata (MFA superata). */
export function requireAuth(req: FastifyRequest, states: AuthUser["state"][] = ["active"]): AuthUser {
  if (!req.auth) throw unauthorized();
  if (!states.includes(req.auth.state)) throw forbidden(req.auth.state === "mfa_setup" ? "mfa_setup_required" : "mfa_required");
  return req.auth;
}

export function requireAdmin(req: FastifyRequest): AuthUser {
  const a = requireAuth(req);
  if (a.role !== "admin") throw forbidden("admin_required");
  return a;
}

/**
 * Invii sicuri: una credenziale cifrata dall'estensione con una chiave derivata
 * da un codice di accesso che il server non riceve mai. Il server conserva il
 * pacchetto cifrato, manda al destinatario solo il collegamento e lo distrugge
 * dopo l'ultima apertura consentita o alla scadenza.
 */
import { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { audit, badRequest, HttpError, newToken, notFound, RateLimiter, tokenHash, tx } from "../core.js";
import { Ctx, requireAuth } from "../server.js";
import { requirePermission } from "./containers.js";

const uuid = z.string().uuid();

/** Formato del pacchetto: lo stesso che decifra la pagina pubblica (send.js). */
const envelopeSchema = z.object({
  v: z.literal(1),
  alg: z.literal("pbkdf2-sha256-600000/aes-256-gcm"),
  salt: z.string().regex(/^[A-Za-z0-9+/=_-]{16,64}$/),
  iv: z.string().regex(/^[A-Za-z0-9+/=_-]{12,32}$/),
  data: z.string().min(16).max(96_000),
});

function status(r: { revoked_at: Date | null; expires_at: Date; envelope: string | null; views: number; max_views: number }) {
  if (r.revoked_at) return "revoked";
  if (r.views >= r.max_views) return "consumed";
  if (new Date(r.expires_at) <= new Date() || !r.envelope) return "expired";
  return "active";
}

export async function sendRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db, cfg } = ctx;
  const policy = () => cfg.secureSend ?? { enabled: true, maxHours: 168, domains: [] };
  // Aperture dalla pagina pubblica: limite per indirizzo IP, oltre a quelli generali.
  const openLimiter = new RateLimiter(30, 60_000);

  app.post("/api/v1/sends", async (req) => {
    const a = requireAuth(req);
    const p = policy();
    if (!p.enabled) throw new HttpError(403, "secure_send_disabled", "L'invio sicuro è disattivato dall'amministratore");
    const body = z.object({
      containerId: uuid,
      itemId: uuid,
      recipientEmail: z.string().trim().toLowerCase().email().max(200),
      envelope: envelopeSchema,
      expiresInHours: z.number().int().min(1).max(24 * 30),
      maxViews: z.number().int().min(1).max(10),
    }).parse(req.body);
    if (body.expiresInHours > p.maxHours) throw badRequest("expiry_too_long", `La scadenza massima consentita è di ${p.maxHours / 24} giorni`);
    const domain = body.recipientEmail.split("@")[1]!;
    if (p.domains.length && !p.domains.some((d) => domain === d || domain.endsWith(`.${d}`))) {
      throw new HttpError(403, "recipient_domain_not_allowed", "Il dominio del destinatario non è tra quelli ammessi dall'amministratore");
    }
    const token = newToken();
    const id = randomUUID();
    const sender = await tx(db, async (c) => {
      // Inviare all'esterno richiede almeno il permesso di modifica sul cliente.
      await requirePermission(c, body.containerId, a.id, "write");
      const it = await c.query("SELECT 1 FROM items WHERE id = $1 AND container_id = $2 AND deleted_at IS NULL", [body.itemId, body.containerId]);
      if (!it.rowCount) throw notFound("item_not_found");
      await c.query(
        `INSERT INTO secure_sends (id, token_hash, created_by, container_id, item_id, recipient_email, envelope, expires_at, max_views)
         VALUES ($1,$2,$3,$4,$5,$6,$7, now() + make_interval(hours => $8), $9)`,
        [id, tokenHash(cfg, token), a.id, body.containerId, body.itemId, body.recipientEmail, JSON.stringify(body.envelope), body.expiresInHours, body.maxViews]);
      await audit(c, { actorId: a.id, action: "send.created", targetType: "item", targetId: body.itemId, containerId: body.containerId, ip: req.ip,
        details: { sendId: id, recipient: body.recipientEmail, hours: body.expiresInHours, maxViews: body.maxViews } });
      return (await c.query("SELECT display_name FROM users WHERE id = $1", [a.id])).rows[0].display_name as string;
    });
    // Il collegamento porta il token nel frammento (#): il browser non lo invia mai al server nelle richieste di pagina.
    const link = `${cfg.publicUrl}/s#${token}`;
    const days = body.expiresInHours >= 48 ? `${Math.round(body.expiresInHours / 24)} giorni` : `${body.expiresInHours} ore`;
    const emailed = await ctx.mailer.send(body.recipientEmail, `${sender} ti ha inviato delle credenziali in modo sicuro`,
      `${sender} ti ha inviato delle credenziali tramite StartCredentials.\n\n` +
      `Puoi aprirle da questo collegamento entro ${days}:\n${link}\n\n` +
      `Ti servirà un codice di accesso che ${sender} ti comunicherà separatamente (non è contenuto in questa email).\n` +
      `${body.maxViews === 1 ? "Il messaggio si può aprire una sola volta" : `Il messaggio si può aprire ${body.maxViews} volte`}: dopo viene distrutto.\n\n` +
      `Se non aspettavi questo messaggio, ignoralo.\n`);
    return { id, link, emailed };
  });

  /** Apertura dalla pagina pubblica: restituisce il pacchetto cifrato e consuma un'apertura. */
  app.post("/api/v1/sends/open", async (req) => {
    openLimiter.check(`ip:${req.ip}`);
    const { token } = z.object({ token: z.string().min(16).max(200) }).parse(req.body);
    const r = await tx(db, async (c) => {
      const s = (await c.query(
        `SELECT s.*, u.display_name, u.email AS sender_email FROM secure_sends s JOIN users u ON u.id = s.created_by
          WHERE s.token_hash = $1 FOR UPDATE OF s`, [tokenHash(cfg, token)])).rows[0];
      if (!s || status(s) !== "active") return null;
      const views = s.views + 1;
      const last = views >= s.max_views;
      // All'ultima apertura il pacchetto cifrato viene cancellato.
      await c.query("UPDATE secure_sends SET views = $2, last_opened_at = now(), envelope = CASE WHEN $3 THEN NULL ELSE envelope END WHERE id = $1",
        [s.id, views, last]);
      await audit(c, { actorId: null, action: "send.opened", targetType: "item", targetId: s.item_id, containerId: s.container_id, ip: req.ip,
        details: { sendId: s.id, recipient: s.recipient_email, view: views, of: s.max_views } });
      return { s, viewsLeft: s.max_views - views };
    });
    if (!r) throw new HttpError(404, "send_not_available", "Il messaggio non esiste, è scaduto, è stato revocato o è già stato aperto");
    await ctx.mailer.send(r.s.sender_email, "Il tuo invio sicuro è stato aperto",
      `Le credenziali inviate in modo sicuro a ${r.s.recipient_email} sono state aperte` +
      `${r.viewsLeft ? ` (restano ${r.viewsLeft} aperture)` : " e il messaggio è stato distrutto"}.\n\nSe non te lo aspettavi, revoca l'invio e cambia la password alla fonte.\n`);
    return { envelope: JSON.parse(r.s.envelope), sender: r.s.display_name, expiresAt: r.s.expires_at, viewsLeft: r.viewsLeft };
  });

  app.get("/api/v1/sends", async (req) => {
    const a = requireAuth(req);
    const r = await db.query(
      `SELECT id, container_id, item_id, recipient_email, expires_at, max_views, views, created_at, last_opened_at, revoked_at, envelope IS NOT NULL AS has_data
         FROM secure_sends WHERE created_by = $1 ORDER BY created_at DESC LIMIT 200`, [a.id]);
    return r.rows.map((x) => ({
      id: x.id, containerId: x.container_id, itemId: x.item_id, recipientEmail: x.recipient_email,
      createdAt: x.created_at, expiresAt: x.expires_at, maxViews: x.max_views, views: x.views, lastOpenedAt: x.last_opened_at,
      status: status({ ...x, envelope: x.has_data ? "x" : null }),
    }));
  });

  /** Revoca: il pacchetto cifrato viene cancellato subito. */
  app.delete("/api/v1/sends/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const r = await c.query(
        `UPDATE secure_sends SET revoked_at = now(), envelope = NULL
          WHERE id = $1 AND revoked_at IS NULL AND (created_by = $2 OR $3) RETURNING item_id, container_id, recipient_email`,
        [id, a.id, a.role === "admin"]);
      if (!r.rowCount) throw notFound();
      await audit(c, { actorId: a.id, action: "send.revoked", targetType: "item", targetId: r.rows[0].item_id, containerId: r.rows[0].container_id, ip: req.ip,
        details: { sendId: id, recipient: r.rows[0].recipient_email } });
      return { ok: true };
    });
  });
}

/** Pulizia periodica: pacchetti scaduti cancellati (resta solo la traccia per il registro). */
export async function purgeExpiredSends(db: Ctx["db"]): Promise<number> {
  const r = await db.query("UPDATE secure_sends SET envelope = NULL WHERE envelope IS NOT NULL AND expires_at <= now()");
  return r.rowCount ?? 0;
}

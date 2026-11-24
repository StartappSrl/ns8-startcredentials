/**
 * Accesso d'emergenza a un cliente.
 *
 * Un gestore designa un collega e prepara una consegna della chiave del cliente
 * cifrata per quel collega e firmata da sé: il server la custodisce ma non può
 * leggerla, né modificarla (la firma lega cliente, versione della chiave,
 * destinatario e permesso). Il collega può chiedere l'accesso: gestori e
 * amministratori vengono avvisati per email e nell'app, e qualsiasi gestore può
 * rifiutare. Se nessuno rifiuta entro il tempo di attesa, la consegna diventa
 * effettiva come una normale condivisione. Prima di allora il server non la
 * restituisce mai a nessuno.
 */
import { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { grantMessage, verify } from "@startcredentials/crypto";
import { audit, badRequest, conflict, Db, forbidden, notFound, Tx, tx } from "../core.js";
import { Ctx, requireAuth } from "../server.js";
import { checkGrant, Grant, grantSchema, permissionOf, requirePermission } from "./containers.js";
import { schemas } from "./auth.js";

const uuid = z.string().uuid();
const HOUR = 3600_000;
/** Attesa minima: lascia ai gestori il tempo di accorgersi della richiesta. */
const MIN_WAIT_HOURS = 24;

type Row = {
  id: string; container_id: string; user_id: string; key_version: number; recipient_key_version: number; permission: string;
  sealed_key: string; granted_by: string; signature: string; label_enc: string; wait_hours: number; created_by: string;
  created_at: Date; requested_at: Date | null; rejected_at: Date | null; rejected_by: string | null;
  container_key_version: number; user_key_version: number; user_status: string; display_name: string; email: string;
};

const SELECT = `
  SELECT e.*, c.key_version AS container_key_version, u.key_version AS user_key_version, u.status AS user_status,
         u.display_name, u.email
    FROM emergency_access e
    JOIN containers c ON c.id = e.container_id AND c.deleted_at IS NULL
    JOIN users u ON u.id = e.user_id`;

/** Una consegna preparata con una chiave del cliente o del designato ormai superata non vale più. */
const stale = (r: Row) => r.key_version !== r.container_key_version || r.recipient_key_version !== r.user_key_version;

function state(r: Row, now = Date.now()) {
  const activatesAt = r.requested_at ? new Date(r.requested_at.getTime() + r.wait_hours * HOUR) : null;
  const status = stale(r) ? "stale"
    : activatesAt ? (activatesAt.getTime() <= now ? "ready" : "pending")
      : r.rejected_at ? "rejected" : "idle";
  return { status, activatesAt };
}

/** Gestori del cliente (diretti o tramite gruppo) e amministratori attivi, escluso il richiedente. */
async function watchers(db: Db | Tx, containerId: string, exclude: string): Promise<{ email: string; display_name: string }[]> {
  const r = await db.query(
    `SELECT DISTINCT u.email, u.display_name FROM users u
      WHERE u.status = 'active' AND u.id <> $2 AND (
        u.role = 'admin'
        OR u.id IN (SELECT k.user_id FROM container_keys k JOIN containers c ON c.id = k.container_id AND c.key_version = k.key_version
                     WHERE k.container_id = $1 AND k.permission = 'manage')
        OR u.id IN (SELECT gm.user_id FROM container_group_keys gk
                      JOIN containers c ON c.id = gk.container_id AND c.key_version = gk.key_version
                      JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL AND gk.group_key_version = g.key_version
                      JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version
                     WHERE gk.container_id = $1 AND gk.permission = 'manage'))`, [containerId, exclude]);
  return r.rows;
}

const when = (d: Date) => d.toLocaleString("it-IT", { dateStyle: "full", timeStyle: "short", timeZone: "Europe/Rome" });

/**
 * Rende effettiva la consegna trattenuta: verifica di nuovo la firma con la
 * chiave attuale di chi l'ha preparata e la inserisce tra gli accessi.
 */
async function activate(c: Tx, r: Row): Promise<void> {
  if (stale(r)) throw conflict("emergency_stale", "La designazione va rinnovata da un gestore: la chiave del cliente o del collega è cambiata");
  if (r.user_status !== "active") throw forbidden("recipient_not_active");
  // Vale solo finché chi l'ha creata è ancora attivo e gestisce il cliente.
  const creator = await c.query("SELECT status FROM users WHERE id = $1", [r.created_by]);
  const creatorPerm = await permissionOf(c, r.container_id, r.created_by);
  if (creator.rows[0]?.status !== "active" || creatorPerm?.permission !== "manage") {
    throw conflict("emergency_stale", "Chi ha creato la designazione non gestisce più il cliente: un gestore attuale deve rinnovarla");
  }
  const cert = await c.query("SELECT k.certification FROM users u JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = $1", [r.user_id]);
  if (!cert.rows[0]?.certification) throw conflict("emergency_stale", "La chiave del collega non è più certificata");
  const g: Grant = {
    containerId: r.container_id, keyVersion: r.key_version, recipientId: r.user_id, permission: r.permission as Grant["permission"],
    sealedKey: r.sealed_key, grantedBy: r.granted_by, signature: r.signature,
  };
  const grantor = await c.query(
    "SELECT k.sign_public FROM users u JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = $1", [r.granted_by]);
  const { signature, ...unsigned } = g;
  if (!grantor.rows[0] || !verify(grantMessage(unsigned), signature, grantor.rows[0].sign_public)) {
    throw conflict("emergency_stale", "La designazione va rinnovata da un gestore: la firma non è più valida");
  }
  const RANK = { read: 1, write: 2, manage: 3 } as const;
  const existing = await c.query("SELECT permission FROM container_keys WHERE container_id = $1 AND key_version = $2 AND user_id = $3",
    [r.container_id, r.key_version, r.user_id]);
  const cur = existing.rows[0]?.permission as keyof typeof RANK | undefined;
  if (!cur || RANK[cur] < RANK[g.permission]) {
    await c.query(
      `INSERT INTO container_keys (container_id, key_version, user_id, sealed_key, permission, granted_by, signature)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (container_id, key_version, user_id)
       DO UPDATE SET sealed_key = EXCLUDED.sealed_key, permission = EXCLUDED.permission, granted_by = EXCLUDED.granted_by,
                     signature = EXCLUDED.signature, created_at = now()`,
      [g.containerId, g.keyVersion, g.recipientId, g.sealedKey, g.permission, g.grantedBy, g.signature]);
  }
  await c.query("DELETE FROM emergency_access WHERE id = $1", [r.id]);
}

/**
 * Durante la rotazione della chiave del cliente: sostituisce le consegne trattenute
 * con quelle preparate con la nuova chiave. Le designazioni non rinnovate restano
 * e risultano "da rinnovare" (la vecchia chiave non apre più nulla).
 */
export async function renewEmergencyGrants(c: Tx, containerId: string, newKeyVersion: number, grants: Grant[], actorId: string): Promise<number> {
  if (!grants.length) return 0;
  const rows = await c.query("SELECT e.id, e.user_id, e.permission, u.key_version FROM emergency_access e JOIN users u ON u.id = e.user_id WHERE e.container_id = $1", [containerId]);
  const byUser = new Map(rows.rows.map((r) => [r.user_id as string, r]));
  let n = 0;
  for (const g of grants) {
    const row = byUser.get(g.recipientId);
    if (!row || g.containerId !== containerId || g.keyVersion !== newKeyVersion || g.permission !== row.permission) {
      throw badRequest("emergency_grants_must_match");
    }
    await checkGrant(c, g, actorId);
    await c.query(
      `UPDATE emergency_access SET key_version = $2, sealed_key = $3, granted_by = $4, signature = $5, recipient_key_version = $6
        WHERE id = $1`, [row.id, g.keyVersion, g.sealedKey, g.grantedBy, g.signature, row.key_version]);
    n++;
  }
  return n;
}

export async function emergencyRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;

  // ------------------------------------------------------------ lato gestori

  app.get("/api/v1/containers/:id/emergency", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    await requirePermission(db, id, a.id, "manage");
    const r = await db.query<Row>(`${SELECT} WHERE e.container_id = $1 ORDER BY u.display_name`, [id]);
    return r.rows.map((x) => {
      const s = state(x);
      return {
        userId: x.user_id, displayName: x.display_name, email: x.email, permission: x.permission, waitHours: x.wait_hours,
        createdBy: x.created_by, createdAt: x.created_at, requestedAt: x.requested_at, rejectedAt: x.rejected_at,
        status: s.status, activatesAt: s.activatesAt,
      };
    });
  });

  /** Richieste in corso sui clienti che l'utente gestisce: servono all'avviso nell'app. */
  app.get("/api/v1/emergency/pending", async (req) => {
    const a = requireAuth(req);
    // Gli amministratori vedono tutte le richieste (e possono rifiutarle) anche senza accesso al cliente.
    const r = await db.query<Row>(
      `${SELECT} WHERE e.requested_at IS NOT NULL AND e.user_id <> $1
         AND ($2::boolean
              OR e.container_id IN (SELECT k.container_id FROM container_keys k JOIN containers c2 ON c2.id = k.container_id AND c2.key_version = k.key_version
                                     WHERE k.user_id = $1 AND k.permission = 'manage')
              OR e.container_id IN (SELECT gk.container_id FROM container_group_keys gk
                                     JOIN containers c3 ON c3.id = gk.container_id AND c3.key_version = gk.key_version
                                     JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL AND gk.group_key_version = g.key_version
                                     JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version AND gm.user_id = $1
                                     WHERE gk.permission = 'manage'))
       ORDER BY e.requested_at LIMIT 200`, [a.id, a.role === "admin"]);
    return r.rows.filter((x) => !stale(x)).map((x) => ({
      containerId: x.container_id, userId: x.user_id, displayName: x.display_name, requestedAt: x.requested_at, activatesAt: state(x).activatesAt,
    }));
  });

  app.put("/api/v1/containers/:id/emergency", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({
      grant: grantSchema,
      labelEnc: schemas.b64.refine((v) => v.length <= 4096),
      waitHours: z.number().int().min(MIN_WAIT_HOURS).max(720),
    }).parse(req.body);
    const g = body.grant;
    return tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      const p = await requirePermission(c, id, a.id, "manage");
      if (p.kind !== "client") throw forbidden("clients_only");
      if (g.containerId !== id || g.keyVersion !== p.keyVersion) throw badRequest("stale_key_version");
      if (g.recipientId === a.id) throw badRequest("cannot_designate_self");
      const has = await permissionOf(c, id, g.recipientId);
      if (has && (has.permission === "manage" || has.permission === g.permission)) throw conflict("already_member", "Questa persona ha già accesso al cliente");
      const prev = await c.query("SELECT requested_at FROM emergency_access WHERE container_id = $1 AND user_id = $2", [id, g.recipientId]);
      if (prev.rows[0]?.requested_at) throw conflict("emergency_pending", "C'è una richiesta in corso: rifiutala o approvala prima di cambiare la designazione");
      await checkGrant(c, g, a.id);
      const uk = await c.query("SELECT key_version FROM users WHERE id = $1", [g.recipientId]);
      await c.query(
        `INSERT INTO emergency_access (id, container_id, user_id, key_version, recipient_key_version, permission, sealed_key, granted_by, signature, label_enc, wait_hours, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$8)
         ON CONFLICT (container_id, user_id) DO UPDATE SET key_version = EXCLUDED.key_version, recipient_key_version = EXCLUDED.recipient_key_version,
           permission = EXCLUDED.permission, sealed_key = EXCLUDED.sealed_key, granted_by = EXCLUDED.granted_by, signature = EXCLUDED.signature,
           label_enc = EXCLUDED.label_enc, wait_hours = EXCLUDED.wait_hours, created_by = EXCLUDED.created_by, created_at = now(),
           requested_at = NULL, rejected_at = NULL, rejected_by = NULL`,
        [randomUUID(), id, g.recipientId, g.keyVersion, uk.rows[0].key_version, g.permission, g.sealedKey, a.id, g.signature, body.labelEnc, body.waitHours]);
      await audit(c, { actorId: a.id, action: "emergency.designated", targetType: "user", targetId: g.recipientId, containerId: id, ip: req.ip,
        details: { permission: g.permission, waitHours: body.waitHours } });
      return { ok: true };
    });
  });

  app.delete("/api/v1/containers/:id/emergency/:userId", async (req) => {
    const a = requireAuth(req);
    const { id, userId } = z.object({ id: uuid, userId: uuid }).parse(req.params);
    return tx(db, async (c) => {
      await requirePermission(c, id, a.id, "manage");
      const r = await c.query("DELETE FROM emergency_access WHERE container_id = $1 AND user_id = $2", [id, userId]);
      if (!r.rowCount) throw notFound();
      await audit(c, { actorId: a.id, action: "emergency.removed", targetType: "user", targetId: userId, containerId: id, ip: req.ip });
      return { ok: true };
    });
  });

  app.post("/api/v1/containers/:id/emergency/:userId/reject", async (req) => {
    const a = requireAuth(req);
    const { id, userId } = z.object({ id: uuid, userId: uuid }).parse(req.params);
    const email = await tx(db, async (c) => {
      // Rifiutare non richiede chiavi: lo può fare anche un amministratore senza accesso al cliente.
      if (a.role !== "admin") await requirePermission(c, id, a.id, "manage");
      const r = await c.query<Row>(`${SELECT} WHERE e.container_id = $1 AND e.user_id = $2 FOR UPDATE OF e`, [id, userId]);
      if (!r.rows[0]?.requested_at) throw notFound("no_pending_request");
      await c.query("UPDATE emergency_access SET requested_at = NULL, rejected_at = now(), rejected_by = $2 WHERE id = $1", [r.rows[0].id, a.id]);
      await audit(c, { actorId: a.id, action: "emergency.rejected", targetType: "user", targetId: userId, containerId: id, ip: req.ip });
      return r.rows[0].email;
    });
    const actor = await db.query("SELECT display_name FROM users WHERE id = $1", [a.id]);
    await ctx.mailer.send(email, "Accesso d'emergenza rifiutato",
      `${actor.rows[0]?.display_name ?? "Un gestore"} ha rifiutato la tua richiesta di accesso d'emergenza a un cliente su StartCredentials.\n\n${ctx.cfg.publicUrl}\n`);
    return { ok: true };
  });

  app.post("/api/v1/containers/:id/emergency/:userId/approve", async (req) => {
    const a = requireAuth(req);
    const { id, userId } = z.object({ id: uuid, userId: uuid }).parse(req.params);
    const email = await tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      await requirePermission(c, id, a.id, "manage");
      const r = await c.query<Row>(`${SELECT} WHERE e.container_id = $1 AND e.user_id = $2 FOR UPDATE OF e`, [id, userId]);
      if (!r.rows[0]?.requested_at) throw notFound("no_pending_request");
      await activate(c, r.rows[0]);
      await audit(c, { actorId: a.id, action: "emergency.approved", targetType: "user", targetId: userId, containerId: id, ip: req.ip,
        details: { permission: r.rows[0].permission } });
      return r.rows[0].email;
    });
    await ctx.mailer.send(email, "Accesso d'emergenza concesso",
      `La tua richiesta di accesso d'emergenza è stata approvata: il cliente è ora tra quelli che vedi su StartCredentials.\n\n${ctx.cfg.publicUrl}\n`);
    return { ok: true };
  });

  // ------------------------------------------------------------ lato designato

  /** Designazioni dell'utente. La consegna trattenuta non viene mai restituita. */
  app.get("/api/v1/emergency", async (req) => {
    const a = requireAuth(req);
    const r = await db.query<Row>(`${SELECT} WHERE e.user_id = $1 ORDER BY e.created_at`, [a.id]);
    const names = await db.query("SELECT id, display_name FROM users WHERE id = ANY($1::uuid[])", [[...new Set(r.rows.map((x) => x.created_by))]]);
    return r.rows.map((x) => {
      const s = state(x);
      return {
        id: x.id, containerId: x.container_id, labelEnc: x.label_enc, permission: x.permission, waitHours: x.wait_hours,
        createdBy: names.rows.find((n) => n.id === x.created_by)?.display_name ?? "", createdAt: x.created_at,
        requestedAt: x.requested_at, rejectedAt: x.rejected_at, status: s.status, activatesAt: s.activatesAt,
      };
    });
  });

  app.post("/api/v1/emergency/:id/request", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const r = await tx(db, async (c) => {
      const q = await c.query<Row>(`${SELECT} WHERE e.id = $1 AND e.user_id = $2 FOR UPDATE OF e`, [id, a.id]);
      const row = q.rows[0];
      if (!row) throw notFound();
      if (stale(row)) throw conflict("emergency_stale", "La designazione va rinnovata da un gestore del cliente");
      if (row.requested_at) throw conflict("already_requested", "Hai già chiesto l'accesso: attendi la scadenza");
      if (row.rejected_at) {
        throw conflict("rejected", "La richiesta è stata rifiutata: potrai chiederla di nuovo solo se un gestore riattiva la designazione");
      }
      await c.query("UPDATE emergency_access SET requested_at = now(), rejected_at = NULL, rejected_by = NULL WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "emergency.requested", targetType: "user", targetId: a.id, containerId: row.container_id, ip: req.ip,
        details: { waitHours: row.wait_hours } });
      return row;
    });
    const at = new Date(Date.now() + r.wait_hours * HOUR);
    for (const w of await watchers(db, r.container_id, a.id)) {
      await ctx.mailer.send(w.email, "Richiesta di accesso d'emergenza",
        `${r.display_name} ha chiesto l'accesso d'emergenza a un cliente su StartCredentials.\n\n` +
        `Se nessun gestore la rifiuta, l'accesso sarà concesso automaticamente ${when(at)}.\n\n` +
        `Se non te l'aspettavi, apri StartCredentials: trovi la richiesta in cima all'elenco dei clienti e puoi rifiutarla. ` +
        `Per sicurezza il nome del cliente non viene scritto nelle email.\n\n${ctx.cfg.publicUrl}\n`);
    }
    return { ok: true, activatesAt: at };
  });

  /** Il designato ottiene l'accesso, se il tempo di attesa è passato senza rifiuti. */
  app.post("/api/v1/emergency/:id/claim", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const r = await tx(db, async (c) => {
      const pre = await c.query("SELECT container_id FROM emergency_access WHERE id = $1 AND user_id = $2", [id, a.id]);
      if (!pre.rows[0]) throw notFound();
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [pre.rows[0].container_id]);
      const q = await c.query<Row>(`${SELECT} WHERE e.id = $1 AND e.user_id = $2 FOR UPDATE OF e`, [id, a.id]);
      const row = q.rows[0];
      if (!row) throw notFound();
      const s = state(row);
      if (s.status === "stale") throw conflict("emergency_stale", "La designazione va rinnovata da un gestore del cliente");
      if (s.status !== "ready") throw forbidden("emergency_not_ready");
      await activate(c, row);
      await audit(c, { actorId: a.id, action: "emergency.granted", targetType: "user", targetId: a.id, containerId: row.container_id, ip: req.ip,
        details: { permission: row.permission, waitHours: row.wait_hours } });
      return row;
    });
    for (const w of await watchers(db, r.container_id, a.id)) {
      await ctx.mailer.send(w.email, "Accesso d'emergenza concesso",
        `Nessun gestore ha rifiutato la richiesta di ${r.display_name}: da ora ha accesso d'emergenza a un cliente su StartCredentials.\n\n` +
        `Se non era previsto, togli l'accesso dalla condivisione del cliente: la chiave verrà ruotata.\n\n${ctx.cfg.publicUrl}\n`);
    }
    return { ok: true, containerId: r.container_id };
  });
}

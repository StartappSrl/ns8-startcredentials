import { FastifyInstance } from "fastify";
import { z } from "zod";
import { grantMessage, groupContainerMessage, verify } from "@startcredentials/crypto";
import { audit, badRequest, conflict, Db, forbidden, notFound, Tx, tx } from "../core.js";
import { Ctx, requireAuth } from "../server.js";
import { schemas } from "./auth.js";

const { b64, envelope } = schemas;
const uuid = z.string().uuid();

export const grantSchema = z.object({
  containerId: uuid,
  keyVersion: z.number().int().min(1),
  recipientId: uuid,
  permission: z.enum(["read", "write", "manage"]),
  sealedKey: b64,
  grantedBy: uuid,
  signature: b64,
});
export type Grant = z.infer<typeof grantSchema>;

const RANK = { read: 1, write: 2, manage: 3 } as const;
export type Permission = keyof typeof RANK;

/** Permesso effettivo: il massimo tra la consegna diretta e quelle tramite i gruppi di cui l'utente fa parte. */
export async function permissionOf(db: Db | Tx, containerId: string, userId: string) {
  const r = await db.query(
    `SELECT c.key_version, c.kind, a.permission FROM containers c
       JOIN (
         SELECT k.container_id, k.key_version, k.permission FROM container_keys k WHERE k.user_id = $2
         UNION ALL
         SELECT gk.container_id, gk.key_version, gk.permission FROM container_group_keys gk
           JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL AND gk.group_key_version = g.key_version
           JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version AND gm.user_id = $2
       ) a ON a.container_id = c.id AND a.key_version = c.key_version
      WHERE c.id = $1 AND c.deleted_at IS NULL`, [containerId, userId]);
  if (!r.rows.length) return null;
  const best = r.rows.reduce((m, x) => (RANK[x.permission as Permission] > RANK[m.permission as Permission] ? x : m));
  return { permission: best.permission as Permission, keyVersion: best.key_version as number, kind: best.kind as string };
}

/** Contenitori accessibili all'utente (direttamente o tramite gruppo), come sottoquery SQL con $1 = utente. */
export const ACCESSIBLE_CONTAINERS = `
  SELECT k.container_id FROM container_keys k JOIN containers c ON c.id = k.container_id AND c.key_version = k.key_version WHERE k.user_id = $1
  UNION
  SELECT gk.container_id FROM container_group_keys gk
    JOIN containers c ON c.id = gk.container_id AND c.key_version = gk.key_version
    JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL AND gk.group_key_version = g.key_version
    JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version AND gm.user_id = $1`;

export async function requirePermission(db: Db | Tx, containerId: string, userId: string, min: Permission) {
  const p = await permissionOf(db, containerId, userId);
  if (!p) throw notFound("container_not_found");
  if (RANK[p.permission] < RANK[min]) throw forbidden(`${min}_required`);
  return p;
}

/**
 * Verifica e salva una consegna di chiave. La firma è controllata anche dal
 * server: un client manomesso non può alterare permessi o destinatari.
 */
export async function insertGrant(c: Tx, g: Grant, actorId: string): Promise<void> {
  if (g.grantedBy !== actorId) throw badRequest("grant_not_signed_by_actor");
  const grantor = await c.query(
    "SELECT k.sign_public FROM users u JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = $1", [actorId]);
  const { signature, ...unsigned } = g;
  if (!verify(grantMessage(unsigned), signature, grantor.rows[0].sign_public)) throw badRequest("invalid_grant_signature");
  if (g.recipientId !== actorId) {
    const rec = await c.query(
      `SELECT u.status, u.role, k.certification FROM users u
         JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = $1`, [g.recipientId]);
    if (!rec.rows[0] || rec.rows[0].status !== "active") throw badRequest("recipient_not_active");
    if (!rec.rows[0].certification) throw badRequest("recipient_not_certified");
  }
  await c.query(
    `INSERT INTO container_keys (container_id, key_version, user_id, sealed_key, permission, granted_by, signature)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (container_id, key_version, user_id)
     DO UPDATE SET sealed_key = EXCLUDED.sealed_key, permission = EXCLUDED.permission, granted_by = EXCLUDED.granted_by,
                   signature = EXCLUDED.signature, created_at = now()`,
    [g.containerId, g.keyVersion, g.recipientId, g.sealedKey, g.permission, g.grantedBy, g.signature]);
}

export const groupGrantSchema = z.object({
  containerId: uuid,
  keyVersion: z.number().int().min(1),
  groupId: uuid,
  groupKeyVersion: z.number().int().min(1),
  permission: z.enum(["read", "write", "manage"]),
  sealedKey: b64,
  grantedBy: uuid,
  signature: b64,
});
export type GroupGrant = z.infer<typeof groupGrantSchema>;

/** Verifica e salva la condivisione di un contenitore con un gruppo. */
export async function insertGroupGrant(c: Tx, g: GroupGrant, actorId: string): Promise<void> {
  if (g.grantedBy !== actorId) throw badRequest("grant_not_signed_by_actor");
  const grantor = await c.query(
    "SELECT k.sign_public FROM users u JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = $1", [actorId]);
  const { signature, ...unsigned } = g;
  if (!verify(groupContainerMessage(unsigned), signature, grantor.rows[0].sign_public)) throw badRequest("invalid_grant_signature");
  const grp = await c.query("SELECT key_version, rotation_required FROM groups WHERE id = $1 AND deleted_at IS NULL", [g.groupId]);
  if (!grp.rows[0]) throw notFound("group_not_found");
  // Chi è appena uscito dal gruppo ha ancora la vecchia chiave: prima va ruotata quella del gruppo.
  if (grp.rows[0].rotation_required) throw conflict("group_rotation_pending", "La chiave del gruppo deve essere ruotata da un amministratore del gruppo");
  if (grp.rows[0].key_version !== g.groupKeyVersion) throw conflict("stale_group_key_version");
  await c.query(
    `INSERT INTO container_group_keys (container_id, key_version, group_id, group_key_version, permission, sealed_key, granted_by, signature)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT (container_id, key_version, group_id)
     DO UPDATE SET group_key_version = EXCLUDED.group_key_version, permission = EXCLUDED.permission, sealed_key = EXCLUDED.sealed_key,
                   granted_by = EXCLUDED.granted_by, signature = EXCLUDED.signature, created_at = now()`,
    [g.containerId, g.keyVersion, g.groupId, g.groupKeyVersion, g.permission, g.sealedKey, g.grantedBy, g.signature]);
}

async function managersLeft(c: Tx, containerId: string, keyVersion: number, excluding: string): Promise<number> {
  const r = await c.query(
    `SELECT (SELECT count(*)::int FROM container_keys WHERE container_id = $1 AND key_version = $2 AND permission = 'manage' AND user_id <> $3)
          + (SELECT count(*)::int FROM container_group_keys gk JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL
              WHERE gk.container_id = $1 AND gk.key_version = $2 AND gk.permission = 'manage'
                AND EXISTS (SELECT 1 FROM group_members gm WHERE gm.group_id = g.id AND gm.key_version = g.key_version AND gm.user_id <> $3)) AS n`,
    [containerId, keyVersion, excluding]);
  return r.rows[0].n;
}

/**
 * Contenitori dell'utente con tutto ciò che serve al client per aprirli:
 * la consegna diretta (se c'è) e le eventuali vie tramite gruppo, ciascuna con
 * la chiave del gruppo consegnata all'utente e la certificazione del gruppo.
 */
export async function loadContainers(db: Db | Tx, userId: string, onlyId?: string) {
  const base = await db.query(
    `SELECT c.id, c.kind, c.meta_key_enc, c.meta_enc, c.key_version, c.updated_at, c.rotation_required,
            (SELECT count(*)::int FROM container_keys m WHERE m.container_id = c.id AND m.key_version = c.key_version) AS members,
            (SELECT count(*)::int FROM container_group_keys m WHERE m.container_id = c.id AND m.key_version = c.key_version) AS groups,
            (SELECT count(*)::int FROM items i WHERE i.container_id = c.id AND i.deleted_at IS NULL) AS items,
            (SELECT count(*)::int FROM items i WHERE i.container_id = c.id AND i.deleted_at IS NULL AND i.type = 'totp') AS totp_items
       FROM containers c
      WHERE c.deleted_at IS NULL AND c.id IN (${ACCESSIBLE_CONTAINERS}) AND ($2::uuid IS NULL OR c.id = $2)
      ORDER BY c.updated_at DESC`, [userId, onlyId ?? null]);
  if (!base.rows.length) return [];
  const ids = base.rows.map((r) => r.id);
  const direct = await db.query(
    `SELECT k.*, gk.sign_public AS grantor_sign_public FROM container_keys k
       JOIN containers c ON c.id = k.container_id AND c.key_version = k.key_version
       JOIN users gu ON gu.id = k.granted_by JOIN user_keys gk ON gk.user_id = gu.id AND gk.version = gu.key_version
      WHERE k.user_id = $1 AND k.container_id = ANY($2::uuid[])`, [userId, ids]);
  const viaGroup = await db.query(
    `SELECT gk.*, g.name AS group_name, g.box_public, g.certification, gm.role, gm.sealed_key AS member_sealed_key,
            gm.granted_by AS member_granted_by, gm.signature AS member_signature
       FROM container_group_keys gk
       JOIN containers c ON c.id = gk.container_id AND c.key_version = gk.key_version
       JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL AND gk.group_key_version = g.key_version
       JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version AND gm.user_id = $1
      WHERE gk.container_id = ANY($2::uuid[])`, [userId, ids]);
  return base.rows.map((r) => {
    const d = direct.rows.find((x) => x.container_id === r.id);
    const groups = viaGroup.rows.filter((x) => x.container_id === r.id).map((x) => ({
      grant: {
        containerId: x.container_id, keyVersion: x.key_version, groupId: x.group_id, groupKeyVersion: x.group_key_version,
        permission: x.permission, sealedKey: x.sealed_key, grantedBy: x.granted_by, signature: x.signature,
      },
      group: { id: x.group_id, name: x.group_name, keyVersion: x.group_key_version, boxPublic: x.box_public, certification: x.certification },
      membership: {
        groupId: x.group_id, keyVersion: x.group_key_version, userId, role: x.role,
        sealedKey: x.member_sealed_key, grantedBy: x.member_granted_by, signature: x.member_signature,
      },
    }));
    const perms = [d?.permission, ...groups.map((g) => g.grant.permission)].filter(Boolean) as Permission[];
    const permission = perms.reduce((m, p) => (RANK[p] > RANK[m] ? p : m));
    return {
      id: r.id, kind: r.kind, metaKeyEnc: r.meta_key_enc, metaEnc: r.meta_enc, keyVersion: r.key_version,
      updatedAt: r.updated_at, members: r.members, groups: r.groups, items: r.items, totpItems: r.totp_items,
      rotationRequired: r.rotation_required, permission,
      grant: d ? {
        containerId: r.id, keyVersion: r.key_version, recipientId: userId, permission: d.permission,
        sealedKey: d.sealed_key, grantedBy: d.granted_by, signature: d.signature,
      } : null,
      grantorSignPublic: d?.grantor_sign_public ?? null,
      groupAccess: groups,
    };
  });
}

const PERM_IT: Record<Permission, string> = { read: "sola lettura", write: "modifica", manage: "gestione" };

/**
 * Avviso email di un nuovo accesso. Il server non conosce il nome del cliente
 * (è cifrato), quindi l'email non lo contiene: si trova in "Condivisi con me".
 */
async function notifyShare(ctx: Ctx, actorId: string, recipientId: string, permission: Permission) {
  const r = await ctx.db.query("SELECT id, email, display_name FROM users WHERE id = ANY($1::uuid[])", [[actorId, recipientId]]);
  const actor = r.rows.find((x) => x.id === actorId);
  const rec = r.rows.find((x) => x.id === recipientId);
  if (!actor || !rec) return;
  await ctx.mailer.send(rec.email, "Nuovo accesso su StartCredentials",
    `${actor.display_name} ti ha dato accesso a un cliente su StartCredentials, con permesso di ${PERM_IT[permission]}.\n\n` +
    `Per sicurezza il nome del cliente non viene scritto nelle email: lo trovi nell'estensione, nella sezione «Condivisi con me».\n\n${ctx.cfg.publicUrl}\n`);
}

export async function containerRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;

  app.get("/api/v1/containers", async (req) => {
    const a = requireAuth(req);
    return loadContainers(db, a.id);
  });

  app.get("/api/v1/containers/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const [row] = await loadContainers(db, a.id, id);
    if (!row) throw notFound("container_not_found");
    const folders = await db.query("SELECT id, parent_id, meta_enc FROM folders WHERE container_id = $1 ORDER BY created_at", [id]);
    return { ...row, folders: folders.rows.map((f) => ({ id: f.id, parentId: f.parent_id, metaEnc: f.meta_enc })) };
  });

  app.post("/api/v1/containers", async (req) => {
    const a = requireAuth(req);
    const body = z.object({ id: uuid, kind: z.enum(["client", "personal"]), metaKeyEnc: envelope, metaEnc: envelope, grant: grantSchema }).parse(req.body);
    if (body.grant.containerId !== body.id || body.grant.recipientId !== a.id || body.grant.keyVersion !== 1 || body.grant.permission !== "manage") {
      throw badRequest("invalid_grant");
    }
    // Policy aziendale: i clienti li creano solo gli amministratori; l'area personale tutti.
    if (body.kind === "client" && a.role !== "admin") throw forbidden("admin_required");
    return tx(db, async (c) => {
      if (body.kind === "personal") {
        const ex = await c.query("SELECT 1 FROM containers WHERE kind = 'personal' AND created_by = $1 AND deleted_at IS NULL", [a.id]);
        if (ex.rowCount) throw conflict("personal_exists");
      }
      await c.query("INSERT INTO containers (id, kind, meta_key_enc, meta_enc, key_version, created_by) VALUES ($1,$2,$3,$4,1,$5)",
        [body.id, body.kind, body.metaKeyEnc, body.metaEnc, a.id]);
      await insertGrant(c, body.grant, a.id);
      await audit(c, { actorId: a.id, action: "container.created", targetType: "container", targetId: body.id, containerId: body.id, ip: req.ip, details: { kind: body.kind } });
      return { id: body.id };
    });
  });

  app.patch("/api/v1/containers/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { metaEnc } = z.object({ metaEnc: envelope }).parse(req.body);
    return tx(db, async (c) => {
      await requirePermission(c, id, a.id, "manage");
      await c.query("UPDATE containers SET meta_enc = $2, updated_at = now() WHERE id = $1", [id, metaEnc]);
      await audit(c, { actorId: a.id, action: "container.updated", targetType: "container", targetId: id, containerId: id, ip: req.ip });
      return { ok: true };
    });
  });

  app.delete("/api/v1/containers/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const p = await requirePermission(c, id, a.id, "manage");
      if (p.kind !== "client") throw forbidden("cannot_delete_container_kind");
      await c.query("UPDATE containers SET deleted_at = now() WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "container.deleted", targetType: "container", targetId: id, containerId: id, ip: req.ip });
      return { ok: true };
    });
  });

  // ------------------------------------------------------------ membri

  app.get("/api/v1/containers/:id/members", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const p = await requirePermission(db, id, a.id, "read");
    const r = await db.query(
      `SELECT k.user_id, u.display_name, u.email, k.permission, k.granted_by, k.created_at
         FROM container_keys k JOIN users u ON u.id = k.user_id
        WHERE k.container_id = $1 AND k.key_version = $2 ORDER BY u.display_name`, [id, p.keyVersion]);
    return r.rows.map((m) => ({ userId: m.user_id, displayName: m.display_name, email: m.email, permission: m.permission, grantedBy: m.granted_by, since: m.created_at }));
  });

  app.put("/api/v1/containers/:id/members", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { grant } = z.object({ grant: grantSchema }).parse(req.body);
    return tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      const p = await requirePermission(c, id, a.id, "manage");
      if (grant.containerId !== id || grant.keyVersion !== p.keyVersion) throw badRequest("stale_key_version");
      if (p.kind === "personal") throw forbidden("personal_not_shareable");
      if (p.kind === "org") {
        const r = await c.query("SELECT role FROM users WHERE id = $1", [grant.recipientId]);
        if (r.rows[0]?.role !== "admin") throw forbidden("org_admins_only");
        if (grant.permission !== "manage") throw badRequest("org_requires_manage");
      }
      if (grant.permission !== "manage" && (await managersLeft(c, id, p.keyVersion, grant.recipientId)) === 0) throw conflict("last_manager");
      const existed = await c.query("SELECT 1 FROM container_keys WHERE container_id = $1 AND key_version = $2 AND user_id = $3", [id, p.keyVersion, grant.recipientId]);
      await insertGrant(c, grant, a.id);
      await audit(c, { actorId: a.id, action: "container.member_set", targetType: "user", targetId: grant.recipientId, containerId: id, ip: req.ip, details: { permission: grant.permission } });
      return { ok: true, notify: !existed.rowCount && grant.recipientId !== a.id && p.kind === "client" };
    }).then(async (r) => {
      if (r.notify) await notifyShare(ctx, a.id, grant.recipientId, grant.permission);
      return { ok: true };
    });
  });

  app.delete("/api/v1/containers/:id/members/:userId", async (req) => {
    const a = requireAuth(req);
    const { id, userId } = z.object({ id: uuid, userId: uuid }).parse(req.params);
    return tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      const p = await requirePermission(c, id, a.id, "manage");
      if ((await managersLeft(c, id, p.keyVersion, userId)) === 0) throw conflict("last_manager");
      const r = await c.query("DELETE FROM container_keys WHERE container_id = $1 AND user_id = $2", [id, userId]);
      if (!r.rowCount) throw notFound("member_not_found");
      // Se il client non completa la rotazione, la farà il prossimo gestore.
      await c.query("UPDATE containers SET rotation_required = true WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "container.member_removed", targetType: "user", targetId: userId, containerId: id, ip: req.ip });
      return { ok: true, rotationRequired: true };
    });
  });

  /**
   * Rotazione atomica: nuova CK per tutti i membri rimasti e IK ricifrate.
   * Le vecchie consegne vengono eliminate nella stessa transazione.
   */
  app.post("/api/v1/containers/:id/rotate", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({
      newKeyVersion: z.number().int().min(2),
      metaKeyEnc: envelope,
      grants: z.array(grantSchema).max(1000),
      groupGrants: z.array(groupGrantSchema).max(200).default([]),
      items: z.array(z.object({ id: uuid, ikEnc: envelope })).max(100_000),
    }).parse(req.body);
    return tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      const p = await requirePermission(c, id, a.id, "manage");
      if (body.newKeyVersion !== p.keyVersion + 1) throw conflict("stale_key_version");
      const members = await c.query("SELECT user_id, permission FROM container_keys WHERE container_id = $1 AND key_version = $2", [id, p.keyVersion]);
      const expected = new Map(members.rows.map((m) => [m.user_id as string, m.permission as string]));
      if (body.grants.length !== expected.size) throw badRequest("grants_must_match_members");
      for (const g of body.grants) {
        if (g.containerId !== id || g.keyVersion !== body.newKeyVersion || expected.get(g.recipientId) !== g.permission) {
          throw badRequest("grants_must_match_members");
        }
        await insertGrant(c, g, a.id);
      }
      const groupRows = await c.query("SELECT group_id, permission FROM container_group_keys WHERE container_id = $1 AND key_version = $2", [id, p.keyVersion]);
      const expectedGroups = new Map(groupRows.rows.map((g) => [g.group_id as string, g.permission as string]));
      if (body.groupGrants.length !== expectedGroups.size) throw badRequest("group_grants_must_match");
      if (body.grants.length + body.groupGrants.length === 0) throw badRequest("no_members");
      for (const g of body.groupGrants) {
        if (g.containerId !== id || g.keyVersion !== body.newKeyVersion || expectedGroups.get(g.groupId) !== g.permission) {
          throw badRequest("group_grants_must_match");
        }
        await insertGroupGrant(c, g, a.id);
      }
      const items = await c.query("SELECT id FROM items WHERE container_id = $1", [id]);
      const sent = new Map(body.items.map((i) => [i.id, i.ikEnc]));
      if (sent.size !== items.rowCount || items.rows.some((r) => !sent.has(r.id))) throw badRequest("items_must_match");
      for (const [itemId, ikEnc] of sent) {
        await c.query("UPDATE items SET ik_enc = $3, ik_key_version = $4 WHERE id = $1 AND container_id = $2", [itemId, id, ikEnc, body.newKeyVersion]);
      }
      await c.query("UPDATE containers SET key_version = $2, meta_key_enc = $3, rotation_required = false, updated_at = now() WHERE id = $1", [id, body.newKeyVersion, body.metaKeyEnc]);
      await c.query("DELETE FROM container_keys WHERE container_id = $1 AND key_version < $2", [id, body.newKeyVersion]);
      await c.query("DELETE FROM container_group_keys WHERE container_id = $1 AND key_version < $2", [id, body.newKeyVersion]);
      await audit(c, { actorId: a.id, action: "container.key_rotated", targetType: "container", targetId: id, containerId: id, ip: req.ip, details: { keyVersion: body.newKeyVersion, members: body.grants.length, groups: body.groupGrants.length, items: sent.size } });
      return { ok: true, keyVersion: body.newKeyVersion };
    });
  });

  // ------------------------------------------------------------ condivisione con i gruppi

  app.get("/api/v1/containers/:id/groups", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const p = await requirePermission(db, id, a.id, "read");
    const r = await db.query(
      `SELECT gk.group_id, g.name, gk.permission, (SELECT count(*)::int FROM group_members gm WHERE gm.group_id = g.id AND gm.key_version = g.key_version) AS members
         FROM container_group_keys gk JOIN groups g ON g.id = gk.group_id AND g.deleted_at IS NULL
        WHERE gk.container_id = $1 AND gk.key_version = $2 ORDER BY g.name`, [id, p.keyVersion]);
    return r.rows.map((g) => ({ groupId: g.group_id, name: g.name, permission: g.permission, members: g.members }));
  });

  app.put("/api/v1/containers/:id/groups", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { grant } = z.object({ grant: groupGrantSchema }).parse(req.body);
    return tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      const p = await requirePermission(c, id, a.id, "manage");
      if (grant.containerId !== id || grant.keyVersion !== p.keyVersion) throw badRequest("stale_key_version");
      if (p.kind !== "client") throw forbidden("only_clients_shareable_with_groups");
      await insertGroupGrant(c, grant, a.id);
      await audit(c, { actorId: a.id, action: "container.group_set", targetType: "group", targetId: grant.groupId, containerId: id, ip: req.ip, details: { permission: grant.permission } });
      return { ok: true };
    });
  });

  app.delete("/api/v1/containers/:id/groups/:groupId", async (req) => {
    const a = requireAuth(req);
    const { id, groupId } = z.object({ id: uuid, groupId: uuid }).parse(req.params);
    return tx(db, async (c) => {
      await c.query("SELECT 1 FROM containers WHERE id = $1 FOR UPDATE", [id]);
      await requirePermission(c, id, a.id, "manage");
      const r = await c.query("DELETE FROM container_group_keys WHERE container_id = $1 AND group_id = $2", [id, groupId]);
      if (!r.rowCount) throw notFound("group_not_found");
      if ((await managersLeft(c, id, (await c.query("SELECT key_version FROM containers WHERE id = $1", [id])).rows[0].key_version, "00000000-0000-0000-0000-000000000000")) === 0) {
        throw conflict("last_manager");
      }
      await c.query("UPDATE containers SET rotation_required = true WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "container.group_removed", targetType: "group", targetId: groupId, containerId: id, ip: req.ip });
      return { ok: true, rotationRequired: true };
    });
  });

  // ------------------------------------------------------------ cartelle

  app.post("/api/v1/containers/:id/folders", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({ id: uuid, parentId: uuid.nullable().optional(), metaEnc: envelope }).parse(req.body);
    return tx(db, async (c) => {
      await requirePermission(c, id, a.id, "write");
      if (body.parentId) {
        const pf = await c.query("SELECT 1 FROM folders WHERE id = $1 AND container_id = $2", [body.parentId, id]);
        if (!pf.rowCount) throw badRequest("invalid_parent");
      }
      await c.query("INSERT INTO folders (id, container_id, parent_id, meta_enc) VALUES ($1,$2,$3,$4)", [body.id, id, body.parentId ?? null, body.metaEnc]);
      await audit(c, { actorId: a.id, action: "folder.created", targetType: "folder", targetId: body.id, containerId: id, ip: req.ip });
      return { id: body.id };
    });
  });

  app.patch("/api/v1/folders/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({ metaEnc: envelope }).parse(req.body);
    return tx(db, async (c) => {
      const f = await c.query("SELECT container_id FROM folders WHERE id = $1", [id]);
      if (!f.rows[0]) throw notFound();
      await requirePermission(c, f.rows[0].container_id, a.id, "write");
      await c.query("UPDATE folders SET meta_enc = $2 WHERE id = $1", [id, body.metaEnc]);
      return { ok: true };
    });
  });

  app.delete("/api/v1/folders/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const f = await c.query("SELECT container_id FROM folders WHERE id = $1", [id]);
      if (!f.rows[0]) throw notFound();
      await requirePermission(c, f.rows[0].container_id, a.id, "write");
      await c.query("DELETE FROM folders WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "folder.deleted", targetType: "folder", targetId: id, containerId: f.rows[0].container_id, ip: req.ip });
      return { ok: true };
    });
  });
}

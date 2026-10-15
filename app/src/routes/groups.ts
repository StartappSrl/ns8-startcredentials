/**
 * Gruppi. Li gestiscono gli amministratori che ne fanno parte come
 * "manager": servono la chiave dell'organizzazione (per certificare la chiave
 * del gruppo) e la chiave privata del gruppo (per ruotarla).
 */
import { FastifyInstance } from "fastify";
import { z } from "zod";
import { groupMemberMessage, verify, verifyGroupCert } from "@startcredentials/crypto";
import { audit, badRequest, conflict, forbidden, notFound, Tx, tx } from "../core.js";
import { Ctx, requireAdmin, requireAuth } from "../server.js";
import { schemas } from "./auth.js";
import { groupGrantSchema, insertGroupGrant } from "./containers.js";

const { b64 } = schemas;
const uuid = z.string().uuid();

const memberSchema = z.object({
  groupId: uuid,
  keyVersion: z.number().int().min(1),
  userId: uuid,
  role: z.enum(["member", "manager"]),
  sealedKey: b64,
  grantedBy: uuid,
  signature: b64,
});
type MemberGrant = z.infer<typeof memberSchema>;

async function orgSignPublic(c: Tx): Promise<string> {
  const r = await c.query("SELECT sign_public FROM org WHERE id = 1");
  if (!r.rows[0]) throw conflict("org_not_initialized");
  return r.rows[0].sign_public;
}

async function checkCert(c: Tx, groupId: string, keyVersion: number, boxPublic: string, certification: string) {
  try {
    verifyGroupCert(groupId, keyVersion, boxPublic, certification, await orgSignPublic(c));
  } catch {
    throw badRequest("invalid_group_certification");
  }
}

async function insertMember(c: Tx, g: MemberGrant, actorId: string) {
  if (g.grantedBy !== actorId) throw badRequest("grant_not_signed_by_actor");
  const k = await c.query(
    `SELECT u.id, u.status, k.sign_public, k.certification FROM users u
       JOIN user_keys k ON k.user_id = u.id AND k.version = u.key_version WHERE u.id = ANY($1::uuid[])`, [[actorId, g.userId]]);
  const actor = k.rows.find((r) => r.id === actorId);
  const rec = k.rows.find((r) => r.id === g.userId);
  const { signature, ...unsigned } = g;
  if (!actor || !verify(groupMemberMessage(unsigned), signature, actor.sign_public)) throw badRequest("invalid_grant_signature");
  if (!rec || rec.status !== "active") throw badRequest("recipient_not_active");
  if (!rec.certification) throw badRequest("recipient_not_certified");
  await c.query(
    `INSERT INTO group_members (group_id, key_version, user_id, role, sealed_key, granted_by, signature)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (group_id, key_version, user_id)
     DO UPDATE SET role = EXCLUDED.role, sealed_key = EXCLUDED.sealed_key, granted_by = EXCLUDED.granted_by,
                   signature = EXCLUDED.signature, created_at = now()`,
    [g.groupId, g.keyVersion, g.userId, g.role, g.sealedKey, g.grantedBy, g.signature]);
}

/** L'attore deve essere amministratore e manager del gruppo (versione corrente della chiave). */
async function requireManager(c: Tx, groupId: string, userId: string) {
  const r = await c.query(
    `SELECT g.*, gm.role FROM groups g
       LEFT JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version AND gm.user_id = $2
      WHERE g.id = $1 AND g.deleted_at IS NULL FOR UPDATE OF g`, [groupId, userId]);
  const g = r.rows[0];
  if (!g) throw notFound("group_not_found");
  if (g.role !== "manager") throw forbidden("group_manager_required");
  return g as { id: string; name: string; key_version: number; rotation_required: boolean };
}

async function markGroupForRotation(c: Tx, groupId: string) {
  await c.query("UPDATE groups SET rotation_required = true WHERE id = $1", [groupId]);
  await c.query("UPDATE containers SET rotation_required = true WHERE id IN (SELECT container_id FROM container_group_keys WHERE group_id = $1)", [groupId]);
}

export async function groupRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db } = ctx;

  app.get("/api/v1/groups", async (req) => {
    const a = requireAuth(req);
    const r = await db.query(
      `SELECT g.id, g.name, g.key_version, g.box_public, g.certification, g.rotation_required,
              (SELECT count(*)::int FROM group_members m WHERE m.group_id = g.id AND m.key_version = g.key_version) AS members,
              (SELECT role FROM group_members m WHERE m.group_id = g.id AND m.key_version = g.key_version AND m.user_id = $1) AS my_role,
              (SELECT count(DISTINCT gk.container_id)::int FROM container_group_keys gk JOIN containers c ON c.id = gk.container_id AND c.key_version = gk.key_version AND c.deleted_at IS NULL
                WHERE gk.group_id = g.id) AS containers
         FROM groups g WHERE g.deleted_at IS NULL ORDER BY g.name`, [a.id]);
    return r.rows.map((g) => ({
      id: g.id, name: g.name, keyVersion: g.key_version, boxPublic: g.box_public, certification: g.certification,
      rotationRequired: g.rotation_required, members: g.members, containers: g.containers, myRole: g.my_role,
    }));
  });

  app.get("/api/v1/groups/:id/members", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const r = await db.query(
      `SELECT gm.user_id, u.display_name, u.email, gm.role FROM groups g
         JOIN group_members gm ON gm.group_id = g.id AND gm.key_version = g.key_version
         JOIN users u ON u.id = gm.user_id
        WHERE g.id = $1 AND g.deleted_at IS NULL ORDER BY u.display_name`, [id]);
    if (a.role !== "admin" && !r.rows.some((m) => m.user_id === a.id)) throw forbidden();
    return r.rows.map((m) => ({ userId: m.user_id, displayName: m.display_name, email: m.email, role: m.role }));
  });

  app.post("/api/v1/groups", async (req) => {
    const a = requireAdmin(req);
    const body = z.object({ id: uuid, name: z.string().trim().min(1).max(80), boxPublic: b64, certification: b64, membership: memberSchema }).parse(req.body);
    const m = body.membership;
    if (m.groupId !== body.id || m.keyVersion !== 1 || m.userId !== a.id || m.role !== "manager") throw badRequest("invalid_membership");
    return tx(db, async (c) => {
      await checkCert(c, body.id, 1, body.boxPublic, body.certification);
      const dup = await c.query("SELECT 1 FROM groups WHERE lower(name) = lower($1) AND deleted_at IS NULL", [body.name]);
      if (dup.rowCount) throw conflict("group_name_taken");
      await c.query("INSERT INTO groups (id, name, key_version, box_public, certification, created_by) VALUES ($1,$2,1,$3,$4,$5)",
        [body.id, body.name, body.boxPublic, body.certification, a.id]);
      await insertMember(c, m, a.id);
      await audit(c, { actorId: a.id, action: "group.created", targetType: "group", targetId: body.id, ip: req.ip, details: { name: body.name } });
      return { id: body.id };
    });
  });

  app.patch("/api/v1/groups/:id", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body);
    return tx(db, async (c) => {
      await requireManager(c, id, a.id);
      await c.query("UPDATE groups SET name = $2 WHERE id = $1", [id, name]);
      await audit(c, { actorId: a.id, action: "group.renamed", targetType: "group", targetId: id, ip: req.ip, details: { name } });
      return { ok: true };
    });
  });

  app.delete("/api/v1/groups/:id", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      await requireManager(c, id, a.id);
      await c.query("UPDATE containers SET rotation_required = true WHERE id IN (SELECT container_id FROM container_group_keys WHERE group_id = $1)", [id]);
      await c.query("DELETE FROM container_group_keys WHERE group_id = $1", [id]);
      await c.query("DELETE FROM group_members WHERE group_id = $1", [id]);
      await c.query("UPDATE groups SET deleted_at = now() WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "group.deleted", targetType: "group", targetId: id, ip: req.ip });
      return { ok: true };
    });
  });

  app.put("/api/v1/groups/:id/members", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { grant } = z.object({ grant: memberSchema }).parse(req.body);
    return tx(db, async (c) => {
      const g = await requireManager(c, id, a.id);
      if (g.rotation_required) throw conflict("group_rotation_pending", "Prima va ruotata la chiave del gruppo");
      if (grant.groupId !== id || grant.keyVersion !== g.key_version) throw badRequest("stale_group_key_version");
      if (grant.role === "manager") {
        const r = await c.query("SELECT role FROM users WHERE id = $1", [grant.userId]);
        if (r.rows[0]?.role !== "admin") throw badRequest("group_managers_must_be_admins");
      } else {
        const others = await c.query("SELECT count(*)::int AS n FROM group_members WHERE group_id = $1 AND key_version = $2 AND role = 'manager' AND user_id <> $3",
          [id, g.key_version, grant.userId]);
        if (others.rows[0].n === 0) throw conflict("last_group_manager");
      }
      await insertMember(c, grant, a.id);
      await audit(c, { actorId: a.id, action: "group.member_set", targetType: "user", targetId: grant.userId, ip: req.ip, details: { groupId: id, role: grant.role } });
      return { ok: true };
    });
  });

  app.delete("/api/v1/groups/:id/members/:userId", async (req) => {
    const a = requireAdmin(req);
    const { id, userId } = z.object({ id: uuid, userId: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const g = await requireManager(c, id, a.id);
      const others = await c.query("SELECT count(*)::int AS n FROM group_members WHERE group_id = $1 AND key_version = $2 AND role = 'manager' AND user_id <> $3",
        [id, g.key_version, userId]);
      if (others.rows[0].n === 0) throw conflict("last_group_manager");
      const r = await c.query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2", [id, userId]);
      if (!r.rowCount) throw notFound("member_not_found");
      await markGroupForRotation(c, id);
      await audit(c, { actorId: a.id, action: "group.member_removed", targetType: "user", targetId: userId, ip: req.ip, details: { groupId: id } });
      return { ok: true, rotationRequired: true };
    });
  });

  /** Materiale per ruotare la chiave del gruppo: membri e condivisioni attuali. */
  app.get("/api/v1/groups/:id/rotation", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const g = await requireManager(c, id, a.id);
      const members = await c.query("SELECT user_id, role FROM group_members WHERE group_id = $1 AND key_version = $2", [id, g.key_version]);
      const mine = await c.query("SELECT * FROM group_members WHERE group_id = $1 AND key_version = $2 AND user_id = $3", [id, g.key_version, a.id]);
      const grants = await c.query(
        `SELECT gk.* FROM container_group_keys gk JOIN containers ct ON ct.id = gk.container_id AND ct.key_version = gk.key_version AND ct.deleted_at IS NULL
          WHERE gk.group_id = $1 AND gk.group_key_version = $2`, [id, g.key_version]);
      const full = await c.query("SELECT box_public, certification FROM groups WHERE id = $1", [id]);
      const m = mine.rows[0];
      return {
        group: { id, name: g.name, keyVersion: g.key_version, boxPublic: full.rows[0].box_public, certification: full.rows[0].certification },
        members: members.rows.map((x) => ({ userId: x.user_id, role: x.role })),
        membership: { groupId: id, keyVersion: m.key_version, userId: a.id, role: m.role, sealedKey: m.sealed_key, grantedBy: m.granted_by, signature: m.signature },
        containerGrants: grants.rows.map((x) => ({
          containerId: x.container_id, keyVersion: x.key_version, groupId: id, groupKeyVersion: x.group_key_version,
          permission: x.permission, sealedKey: x.sealed_key, grantedBy: x.granted_by, signature: x.signature,
        })),
      };
    });
  });

  /**
   * Rotazione della chiave del gruppo: nuova coppia certificata, consegnata a
   * tutti i membri rimasti, e chiavi dei contenitori ricondivise. Atomica.
   */
  app.post("/api/v1/groups/:id/rotate", async (req) => {
    const a = requireAdmin(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({
      newKeyVersion: z.number().int().min(2),
      boxPublic: b64,
      certification: b64,
      members: z.array(memberSchema).min(1).max(1000),
      containerGrants: z.array(groupGrantSchema).max(10_000),
    }).parse(req.body);
    return tx(db, async (c) => {
      const g = await requireManager(c, id, a.id);
      if (body.newKeyVersion !== g.key_version + 1) throw conflict("stale_group_key_version");
      await checkCert(c, id, body.newKeyVersion, body.boxPublic, body.certification);
      const members = await c.query("SELECT user_id, role FROM group_members WHERE group_id = $1 AND key_version = $2", [id, g.key_version]);
      const expected = new Map(members.rows.map((m) => [m.user_id as string, m.role as string]));
      if (body.members.length !== expected.size) throw badRequest("members_must_match");
      const grants = await c.query(
        `SELECT gk.container_id, gk.permission, ct.key_version AS container_version FROM container_group_keys gk
           JOIN containers ct ON ct.id = gk.container_id AND ct.key_version = gk.key_version AND ct.deleted_at IS NULL
          WHERE gk.group_id = $1 AND gk.group_key_version = $2`, [id, g.key_version]);
      const expectedGrants = new Map(grants.rows.map((x) => [x.container_id as string, x]));
      if (body.containerGrants.length !== expectedGrants.size) throw badRequest("container_grants_must_match");

      // Aggiorna prima il gruppo: insertGroupGrant controlla versione e stato correnti.
      await c.query("UPDATE groups SET key_version = $2, box_public = $3, certification = $4, rotation_required = false WHERE id = $1",
        [id, body.newKeyVersion, body.boxPublic, body.certification]);
      for (const m of body.members) {
        if (m.groupId !== id || m.keyVersion !== body.newKeyVersion || expected.get(m.userId) !== m.role) throw badRequest("members_must_match");
        await insertMember(c, m, a.id);
      }
      for (const gg of body.containerGrants) {
        const e = expectedGrants.get(gg.containerId);
        if (!e || gg.groupId !== id || gg.groupKeyVersion !== body.newKeyVersion || gg.keyVersion !== e.container_version || gg.permission !== e.permission) {
          throw badRequest("container_grants_must_match");
        }
        await insertGroupGrant(c, gg, a.id);
      }
      await c.query("DELETE FROM group_members WHERE group_id = $1 AND key_version < $2", [id, body.newKeyVersion]);
      await audit(c, { actorId: a.id, action: "group.key_rotated", targetType: "group", targetId: id, ip: req.ip,
        details: { keyVersion: body.newKeyVersion, members: body.members.length, containers: body.containerGrants.length } });
      return { ok: true, keyVersion: body.newKeyVersion };
    });
  });

}

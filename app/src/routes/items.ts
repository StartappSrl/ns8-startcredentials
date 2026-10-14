import { FastifyInstance } from "fastify";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { audit, badRequest, conflict, Db, notFound, Tx, tx } from "../core.js";
import { Ctx, requireAuth } from "../server.js";
import { schemas } from "./auth.js";
import { requirePermission } from "./containers.js";

const { b64, envelope } = schemas;
const uuid = z.string().uuid();
const itemType = z.enum(["login", "totp", "note", "file", "ssh_key"]);
const hostHashes = z.array(b64.max(100)).max(20).default([]);
const KEEP_VERSIONS = 20;

const newItem = z.object({
  id: uuid,
  folderId: uuid.nullable().optional(),
  type: itemType,
  ikEnc: envelope,
  ikKeyVersion: z.number().int().min(1),
  dataEnc: envelope,
  hostHashes,
});

async function itemContainer(db: Db | Tx, itemId: string) {
  const r = await db.query("SELECT container_id FROM items WHERE id = $1", [itemId]);
  if (!r.rows[0]) throw notFound("item_not_found");
  return r.rows[0].container_id as string;
}

async function checkFolder(c: Tx, folderId: string | null | undefined, containerId: string) {
  if (!folderId) return;
  const f = await c.query("SELECT 1 FROM folders WHERE id = $1 AND container_id = $2", [folderId, containerId]);
  if (!f.rowCount) throw badRequest("invalid_folder");
}

export async function itemRoutes(app: FastifyInstance, ctx: Ctx) {
  const { db, cfg } = ctx;

  app.get("/api/v1/containers/:id/items", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { trash } = z.object({ trash: z.enum(["0", "1"]).default("0") }).parse(req.query);
    await requirePermission(db, id, a.id, "read");
    const items = await db.query(
      `SELECT i.id, i.folder_id, i.type, i.ik_enc, i.ik_key_version, i.data_enc, i.revision, i.updated_at, i.deleted_at, u.display_name AS updated_by
         FROM items i JOIN users u ON u.id = i.updated_by
        WHERE i.container_id = $1 AND (i.deleted_at IS ${trash === "1" ? "NOT " : ""}NULL)
        ORDER BY i.updated_at DESC`, [id]);
    const att = await db.query(
      "SELECT id, item_id, fk_enc, meta_enc, header, size, chunk_count FROM attachments WHERE container_id = $1 AND status = 'ready' ORDER BY created_at", [id]);
    const byItem = new Map<string, unknown[]>();
    for (const r of att.rows) {
      const list = byItem.get(r.item_id) ?? [];
      list.push({ id: r.id, fkEnc: r.fk_enc, metaEnc: r.meta_enc, header: r.header, size: Number(r.size), chunkCount: r.chunk_count });
      byItem.set(r.item_id, list);
    }
    return items.rows.map((r) => ({
      id: r.id, folderId: r.folder_id, type: r.type, ikEnc: r.ik_enc, ikKeyVersion: r.ik_key_version,
      dataEnc: r.data_enc, revision: r.revision, updatedAt: r.updated_at, updatedBy: r.updated_by,
      deletedAt: r.deleted_at, attachments: byItem.get(r.id) ?? [],
    }));
  });

  app.post("/api/v1/containers/:id/items", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = newItem.parse(req.body);
    return tx(db, async (c) => {
      const p = await requirePermission(c, id, a.id, "write");
      if (body.ikKeyVersion !== p.keyVersion) throw conflict("stale_key_version");
      await checkFolder(c, body.folderId, id);
      await c.query(
        `INSERT INTO items (id, container_id, folder_id, type, ik_enc, ik_key_version, data_enc, host_hashes, created_by, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
        [body.id, id, body.folderId ?? null, body.type, body.ikEnc, body.ikKeyVersion, body.dataEnc, body.hostHashes, a.id]);
      await c.query("UPDATE containers SET updated_at = now() WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "item.created", targetType: "item", targetId: body.id, containerId: id, ip: req.ip, details: { type: body.type } });
      return { id: body.id, revision: 1 };
    });
  });

  app.put("/api/v1/items/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({
      revision: z.number().int().min(1),
      dataEnc: envelope,
      hostHashes,
      folderId: uuid.nullable().optional(),
      type: itemType.optional(),
    }).parse(req.body);
    return tx(db, async (c) => {
      const cur = await c.query("SELECT container_id, revision, data_enc, updated_by FROM items WHERE id = $1 AND deleted_at IS NULL FOR UPDATE", [id]);
      const it = cur.rows[0];
      if (!it) throw notFound("item_not_found");
      await requirePermission(c, it.container_id, a.id, "write");
      if (it.revision !== body.revision) throw conflict("revision_conflict", "L'elemento è stato modificato da un altro utente");
      if (body.folderId !== undefined) await checkFolder(c, body.folderId, it.container_id);
      await c.query("INSERT INTO item_versions (item_id, revision, data_enc, created_by) VALUES ($1,$2,$3,$4)", [id, it.revision, it.data_enc, it.updated_by]);
      await c.query("DELETE FROM item_versions WHERE item_id = $1 AND revision <= $2", [id, it.revision - KEEP_VERSIONS]);
      const next = it.revision + 1;
      await c.query(
        `UPDATE items SET data_enc = $2, host_hashes = $3, revision = $4, updated_by = $5, updated_at = now(),
                folder_id = CASE WHEN $6::boolean THEN $7::uuid ELSE folder_id END, type = COALESCE($8, type)
          WHERE id = $1`,
        [id, body.dataEnc, body.hostHashes, next, a.id, body.folderId !== undefined, body.folderId ?? null, body.type ?? null]);
      await c.query("UPDATE containers SET updated_at = now() WHERE id = $1", [it.container_id]);
      await audit(c, { actorId: a.id, action: "item.updated", targetType: "item", targetId: id, containerId: it.container_id, ip: req.ip, details: { revision: next } });
      return { id, revision: next };
    });
  });

  app.delete("/api/v1/items/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const containerId = await itemContainer(c, id);
      await requirePermission(c, containerId, a.id, "write");
      await c.query("UPDATE items SET deleted_at = now(), updated_by = $2 WHERE id = $1 AND deleted_at IS NULL", [id, a.id]);
      await audit(c, { actorId: a.id, action: "item.deleted", targetType: "item", targetId: id, containerId, ip: req.ip });
      return { ok: true };
    });
  });

  app.post("/api/v1/items/:id/restore", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const containerId = await itemContainer(c, id);
      await requirePermission(c, containerId, a.id, "write");
      await c.query("UPDATE items SET deleted_at = NULL, updated_by = $2, updated_at = now() WHERE id = $1", [id, a.id]);
      await audit(c, { actorId: a.id, action: "item.restored", targetType: "item", targetId: id, containerId, ip: req.ip });
      return { ok: true };
    });
  });

  app.get("/api/v1/items/:id/versions", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const containerId = await itemContainer(db, id);
    await requirePermission(db, containerId, a.id, "read");
    const r = await db.query(
      `SELECT v.revision, v.data_enc, v.created_at, u.display_name FROM item_versions v JOIN users u ON u.id = v.created_by
        WHERE v.item_id = $1 ORDER BY v.revision DESC`, [id]);
    return r.rows.map((v) => ({ revision: v.revision, dataEnc: v.data_enc, createdAt: v.created_at, by: v.display_name }));
  });

  // ------------------------------------------------------------ allegati

  const chunkPath = (id: string, n: number) => join(cfg.attachmentsDir, id.slice(0, 2), id, String(n));

  async function attachmentFor(c: Db | Tx, id: string) {
    const r = await c.query("SELECT * FROM attachments WHERE id = $1", [id]);
    if (!r.rows[0]) throw notFound("attachment_not_found");
    return r.rows[0];
  }

  app.post("/api/v1/items/:id/attachments", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({
      id: uuid, fkEnc: envelope, metaEnc: envelope, header: b64.max(100),
      size: z.number().int().min(0), chunkCount: z.number().int().min(1).max(10_000),
    }).parse(req.body);
    if (body.size > cfg.maxAttachmentBytes) throw badRequest("attachment_too_large", `Limite ${Math.round(cfg.maxAttachmentBytes / 1048576)} MiB`);
    return tx(db, async (c) => {
      const containerId = await itemContainer(c, id);
      await requirePermission(c, containerId, a.id, "write");
      await c.query(
        `INSERT INTO attachments (id, item_id, container_id, fk_enc, meta_enc, header, size, chunk_count, status, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'uploading',$9)`,
        [body.id, id, containerId, body.fkEnc, body.metaEnc, body.header, body.size, body.chunkCount, a.id]);
      return { id: body.id };
    });
  });

  app.put("/api/v1/attachments/:id/chunks/:n", async (req) => {
    const a = requireAuth(req);
    const { id, n } = z.object({ id: uuid, n: z.coerce.number().int().min(0) }).parse(req.params);
    const at = await attachmentFor(db, id);
    await requirePermission(db, at.container_id, a.id, "write");
    if (at.status !== "uploading" || n >= at.chunk_count) throw badRequest("invalid_chunk");
    if (!Buffer.isBuffer(req.body)) throw badRequest("octet_stream_required");
    const p = chunkPath(id, n);
    await mkdir(join(p, ".."), { recursive: true });
    await writeFile(p, req.body);
    return { ok: true };
  });

  app.post("/api/v1/attachments/:id/complete", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return tx(db, async (c) => {
      const at = await attachmentFor(c, id);
      await requirePermission(c, at.container_id, a.id, "write");
      let total = 0;
      for (let i = 0; i < at.chunk_count; i++) {
        try {
          total += (await stat(chunkPath(id, i))).size;
        } catch {
          throw badRequest("missing_chunks");
        }
      }
      if (total > cfg.maxAttachmentBytes + at.chunk_count * 64) throw badRequest("attachment_too_large");
      await c.query("UPDATE attachments SET status = 'ready' WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "attachment.added", targetType: "item", targetId: at.item_id, containerId: at.container_id, ip: req.ip, details: { attachmentId: id, size: Number(at.size) } });
      return { ok: true };
    });
  });

  app.get("/api/v1/attachments/:id/chunks/:n", async (req, reply) => {
    const a = requireAuth(req);
    const { id, n } = z.object({ id: uuid, n: z.coerce.number().int().min(0) }).parse(req.params);
    const at = await attachmentFor(db, id);
    await requirePermission(db, at.container_id, a.id, "read");
    if (at.status !== "ready" || n >= at.chunk_count) throw notFound();
    return reply.type("application/octet-stream").send(await readFile(chunkPath(id, n)));
  });

  app.delete("/api/v1/attachments/:id", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    await tx(db, async (c) => {
      const at = await attachmentFor(c, id);
      await requirePermission(c, at.container_id, a.id, "write");
      await c.query("DELETE FROM attachments WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "attachment.deleted", targetType: "item", targetId: at.item_id, containerId: at.container_id, ip: req.ip, details: { attachmentId: id } });
    });
    await rm(join(cfg.attachmentsDir, id.slice(0, 2), id), { recursive: true, force: true });
    return { ok: true };
  });

  // ------------------------------------------------------------ ricerca autofill

  app.post("/api/v1/lookup", async (req) => {
    const a = requireAuth(req);
    const { queries } = z.object({ queries: z.array(z.object({ containerId: uuid, hostHash: b64.max(100) })).max(1000) }).parse(req.body);
    if (!queries.length) return [];
    const r = await db.query(
      `SELECT i.id, i.container_id FROM items i
         JOIN containers c ON c.id = i.container_id AND c.deleted_at IS NULL
         JOIN container_keys k ON k.container_id = c.id AND k.key_version = c.key_version AND k.user_id = $1
         JOIN unnest($2::uuid[], $3::text[]) AS q(container_id, host_hash) ON q.container_id = i.container_id
        WHERE i.deleted_at IS NULL AND i.host_hashes @> ARRAY[q.host_hash]`,
      [a.id, queries.map((q) => q.containerId), queries.map((q) => q.hostHash)]);
    return r.rows.map((x) => ({ itemId: x.id, containerId: x.container_id }));
  });

  // ------------------------------------------------------------ import

  app.post("/api/v1/containers/:id/import", async (req) => {
    const a = requireAuth(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z.object({
      source: z.string().max(40),
      folders: z.array(z.object({ id: uuid, parentId: uuid.nullable().optional(), metaEnc: envelope })).max(5000).default([]),
      items: z.array(newItem).max(5000),
    }).parse(req.body);
    return tx(db, async (c) => {
      const p = await requirePermission(c, id, a.id, "write");
      for (const f of body.folders) {
        await c.query("INSERT INTO folders (id, container_id, parent_id, meta_enc) VALUES ($1,$2,$3,$4)", [f.id, id, f.parentId ?? null, f.metaEnc]);
      }
      for (const it of body.items) {
        if (it.ikKeyVersion !== p.keyVersion) throw conflict("stale_key_version");
        await checkFolder(c, it.folderId, id);
        await c.query(
          `INSERT INTO items (id, container_id, folder_id, type, ik_enc, ik_key_version, data_enc, host_hashes, created_by, updated_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
          [it.id, id, it.folderId ?? null, it.type, it.ikEnc, it.ikKeyVersion, it.dataEnc, it.hostHashes, a.id]);
      }
      await c.query("UPDATE containers SET updated_at = now() WHERE id = $1", [id]);
      await audit(c, { actorId: a.id, action: "container.imported", targetType: "container", targetId: id, containerId: id, ip: req.ip, details: { source: body.source, items: body.items.length, folders: body.folders.length } });
      return { imported: body.items.length, folders: body.folders.length };
    });
  });
}

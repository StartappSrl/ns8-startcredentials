/**
 * Infrastruttura del server: configurazione, database, errori HTTP,
 * token, cifratura dei segreti MFA, rate limiting e registro di audit.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";

// ---------------------------------------------------------------- config

export interface Config {
  databaseUrl: string;
  serverSecret: Buffer; // 32 byte: cifra i segreti MFA e firma i token
  bootstrapToken: string;
  publicUrl: string;
  attachmentsDir: string;
  port: number;
  maxAttachmentBytes: number;
  sessionHours: number;
  /** Tentativi di autenticazione al minuto per indirizzo IP. */
  authPerIpPerMinute?: number;
  smtp?: { host: string; port: number; user?: string; pass?: string; secure: boolean; from: string };
}

export function loadConfig(env = process.env): Config {
  const need = (k: string) => {
    const v = env[k];
    if (!v) throw new Error(`Variabile d'ambiente mancante: ${k}`);
    return v;
  };
  const secret = Buffer.from(need("SERVER_SECRET"), "base64");
  if (secret.length !== 32) throw new Error("SERVER_SECRET deve essere di 32 byte in base64");
  const host = env.STARTCREDENTIALS_HOST;
  return {
    databaseUrl: need("DATABASE_URL"),
    serverSecret: secret,
    bootstrapToken: need("BOOTSTRAP_TOKEN"),
    publicUrl: env.PUBLIC_URL ?? (host ? `https://${host}` : "http://localhost:8080"),
    attachmentsDir: env.ATTACHMENTS_DIR ?? "/srv/attachments",
    port: Number(env.PORT ?? 8080),
    maxAttachmentBytes: Number(env.MAX_ATTACHMENT_MB ?? 50) * 1024 * 1024,
    sessionHours: Number(env.SESSION_HOURS ?? 12),
    authPerIpPerMinute: Number(env.AUTH_RATE_LIMIT ?? 30),
    smtp: env.SMTP_HOST && env.SMTP_ENABLED !== "0"
      ? {
          host: env.SMTP_HOST,
          port: Number(env.SMTP_PORT ?? 587),
          user: env.SMTP_USERNAME || undefined,
          pass: env.SMTP_PASSWORD || undefined,
          secure: env.SMTP_ENCRYPTION === "tls",
          from: env.SMTP_FROM ?? `startcredentials@${host ?? "localhost"}`,
        }
      : undefined,
  };
}

// ---------------------------------------------------------------- database

export type Db = pg.Pool;
export type Tx = pg.PoolClient;

export function createPool(url: string): Db {
  return new pg.Pool({ connectionString: url, max: 10 });
}

export async function migrate(db: Db, dir: string): Promise<void> {
  await db.query("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    const done = await db.query("SELECT 1 FROM schema_migrations WHERE name = $1", [f]);
    if (done.rowCount) continue;
    await tx(db, async (c) => {
      await c.query(readFileSync(join(dir, f), "utf8"));
      await c.query("INSERT INTO schema_migrations (name) VALUES ($1)", [f]);
    });
  }
}

export async function tx<T>(db: Db, fn: (c: Tx) => Promise<T>): Promise<T> {
  const c = await db.connect();
  try {
    await c.query("BEGIN");
    const r = await fn(c);
    await c.query("COMMIT");
    return r;
  } catch (e) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

export async function getSetting(db: Db | Tx, key: string): Promise<string | undefined> {
  const r = await db.query("SELECT value FROM settings WHERE key = $1", [key]);
  return r.rows[0]?.value;
}

export async function setSetting(db: Db | Tx, key: string, value: string): Promise<void> {
  await db.query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", [key, value]);
}

// ---------------------------------------------------------------- errori

export class HttpError extends Error {
  constructor(public status: number, public code: string, message?: string) {
    super(message ?? code);
  }
}
export const badRequest = (code: string, msg?: string) => new HttpError(400, code, msg);
export const unauthorized = (code = "unauthorized") => new HttpError(401, code);
export const forbidden = (code = "forbidden") => new HttpError(403, code);
export const notFound = (code = "not_found") => new HttpError(404, code);
export const conflict = (code: string, msg?: string) => new HttpError(409, code, msg);

// ---------------------------------------------------------------- token

export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

/** I token sono salvati solo come HMAC: un dump del database non li rivela. */
export function tokenHash(cfg: Config, token: string): string {
  return createHmac("sha256", cfg.serverSecret).update(token).digest("base64url");
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---------------------------------------------------------------- segreti MFA

export function encryptServerSecret(cfg: Config, plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", cfg.serverSecret, iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64url");
}

export function decryptServerSecret(cfg: Config, enc: string): string {
  const raw = Buffer.from(enc, "base64url");
  const d = createDecipheriv("aes-256-gcm", cfg.serverSecret, raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8");
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(s: string): Buffer {
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const ch of s.toUpperCase().replace(/=+$/, "")) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totpAt(secretB32: string, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", base32Decode(secretB32)).update(msg).digest();
  const o = mac[mac.length - 1]! & 15;
  const bin = ((mac[o]! & 0x7f) << 24) | (mac[o + 1]! << 16) | (mac[o + 2]! << 8) | mac[o + 3]!;
  return String(bin % 1_000_000).padStart(6, "0");
}

/** Verifica con tolleranza di ±1 intervallo; restituisce il contatore usato (anti-riuso). */
export function verifyTotp(secretB32: string, code: string, lastCounter: number, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const cur = Math.floor(now / 30000);
  for (const c of [cur - 1, cur, cur + 1]) {
    if (c > lastCounter && safeEqual(totpAt(secretB32, c), code)) return c;
  }
  return null;
}

// ---------------------------------------------------------------- rate limiting

export class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();
  constructor(private limit: number, private windowMs: number) {}

  check(key: string): void {
    const now = Date.now();
    const h = this.hits.get(key);
    if (!h || h.reset < now) {
      this.hits.set(key, { n: 1, reset: now + this.windowMs });
      if (this.hits.size > 50_000) this.prune(now);
      return;
    }
    h.n++;
    if (h.n > this.limit) throw new HttpError(429, "rate_limited", "Troppi tentativi, riprova tra poco");
  }

  private prune(now: number) {
    for (const [k, v] of this.hits) if (v.reset < now) this.hits.delete(k);
  }
}

// ---------------------------------------------------------------- audit

export interface AuditEvent {
  actorId?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  containerId?: string | null;
  ip?: string;
  details?: Record<string, unknown>;
}

/** JSON con chiavi ordinate: jsonb di PostgreSQL non conserva l'ordine delle chiavi. */
function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

function auditHash(prev: string, at: string, e: AuditEvent): string {
  const canonical = stable([
    prev, at, e.actorId ?? null, e.action, e.targetType ?? null, e.targetId ?? null,
    e.containerId ?? null, e.ip ?? null, e.details ?? {},
  ]);
  return createHash("sha256").update(canonical).digest("hex");
}

/** Aggiunge una riga alla catena di hash. Va chiamata dentro una transazione. */
export async function audit(c: Tx, e: AuditEvent): Promise<void> {
  await c.query("SELECT pg_advisory_xact_lock(7123001)");
  const last = await c.query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1");
  const prev: string = last.rows[0]?.hash ?? "genesis";
  const at = new Date().toISOString();
  const hash = auditHash(prev, at, e);
  await c.query(
    `INSERT INTO audit_log (at, actor_id, action, target_type, target_id, container_id, ip, details, prev_hash, hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [at, e.actorId ?? null, e.action, e.targetType ?? null, e.targetId ?? null, e.containerId ?? null, e.ip ?? null, e.details ?? {}, prev, hash],
  );
}

export async function verifyAuditChain(db: Db): Promise<{ ok: boolean; rows: number; brokenAt?: number }> {
  const r = await db.query("SELECT * FROM audit_log ORDER BY id");
  let prev = "genesis";
  for (const row of r.rows) {
    const at = new Date(row.at).toISOString();
    const expected = auditHash(prev, at, {
      actorId: row.actor_id, action: row.action, targetType: row.target_type ?? undefined,
      targetId: row.target_id ?? undefined, containerId: row.container_id, ip: row.ip ?? undefined, details: row.details,
    });
    if (row.prev_hash !== prev || row.hash !== expected) return { ok: false, rows: r.rowCount ?? 0, brokenAt: Number(row.id) };
    prev = row.hash;
  }
  return { ok: true, rows: r.rowCount ?? 0 };
}

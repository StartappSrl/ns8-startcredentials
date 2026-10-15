/**
 * Import da altri gestori di password. Tutto avviene sul dispositivo:
 * il file originale non viene mai inviato al server.
 */
import { unzipSync } from "fflate";
import type { ItemData } from "@startcredentials/crypto";
import type { Container, Vault } from "../vault.js";
import { KEEPASS_TOTP_FIELDS, keepassTotpUri } from "../totp-fields.js";

export type ImportSource = "csv" | "bitwarden" | "1password" | "keepass";

export interface ImportedFolder { key: string; name: string; parentKey: string | null }
export interface ImportedItem { folderKey: string | null; data: ItemData }
export interface ImportResult { source: string; folders: ImportedFolder[]; items: ImportedItem[]; skipped: { name: string; reason: string }[] }

// ------------------------------------------------------------------ CSV (RFC 4180)

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  const s = text.replace(/^\uFEFF/, "");
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (quoted) {
      if (ch === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && s[i + 1] === "\n") i++;
      row.push(field);
      if (row.some((f) => f !== "")) rows.push(row);
      row = [];
      field = "";
    } else field += ch;
  }
  row.push(field);
  if (row.some((f) => f !== "")) rows.push(row);
  return rows;
}

const SYN: Record<string, string[]> = {
  name: ["name", "title", "account", "resource name", "resource", "nome", "titolo"],
  username: ["username", "login name", "login", "login_username", "user", "user name", "email", "utente", "nome utente"],
  password: ["password", "login_password", "pass"],
  url: ["url", "web site", "website", "uri", "login_uri", "uris", "sito"],
  notes: ["notes", "note", "comments", "comment", "extra", "description", "descrizione"],
  totp: ["totp", "otp", "login_totp", "one-time password", "otpauth"],
  folder: ["folder", "group", "grouping", "folder path", "path", "cartella", "gruppo"],
};

function totpToUri(value: string, name: string): string | undefined {
  const v = value.trim();
  if (!v) return undefined;
  if (v.startsWith("otpauth://")) return v;
  const secret = v.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(secret)) return undefined;
  return `otpauth://totp/${encodeURIComponent(name || "Importato")}?secret=${secret}`;
}

class FolderTree {
  folders: ImportedFolder[] = [];
  private byPath = new Map<string, string>();

  /** "Clienti/Rossi/Server" → crea la gerarchia e restituisce la chiave della foglia. */
  get(path: string | undefined | null, sep = "/"): string | null {
    const parts = (path ?? "").split(sep).map((p) => p.trim()).filter(Boolean);
    let parent: string | null = null;
    let acc = "";
    for (const p of parts) {
      acc = acc ? `${acc}${sep}${p}` : p;
      let key = this.byPath.get(acc);
      if (!key) {
        key = `f${this.folders.length + 1}`;
        this.folders.push({ key, name: p, parentKey: parent });
        this.byPath.set(acc, key);
      }
      parent = key;
    }
    return parent;
  }
}

function cleanItem(d: ItemData): ItemData {
  const out: ItemData = { type: d.type, name: d.name.trim() || "Senza nome" };
  if (d.username?.trim()) out.username = d.username.trim();
  if (d.password) out.password = d.password;
  const urls = (d.urls ?? []).map((u) => u.trim()).filter(Boolean);
  if (urls.length) out.urls = urls;
  if (d.totpUri) out.totpUri = d.totpUri;
  if (d.notes?.trim()) out.notes = d.notes;
  if (d.fields?.length) out.fields = d.fields;
  return out;
}

/** CSV generico: Chrome, Edge, LastPass, Passbolt (CSV KeePass/LastPass), Bitwarden CSV, KeePass CSV. */
export function importCsv(text: string, source = "csv"): ImportResult {
  const rows = parseCsv(text);
  const header = (rows.shift() ?? []).map((h) => h.trim().toLowerCase());
  const col = (k: string) => header.findIndex((h) => SYN[k]!.includes(h));
  const idx = Object.fromEntries(Object.keys(SYN).map((k) => [k, col(k)])) as Record<string, number>;
  if (idx.password! < 0 && idx.username! < 0) throw new Error("Intestazioni CSV non riconosciute: servono almeno le colonne utente o password");
  const tree = new FolderTree();
  const res: ImportResult = { source, folders: [], items: [], skipped: [] };
  const get = (r: string[], k: string) => (idx[k]! >= 0 ? r[idx[k]!] ?? "" : "");
  for (const r of rows) {
    const url = get(r, "url");
    const name = get(r, "name") || hostOf(url) || get(r, "username");
    // LastPass marca le note sicure con url "http://sn".
    const isNote = url === "http://sn" || (!get(r, "password") && !get(r, "username") && !!get(r, "notes"));
    if (!name && !get(r, "password")) {
      res.skipped.push({ name: "(riga vuota)", reason: "Nessun dato utile" });
      continue;
    }
    const totp = totpToUri(get(r, "totp"), name);
    res.items.push({
      folderKey: tree.get(get(r, "folder").replace(/\\/g, "/")),
      data: cleanItem({
        type: isNote ? "note" : "login", name, username: get(r, "username"), password: get(r, "password"),
        urls: isNote || !url ? [] : url.split(/[\n,]/), notes: get(r, "notes"), totpUri: totp,
      }),
    });
  }
  res.folders = tree.folders;
  return res;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// ------------------------------------------------------------------ Bitwarden JSON

interface BwItem {
  type: number; name: string; notes?: string | null; folderId?: string | null; collectionIds?: string[] | null;
  login?: { username?: string | null; password?: string | null; totp?: string | null; uris?: { uri?: string | null }[] | null };
  fields?: { name?: string | null; value?: string | null; type?: number }[] | null;
  card?: Record<string, string | null>; identity?: Record<string, string | null>;
}

export function importBitwarden(text: string): ImportResult {
  const j = JSON.parse(text) as { encrypted?: boolean; folders?: { id: string; name: string }[]; collections?: { id: string; name: string }[]; items?: BwItem[] };
  if (j.encrypted) throw new Error("L'export Bitwarden è cifrato: esporta in formato JSON non cifrato");
  const tree = new FolderTree();
  const folderPath = new Map((j.folders ?? []).map((f) => [f.id, f.name]));
  for (const c of j.collections ?? []) folderPath.set(c.id, c.name);
  const res: ImportResult = { source: "bitwarden", folders: [], items: [], skipped: [] };
  for (const it of j.items ?? []) {
    const path = it.folderId ? folderPath.get(it.folderId) : it.collectionIds?.[0] ? folderPath.get(it.collectionIds[0]) : undefined;
    const fields = (it.fields ?? []).filter((f) => f.name).map((f) => ({ label: f.name!, value: f.value ?? "", secret: f.type === 1 }));
    if (it.type === 1) {
      res.items.push({
        folderKey: tree.get(path),
        data: cleanItem({
          type: "login", name: it.name, username: it.login?.username ?? "", password: it.login?.password ?? "",
          urls: (it.login?.uris ?? []).map((u) => u.uri ?? "").filter(Boolean),
          totpUri: totpToUri(it.login?.totp ?? "", it.name), notes: it.notes ?? "", fields,
        }),
      });
    } else if (it.type === 2) {
      res.items.push({ folderKey: tree.get(path), data: cleanItem({ type: "note", name: it.name, notes: it.notes ?? "", fields }) });
    } else {
      // Carte e identità diventano note con campi riservati.
      const extra = Object.entries(it.card ?? it.identity ?? {}).filter(([, v]) => v).map(([k, v]) => ({ label: k, value: String(v), secret: true }));
      res.items.push({ folderKey: tree.get(path), data: cleanItem({ type: "note", name: it.name, notes: it.notes ?? "", fields: [...fields, ...extra] }) });
    }
  }
  res.folders = tree.folders;
  return res;
}

// ------------------------------------------------------------------ 1Password (.1pux)

interface OpField { title?: string; id?: string; value?: Record<string, unknown> }
interface OpItem {
  state?: string;
  overview?: { title?: string; url?: string; urls?: { url?: string }[] };
  details?: { loginFields?: { designation?: string; value?: string; name?: string }[]; notesPlain?: string; password?: string; sections?: { title?: string; fields?: OpField[] }[] };
}

export function import1Password(data: Uint8Array): ImportResult {
  const files = unzipSync(data);
  const raw = files["export.data"];
  if (!raw) throw new Error("File .1pux non valido: manca export.data");
  const j = JSON.parse(new TextDecoder().decode(raw)) as { accounts?: { vaults?: { attrs?: { name?: string }; items?: OpItem[] }[] }[] };
  const tree = new FolderTree();
  const res: ImportResult = { source: "1password", folders: [], items: [], skipped: [] };
  for (const acc of j.accounts ?? []) {
    for (const v of acc.vaults ?? []) {
      const folderKey = tree.get(v.attrs?.name ?? "1Password");
      for (const it of v.items ?? []) {
        if (it.state === "archived") continue;
        const name = it.overview?.title ?? "Senza nome";
        const lf = it.details?.loginFields ?? [];
        let totp: string | undefined;
        const fields: NonNullable<ItemData["fields"]> = [];
        for (const s of it.details?.sections ?? []) {
          for (const f of s.fields ?? []) {
            const val = f.value ?? {};
            if (typeof val.totp === "string") totp = totpToUri(val.totp, name);
            else {
              const [kind, value] = Object.entries(val)[0] ?? [];
              if (typeof value === "string" && value) fields.push({ label: f.title || f.id || "campo", value, secret: kind === "concealed" });
            }
          }
        }
        const urls = [it.overview?.url, ...(it.overview?.urls ?? []).map((u) => u.url)].filter((u): u is string => !!u);
        const username = lf.find((f) => f.designation === "username")?.value ?? "";
        const password = lf.find((f) => f.designation === "password")?.value ?? it.details?.password ?? "";
        res.items.push({
          folderKey,
          data: cleanItem({
            type: username || password ? "login" : "note", name, username, password,
            urls: [...new Set(urls)], totpUri: totp, notes: it.details?.notesPlain ?? "", fields,
          }),
        });
      }
    }
  }
  res.folders = tree.folders;
  return res;
}

// ------------------------------------------------------------------ KeePass / KeePassXC / Passbolt (.kdbx)

export async function importKeePass(data: ArrayBuffer, password: string, keyFile?: ArrayBuffer): Promise<ImportResult> {
  const kdbxweb = await import("kdbxweb");
  const { argon2d, argon2id } = await import("hash-wasm");
  kdbxweb.CryptoEngine.setArgon2Impl(async (pwd, salt, memory, iterations, length, parallelism, type) => {
    const fn = type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
    const out = await fn({
      password: new Uint8Array(pwd), salt: new Uint8Array(salt), memorySize: memory, iterations,
      hashLength: length, parallelism, outputType: "binary",
    });
    return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength) as ArrayBuffer;
  });
  // In KDBX "nessuna password" e "password vuota" sono chiavi diverse: un export
  // senza password (es. da Passbolt) si apre solo con la prima. Con il campo
  // vuoto proviamo entrambe.
  const candidates = password ? [kdbxweb.ProtectedValue.fromString(password)] : [null, kdbxweb.ProtectedValue.fromString("")];
  let db: InstanceType<typeof kdbxweb.Kdbx> | undefined;
  for (const pw of candidates) {
    try {
      db = await kdbxweb.Kdbx.load(data, new kdbxweb.Credentials(pw, keyFile ?? null));
      break;
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code && code !== "InvalidKey") throw new Error(`File KeePass non valido o non supportato (${code})`);
    }
  }
  if (!db) {
    throw new Error(password || keyFile
      ? "Impossibile aprire il file KeePass: password o file chiave errati"
      : "Il file KeePass è protetto: inserisci la password o il file chiave usati nell'export");
  }
  const tree = new FolderTree();
  const res: ImportResult = { source: "keepass", folders: [], items: [], skipped: [] };
  const recycle = db.meta.recycleBinUuid?.id;
  const text = (v: unknown) => (v instanceof kdbxweb.ProtectedValue ? v.getText() : typeof v === "string" ? v : "");
  const STANDARD = new Set(["Title", "UserName", "Password", "URL", "Notes", "otp", "TOTP Seed", "TOTP Settings", ...KEEPASS_TOTP_FIELDS]);

  const walk = (group: InstanceType<typeof kdbxweb.KdbxGroup>, path: string[]) => {
    if (recycle && group.uuid.id === recycle) return;
    const folderKey = path.length ? tree.get(path.join("\u0000"), "\u0000") : null;
    for (const e of group.entries) {
      const f = e.fields;
      const name = text(f.get("Title")) || "Senza nome";
      const otp = text(f.get("otp")) || text(f.get("TOTP Seed"))
        || keepassTotpUri((n) => (f.has(n) ? text(f.get(n)) : undefined), name) || "";
      const fields: NonNullable<ItemData["fields"]> = [];
      for (const [k, v] of f) {
        if (!STANDARD.has(k)) fields.push({ label: k, value: text(v), secret: v instanceof kdbxweb.ProtectedValue });
      }
      if (e.binaries.size) res.skipped.push({ name, reason: `${e.binaries.size} allegati non importati: aggiungili a mano` });
      res.items.push({
        folderKey,
        data: cleanItem({
          type: text(f.get("Password")) || text(f.get("UserName")) ? "login" : "note",
          name, username: text(f.get("UserName")), password: text(f.get("Password")),
          urls: text(f.get("URL")) ? [text(f.get("URL"))] : [], notes: text(f.get("Notes")),
          totpUri: totpToUri(otp, name), fields,
        }),
      });
    }
    for (const g of group.groups) walk(g, [...path, g.name ?? "Gruppo"]);
  };
  const root = db.getDefaultGroup();
  walk(root, []);
  res.folders = tree.folders;
  return res;
}

// ------------------------------------------------------------------ export di StartCredentials

/**
 * Reimporta un export cifrato di StartCredentials in un solo contenitore:
 * ogni cliente di origine diventa una cartella, con le sue sottocartelle.
 */
export async function importStartCredentials(file: string, passphrase: string): Promise<ImportResult> {
  const { decryptExport } = await import("../vault.js");
  const data = await decryptExport(file, passphrase);
  const res: ImportResult = { source: "startcredentials", folders: [], items: [], skipped: [] };
  data.containers.forEach((c, ci) => {
    const rootKey = `c${ci}`;
    res.folders.push({ key: rootKey, name: c.kind === "personal" ? "Area personale" : c.meta.name, parentKey: null });
    // Le cartelle vanno create prima dei figli: ordiniamo per profondità.
    const depth = (k: string | null): number => { const f = c.folders.find((x) => x.key === k); return f ? 1 + depth(f.parentKey) : 0; };
    for (const f of [...c.folders].sort((a, b) => depth(a.key) - depth(b.key))) {
      res.folders.push({ key: `${rootKey}:${f.key}`, name: f.name, parentKey: f.parentKey ? `${rootKey}:${f.parentKey}` : rootKey });
    }
    for (const it of c.items) res.items.push({ folderKey: it.folderKey ? `${rootKey}:${it.folderKey}` : rootKey, data: it.data });
  });
  return res;
}

// ------------------------------------------------------------------ scrittura nella cassaforte

/** Cifra e carica il risultato di un import (lotti da 500 elementi). */
export async function importInto(vault: Vault, containerId: string, r: ImportResult, onProgress?: (done: number, total: number) => void): Promise<number> {
  return vault.bulkCreate(containerId, r.source, r.folders, r.items, onProgress);
}

// ------------------------------------------------------------------ un cliente per cartella principale

export interface ClientImportPlan {
  clients: {
    name: string;
    existing: Container | null;
    /** true se esiste un cliente omonimo su cui non hai il permesso di scrittura. */
    readOnly: boolean;
    folders: ImportedFolder[];
    items: ImportedItem[];
  }[];
  /** Elementi fuori da ogni cartella. */
  loose: ImportedItem[];
}

const norm = (s: string) => s.trim().toLocaleLowerCase("it");

/**
 * Prepara l'import "un cliente per ogni cartella principale": ogni cartella
 * di primo livello diventa (o ritrova) un cliente, le sottocartelle restano
 * cartelle al suo interno.
 */
export function planClientImport(r: ImportResult, containers: Container[]): ClientImportPlan {
  const byKey = new Map(r.folders.map((f) => [f.key, f]));
  const topOf = (key: string): ImportedFolder => {
    let f = byKey.get(key)!;
    while (f.parentKey) f = byKey.get(f.parentKey)!;
    return f;
  };
  const tops = r.folders.filter((f) => !f.parentKey);
  // Cartelle principali omonime (es. "Rossi" e "rossi") confluiscono nello stesso cliente.
  const groups = new Map<string, { name: string; topKeys: Set<string> }>();
  for (const t of tops) {
    const k = norm(t.name);
    if (!groups.has(k)) groups.set(k, { name: t.name.trim(), topKeys: new Set() });
    groups.get(k)!.topKeys.add(t.key);
  }
  const clients: ClientImportPlan["clients"] = [];
  for (const [k, g] of groups) {
    const existingAny = containers.filter((c) => c.kind === "client" && norm(c.meta.name) === k);
    const writable = existingAny.find((c) => c.permission !== "read") ?? null;
    const folders = r.folders
      .filter((f) => f.parentKey && g.topKeys.has(topOf(f.key).key))
      .map((f) => ({ ...f, parentKey: g.topKeys.has(f.parentKey!) ? null : f.parentKey }));
    const items = r.items
      .filter((i) => i.folderKey && g.topKeys.has(topOf(i.folderKey).key))
      .map((i) => ({ ...i, folderKey: g.topKeys.has(i.folderKey!) ? null : i.folderKey }));
    clients.push({ name: g.name, existing: writable, readOnly: !writable && existingAny.length > 0, folders, items });
  }
  clients.sort((a, b) => a.name.localeCompare(b.name, "it"));
  return { clients, loose: r.items.filter((i) => !i.folderKey) };
}

export interface ClientImportSummary {
  created: string[];
  reused: string[];
  imported: number;
  loose: number;
  /** Elementi identici a quelli già presenti nella destinazione, non reimportati. */
  duplicates: number;
  skipped: { name: string; reason: string }[];
}

/** Esegue il piano: crea i clienti mancanti e importa in ciascuno le sue credenziali. */
export async function importAsClients(
  vault: Vault, r: ImportResult, opts: { looseContainerId?: string | null; onProgress?: (text: string) => void } = {},
): Promise<ClientImportSummary> {
  const plan = planClientImport(r, await vault.containers());
  const out: ClientImportSummary = { created: [], reused: [], imported: 0, loose: 0, duplicates: 0, skipped: [] };
  const sig = (d: ItemData) => JSON.stringify([norm(d.name), d.username ?? "", d.password ?? "", d.totpUri ?? ""]);
  /** Toglie gli elementi già presenti nella destinazione (stesso nome, utente, password e OTP). */
  const withoutDuplicates = async (containerId: string, items: ImportedItem[]) => {
    const existing = new Set((await vault.items(containerId)).map((i) => sig(i.data)));
    const keep = items.filter((i) => !existing.has(sig(i.data)));
    out.duplicates += items.length - keep.length;
    return keep;
  };
  for (const c of plan.clients) {
    if (c.readOnly) {
      out.skipped.push({ name: c.name, reason: `${c.items.length} elementi non importati: esiste già un cliente con questo nome ma hai solo la lettura` });
      continue;
    }
    if (!c.items.length && !c.folders.length) continue;
    opts.onProgress?.(`Cliente ${c.name}…`);
    let id = c.existing?.id;
    if (!id) {
      id = await vault.createContainer({ name: c.name });
      out.created.push(c.name);
      out.imported += await vault.bulkCreate(id, r.source, c.folders, c.items);
    } else {
      out.reused.push(c.name);
      // Le cartelle omonime già presenti nel cliente vengono riusate.
      const detail = await vault.container(id);
      const items = await withoutDuplicates(id, c.items);
      const reuse = new Map<string, string>();
      const newFolders: ImportedFolder[] = [];
      for (const f of c.folders) {
        const parentExisting = f.parentKey ? reuse.get(f.parentKey) ?? null : null;
        const match = detail.folders.find((x) => norm(x.name) === norm(f.name) && x.parentId === (f.parentKey ? parentExisting : null) && (!f.parentKey || parentExisting));
        if (match) reuse.set(f.key, match.id);
        else newFolders.push(f);
      }
      if (reuse.size) {
        // Cartelle già esistenti: creiamo solo quelle nuove, poi spostiamo gli elementi negli id reali.
        const created = new Map<string, string>();
        for (const f of newFolders) {
          const parent = f.parentKey ? reuse.get(f.parentKey) ?? created.get(f.parentKey) ?? null : null;
          created.set(f.key, await vault.createFolder(id, f.name, parent));
        }
        for (const it of items) {
          const target = it.folderKey ? reuse.get(it.folderKey) ?? created.get(it.folderKey) ?? null : null;
          await vault.createItem(id, it.data, target);
          out.imported++;
        }
      } else {
        out.imported += await vault.bulkCreate(id, r.source, c.folders, items);
      }
    }
  }
  if (plan.loose.length) {
    if (opts.looseContainerId) {
      opts.onProgress?.("Credenziali senza cartella…");
      out.loose = await vault.bulkCreate(opts.looseContainerId, r.source, [], await withoutDuplicates(opts.looseContainerId, plan.loose));
      out.imported += out.loose;
    } else {
      out.skipped.push({ name: "Senza cartella", reason: `${plan.loose.length} elementi fuori da ogni cartella non importati` });
    }
  }
  return out;
}

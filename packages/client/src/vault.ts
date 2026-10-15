/**
 * Vault: l'utente sbloccato. Tiene in memoria le chiavi private e le chiavi
 * dei contenitori, e traduce ogni operazione in chiamate API con soli dati
 * cifrati. Nessun segreto in chiaro lascia mai questo oggetto.
 */
import * as opaque from "@serenity-kit/opaque";
import { combine, split } from "shamir-secret-sharing";
import {
  boxPublicFromPrivate, certifyUserKeys, CryptoError, decryptFile, decryptItem, deriveMasterKey, encryptFile, encryptItem,
  fingerprint, fromB64, generateTotp, generateUserKeys, grantContainerKey, hostHash, initCrypto, ItemData, KdfParams,
  KeyGrant, newContainerKey, newFileKey, newKdfParams, newSymmetricKey, normalizeHost, open, openContainerKey,
  openItemKey, openSealed, parseOtpauthUri, parsePrivateKeys, Permission, PublicKeys, reencryptItemData,
  rewrapItemKey, seal, sealToPublicKey, serializePrivateKeys, toB64, unwrapPrivateKeys, UserKeyPair,
  verifyUserCertification, wipe, wrapPrivateKeys,
} from "@startcredentials/crypto";
import { Api, ApiError } from "./api.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const json = (v: unknown) => enc.encode(JSON.stringify(v));
const unjson = <T>(b: Uint8Array) => JSON.parse(dec.decode(b)) as T;
const uuid = () => globalThis.crypto.randomUUID();

const ctxs = {
  metaKey: (cid: string) => `sc:container-meta-key:v1:${cid}`,
  meta: (cid: string) => `sc:container-meta:v1:${cid}`,
  folder: (cid: string, fid: string) => `sc:folder:v1:${cid}:${fid}`,
  fileKey: (iid: string, aid: string) => `sc:file-key:v1:${iid}:${aid}`,
  fileMeta: (iid: string, aid: string) => `sc:file-meta:v1:${iid}:${aid}`,
  recovery: (uid: string) => `sc:recovery:v1:${uid}`,
};

// ------------------------------------------------------------------ tipi

export interface ContainerMeta { name: string; sector?: string; notes?: string; color?: string }
export interface Folder { id: string; parentId: string | null; name: string }
export interface Container {
  id: string; kind: "client" | "personal" | "org"; keyVersion: number; permission: Permission;
  meta: ContainerMeta; members: number; items: number; totpItems: number; updatedAt: string; grantedBy: string;
  rotationRequired: boolean;
}
export interface Attachment { id: string; name: string; mime: string; size: number; chunkCount: number; header: string; fkEnc: string }
export interface Item {
  id: string; containerId: string; folderId: string | null; type: ItemData["type"]; data: ItemData;
  revision: number; updatedAt: string; updatedBy: string; deletedAt: string | null; attachments: Attachment[];
  ikEnc: string;
}
export interface DirectoryUser {
  id: string; email: string; displayName: string; role: "admin" | "user"; status: "active" | "suspended"; keyVersion: number;
  publicKeys: PublicKeys; certification: string | null; verified: boolean; fingerprint: string;
}
export interface Me {
  id: string; email: string; displayName: string; role: "admin" | "user"; keyVersion: number;
  publicKeys: PublicKeys; privateEnc: string; kdfParams: KdfParams; certification: string | null; hasRecovery: boolean;
  org: { signPublic: string; recoveryPublic: string; containerId?: string } | null;
}
export type SessionState = "mfa_setup" | "mfa_pending" | "active";

interface RawContainer {
  id: string; kind: Container["kind"]; metaKeyEnc: string; metaEnc: string; keyVersion: number; updatedAt: string;
  members: number; items: number; totpItems: number; grant: KeyGrant; grantorSignPublic: string; rotationRequired: boolean;
}
interface RawItem {
  id: string; folderId: string | null; type: ItemData["type"]; ikEnc: string; ikKeyVersion: number; dataEnc: string;
  revision: number; updatedAt: string; updatedBy: string; deletedAt: string | null;
  attachments: { id: string; fkEnc: string; metaEnc: string; header: string; size: number; chunkCount: number }[];
}

export interface ExportData {
  format: "startcredentials-export";
  version: 1;
  exportedAt: string;
  exportedBy: string;
  containers: {
    kind: "client" | "personal" | "org";
    meta: ContainerMeta;
    folders: { key: string; name: string; parentKey: string | null }[];
    items: { folderKey: string | null; data: ItemData }[];
  }[];
}

/** Apre un export cifrato di StartCredentials. */
export async function decryptExport(file: string, passphrase: string): Promise<ExportData> {
  await ready();
  let outer: { format?: string; kdfParams: KdfParams; data: string };
  try {
    outer = JSON.parse(file);
  } catch {
    throw new Error("Il file non è un export di StartCredentials");
  }
  if (outer.format !== "startcredentials-export-encrypted") throw new Error("Il file non è un export di StartCredentials");
  const key = deriveMasterKey(passphrase, outer.kdfParams);
  try {
    return unjson<ExportData>(open(key, outer.data, "sc:export:v1"));
  } catch {
    throw new SecurityError("Passphrase errata o file alterato");
  } finally {
    wipe(key);
  }
}

export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecurityError";
  }
}

// ------------------------------------------------------------------ flussi senza sblocco

export async function ready(): Promise<void> {
  await initCrypto();
  await opaque.ready;
}

export interface RegisterParams {
  token: string; password: string; email?: string; displayName?: string;
  /** Solo per i test: parametri Argon2id ridotti. */
  kdf?: { opsLimit: number; memLimitBytes: number };
}

/** Registrazione da invito (o bootstrap del primo amministratore). Restituisce una sessione in stato mfa_setup. */
export async function register(api: Api, p: RegisterParams): Promise<{ token: string; state: SessionState; userId: string }> {
  await ready();
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: p.password });
  const start = await api.post<{ registrationResponse: string; userId: string; org: { signPublic: string; recoveryPublic: string } | null }>(
    "/auth/register/start", { token: p.token, email: p.email, displayName: p.displayName, registrationRequest });
  const { registrationRecord } = opaque.client.finishRegistration({ clientRegistrationState, registrationResponse: start.registrationResponse, password: p.password });
  const kdfParams = p.kdf ? newKdfParams(p.kdf.opsLimit, p.kdf.memLimitBytes) : newKdfParams();
  const mk = deriveMasterKey(p.password, kdfParams);
  const keys = generateUserKeys();
  const payload = serializePrivateKeys(keys);
  try {
    const res = await api.post<{ token: string; state: SessionState; userId: string }>("/auth/register/finish", {
      token: p.token,
      registrationRecord,
      keys: {
        boxPublic: keys.publicKeys.box,
        signPublic: keys.publicKeys.sign,
        privateEnc: wrapPrivateKeys(mk, keys, start.userId, 1),
        kdfParams,
        recoveryEnc: start.org ? sealToPublicKey(payload, start.org.recoveryPublic) : undefined,
      },
    });
    api.token = res.token;
    return res;
  } finally {
    wipe(mk);
    wipe(payload);
    wipe(keys.boxPrivate);
    wipe(keys.signPrivate);
  }
}

/** Login OPAQUE: il server non riceve mai la password. */
export async function login(api: Api, email: string, password: string): Promise<{ token: string; state: SessionState }> {
  await ready();
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const start = await api.post<{ loginId: string; loginResponse: string }>("/auth/login/start", { email, startLoginRequest });
  const fin = opaque.client.finishLogin({ clientLoginState, loginResponse: start.loginResponse, password });
  // Credenziali errate: completiamo comunque il giro per non distinguere i casi.
  const res = await api.post<{ token: string; state: SessionState }>("/auth/login/finish", {
    loginId: start.loginId,
    finishLoginRequest: fin?.finishLoginRequest ?? toB64(globalThis.crypto.getRandomValues(new Uint8Array(64))),
  });
  api.token = res.token;
  return res;
}

export async function setupMfa(api: Api): Promise<{ secret: string; otpauthUri: string }> {
  return api.post("/auth/mfa/setup");
}
/** Attiva l'MFA e restituisce i 10 codici di riserva, da mostrare una volta sola. */
export async function enableMfa(api: Api, code: string): Promise<string[]> {
  const r = await api.post<{ backupCodes: string[] }>("/auth/mfa/enable", { code });
  return r.backupCodes;
}
export async function verifyMfa(api: Api, code: string): Promise<void> {
  await api.post("/auth/mfa/verify", { code });
}
export async function logout(api: Api): Promise<void> {
  try {
    await api.post("/auth/logout");
  } finally {
    api.token = undefined;
  }
}

/** Il primo amministratore usa il token di bootstrap del modulo NethServer. */
export async function serverStatus(api: Api): Promise<{ bootstrapped: boolean; org: { signPublic: string; recoveryPublic: string } | null }> {
  return api.get("/auth/status");
}

/** Completa un recupero account avviato da due amministratori. */
export async function completeRecovery(api: Api, p: { token: string; code: string; newPassword: string; kdf?: RegisterParams["kdf"] }): Promise<void> {
  await ready();
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: p.newPassword });
  const start = await api.post<{ registrationResponse: string; userId: string; blob: { data: string; kdfParams: KdfParams } }>(
    "/auth/recover/start", { token: p.token, registrationRequest });
  const codeKey = deriveMasterKey(p.code.replace(/[\s-]/g, "").toUpperCase(), start.blob.kdfParams);
  let payload: Uint8Array | undefined;
  try {
    payload = open(codeKey, start.blob.data, ctxs.recovery(start.userId));
  } catch {
    throw new SecurityError("Codice di recupero errato");
  } finally {
    wipe(codeKey);
  }
  const { keyVersion, keys: keysB64 } = unjson<{ keyVersion: number; keys: string }>(payload);
  const keys = parsePrivateKeys(fromB64(keysB64));
  const { registrationRecord } = opaque.client.finishRegistration({ clientRegistrationState, registrationResponse: start.registrationResponse, password: p.newPassword });
  const kdfParams = p.kdf ? newKdfParams(p.kdf.opsLimit, p.kdf.memLimitBytes) : newKdfParams();
  const mk = deriveMasterKey(p.newPassword, kdfParams);
  try {
    await api.post("/auth/recover/finish", {
      token: p.token, registrationRecord, kdfParams, privateEnc: wrapPrivateKeys(mk, keys, start.userId, keyVersion),
    });
  } finally {
    wipe(mk);
    wipe(keys.boxPrivate);
    wipe(keys.signPrivate);
  }
}

// ------------------------------------------------------------------ Vault

export interface UnlockOptions {
  /**
   * Chiave di firma dell'organizzazione già nota al client (TOFU). Se il server
   * ne presenta una diversa lo sblocco fallisce: protegge dalla sostituzione delle chiavi.
   */
  pinnedOrgSignPublic?: string;
}

export interface SerializedSession {
  v: 1; me: Me; keys: string;
}

export class Vault {
  private cks = new Map<string, { version: number; ck: Uint8Array; metaKey: Uint8Array; permission: Permission; kind: Container["kind"] }>();
  private dirCache?: { at: number; users: DirectoryUser[] };
  private orgSignPrivate?: Uint8Array;

  private constructor(public api: Api, public me: Me, private keys: UserKeyPair) {}

  /** Sblocco: scarica le chiavi cifrate e le apre con la master key derivata localmente. */
  static async unlock(api: Api, password: string, opts: UnlockOptions = {}): Promise<Vault> {
    await ready();
    const me = await api.get<Me>("/me");
    Vault.checkOrgPin(me, opts);
    const mk = deriveMasterKey(password, me.kdfParams);
    try {
      let keys: UserKeyPair;
      try {
        keys = unwrapPrivateKeys(mk, me.privateEnc, me.id, me.keyVersion);
      } catch (e) {
        if (e instanceof CryptoError) throw new SecurityError("Master password errata");
        throw e;
      }
      if (keys.publicKeys.box !== me.publicKeys.box || keys.publicKeys.sign !== me.publicKeys.sign) {
        throw new SecurityError("Le chiavi pubbliche sul server non corrispondono a quelle cifrate");
      }
      return new Vault(api, me, keys);
    } finally {
      wipe(mk);
    }
  }

  private static checkOrgPin(me: Me, opts: UnlockOptions) {
    if (opts.pinnedOrgSignPublic && me.org && me.org.signPublic !== opts.pinnedOrgSignPublic) {
      throw new SecurityError("La chiave dell'organizzazione presentata dal server è cambiata: possibile attacco");
    }
    if (opts.pinnedOrgSignPublic && !me.org) {
      throw new SecurityError("Il server non presenta più la chiave dell'organizzazione");
    }
  }

  /** Per l'estensione: le chiavi restano in chrome.storage.session (solo memoria). */
  serialize(): SerializedSession {
    return { v: 1, me: this.me, keys: toB64(serializePrivateKeys(this.keys)) };
  }

  static async restore(api: Api, s: SerializedSession, opts: UnlockOptions = {}): Promise<Vault> {
    await ready();
    Vault.checkOrgPin(s.me, opts);
    return new Vault(api, s.me, parsePrivateKeys(fromB64(s.keys)));
  }

  lock(): void {
    wipe(this.keys.boxPrivate);
    wipe(this.keys.signPrivate);
    for (const v of this.cks.values()) {
      wipe(v.ck);
      wipe(v.metaKey);
    }
    this.cks.clear();
    wipe(this.orgSignPrivate);
    this.orgSignPrivate = undefined;
  }

  get myFingerprint(): string {
    return fingerprint(this.keys.publicKeys);
  }

  private get self() {
    return { userId: this.me.id, keys: this.keys };
  }

  async refreshMe(): Promise<Me> {
    const me = await this.api.get<Me>("/me");
    if (this.me.org && me.org?.signPublic !== this.me.org.signPublic) {
      throw new SecurityError("La chiave dell'organizzazione è cambiata durante la sessione");
    }
    this.me = me;
    return me;
  }

  // ---------------------------------------------------------------- rubrica

  async directory(force = false): Promise<DirectoryUser[]> {
    if (!force && this.dirCache && Date.now() - this.dirCache.at < 60_000) return this.dirCache.users;
    const raw = await this.api.get<Omit<DirectoryUser, "verified" | "fingerprint">[]>("/users/directory");
    const users = raw.map((u) => {
      let verified = false;
      if (u.id === this.me.id) verified = u.publicKeys.box === this.keys.publicKeys.box && u.publicKeys.sign === this.keys.publicKeys.sign;
      else if (u.certification && this.me.org) {
        try {
          verifyUserCertification(u.id, u.keyVersion, u.publicKeys, u.certification, this.me.org.signPublic);
          verified = true;
        } catch {
          verified = false;
        }
      }
      return { ...u, verified, fingerprint: fingerprint(u.publicKeys) };
    });
    this.dirCache = { at: Date.now(), users };
    return users;
  }

  private async signerKey(userId: string): Promise<string> {
    if (userId === this.me.id) return this.keys.publicKeys.sign;
    let u = (await this.directory()).find((x) => x.id === userId);
    if (!u) u = (await this.directory(true)).find((x) => x.id === userId);
    if (!u?.verified) throw new SecurityError("Chi ha condiviso questo contenitore non ha una chiave certificata dall'organizzazione");
    return u.publicKeys.sign;
  }

  // ---------------------------------------------------------------- contenitori

  private async openRaw(r: RawContainer): Promise<Container> {
    const cached = this.cks.get(r.id);
    if (!cached || cached.version !== r.keyVersion) {
      const signer = await this.signerKey(r.grant.grantedBy);
      if (signer !== r.grantorSignPublic) throw new SecurityError("Chiave del concedente non corrispondente");
      const ck = openContainerKey(r.grant, this.self, signer);
      const metaKey = open(ck, r.metaKeyEnc, ctxs.metaKey(r.id));
      if (cached) {
        wipe(cached.ck);
        wipe(cached.metaKey);
      }
      this.cks.set(r.id, { version: r.keyVersion, ck, metaKey, permission: r.grant.permission, kind: r.kind });
    } else {
      cached.permission = r.grant.permission;
    }
    const k = this.cks.get(r.id)!;
    return {
      id: r.id, kind: r.kind, keyVersion: r.keyVersion, permission: r.grant.permission,
      meta: unjson<ContainerMeta>(open(k.metaKey, r.metaEnc, ctxs.meta(r.id))),
      members: r.members, items: r.items, totpItems: r.totpItems, updatedAt: r.updatedAt, grantedBy: r.grant.grantedBy,
      rotationRequired: !!r.rotationRequired,
    };
  }

  async containers(): Promise<Container[]> {
    const raw = await this.api.get<RawContainer[]>("/containers");
    const out: Container[] = [];
    for (const r of raw) out.push(await this.openRaw(r));
    return out;
  }

  async container(id: string): Promise<Container & { folders: Folder[] }> {
    const r = await this.api.get<RawContainer & { folders: { id: string; parentId: string | null; metaEnc: string }[] }>(`/containers/${id}`);
    const c = await this.openRaw(r);
    const k = this.cks.get(id)!;
    const folders = r.folders.map((f) => ({ id: f.id, parentId: f.parentId, name: unjson<{ name: string }>(open(k.metaKey, f.metaEnc, ctxs.folder(id, f.id))).name }));
    return { ...c, folders };
  }

  private async key(containerId: string) {
    if (!this.cks.has(containerId)) await this.container(containerId);
    return this.cks.get(containerId)!;
  }

  async createContainer(meta: ContainerMeta, kind: "client" | "personal" = "client"): Promise<string> {
    const id = uuid();
    const ck = newContainerKey();
    const metaKey = newSymmetricKey();
    const grant = grantContainerKey({
      containerKey: ck, containerId: id, keyVersion: 1, recipientId: this.me.id,
      recipientPublic: this.keys.publicKeys, permission: "manage", grantor: this.self,
    });
    await this.api.post("/containers", {
      id, kind,
      metaKeyEnc: seal(ck, metaKey, ctxs.metaKey(id), `ck:${id}:1`),
      metaEnc: seal(metaKey, json(meta), ctxs.meta(id), `mk:${id}`),
      grant,
    });
    this.cks.set(id, { version: 1, ck, metaKey, permission: "manage", kind });
    return id;
  }

  async ensurePersonal(): Promise<string> {
    const p = (await this.containers()).find((c) => c.kind === "personal");
    if (p) return p.id;
    try {
      return await this.createContainer({ name: "Area personale" }, "personal");
    } catch (e) {
      if (e instanceof ApiError && e.code === "personal_exists") return (await this.containers()).find((c) => c.kind === "personal")!.id;
      throw e;
    }
  }

  async updateContainer(id: string, meta: ContainerMeta): Promise<void> {
    const k = await this.key(id);
    await this.api.patch(`/containers/${id}`, { metaEnc: seal(k.metaKey, json(meta), ctxs.meta(id), `mk:${id}`) });
  }

  async deleteContainer(id: string): Promise<void> {
    await this.api.del(`/containers/${id}`);
    this.forget(id);
  }

  private forget(id: string) {
    const k = this.cks.get(id);
    if (k) {
      wipe(k.ck);
      wipe(k.metaKey);
      this.cks.delete(id);
    }
  }

  async createFolder(containerId: string, name: string, parentId: string | null = null): Promise<string> {
    const k = await this.key(containerId);
    const id = uuid();
    await this.api.post(`/containers/${containerId}/folders`, { id, parentId, metaEnc: seal(k.metaKey, json({ name }), ctxs.folder(containerId, id), `mk:${containerId}`) });
    return id;
  }

  async renameFolder(containerId: string, folderId: string, name: string): Promise<void> {
    const k = await this.key(containerId);
    await this.api.patch(`/folders/${folderId}`, { metaEnc: seal(k.metaKey, json({ name }), ctxs.folder(containerId, folderId), `mk:${containerId}`) });
  }

  async deleteFolder(folderId: string): Promise<void> {
    await this.api.del(`/folders/${folderId}`);
  }

  // ---------------------------------------------------------------- elementi

  private hostHashes(ck: Uint8Array, data: ItemData): string[] {
    const out = new Set<string>();
    for (const u of data.urls ?? []) {
      try {
        out.add(hostHash(ck, u));
      } catch {
        /* URL non valido: nessun autofill */
      }
      if (out.size >= 20) break;
    }
    return [...out];
  }

  async items(containerId: string, opts: { trash?: boolean } = {}): Promise<Item[]> {
    const k = await this.key(containerId);
    const raw = await this.api.get<RawItem[]>(`/containers/${containerId}/items${opts.trash ? "?trash=1" : ""}`);
    return raw.map((r) => {
      const data = decryptItem(k.ck, containerId, r.id, { ikEnc: r.ikEnc, dataEnc: r.dataEnc });
      const ik = openItemKey(k.ck, containerId, r.id, r.ikEnc);
      try {
        const attachments = r.attachments.map((a) => {
          const m = unjson<{ name: string; mime: string }>(open(ik, a.metaEnc, ctxs.fileMeta(r.id, a.id)));
          return { id: a.id, name: m.name, mime: m.mime, size: a.size, chunkCount: a.chunkCount, header: a.header, fkEnc: a.fkEnc };
        });
        return {
          id: r.id, containerId, folderId: r.folderId, type: r.type, data, revision: r.revision, updatedAt: r.updatedAt,
          updatedBy: r.updatedBy, deletedAt: r.deletedAt, attachments, ikEnc: r.ikEnc,
        };
      } finally {
        wipe(ik);
      }
    });
  }

  async createItem(containerId: string, data: ItemData, folderId: string | null = null): Promise<string> {
    const k = await this.key(containerId);
    const id = uuid();
    const e = encryptItem(k.ck, k.version, containerId, id, data);
    try {
      await this.api.post(`/containers/${containerId}/items`, {
        id, folderId, type: data.type, ikEnc: e.ikEnc, ikKeyVersion: k.version, dataEnc: e.dataEnc, hostHashes: this.hostHashes(k.ck, data),
      });
    } catch (err) {
      if (err instanceof ApiError && err.code === "stale_key_version") {
        this.forget(containerId);
        return this.createItem(containerId, data, folderId);
      }
      throw err;
    }
    return id;
  }

  async updateItem(item: Item, data: ItemData, folderId?: string | null): Promise<number> {
    const k = await this.key(item.containerId);
    const ik = openItemKey(k.ck, item.containerId, item.id, item.ikEnc);
    try {
      const r = await this.api.put<{ revision: number }>(`/items/${item.id}`, {
        revision: item.revision, type: data.type, folderId,
        dataEnc: reencryptItemData(ik, item.containerId, item.id, data), hostHashes: this.hostHashes(k.ck, data),
      });
      return r.revision;
    } finally {
      wipe(ik);
    }
  }

  /** Import massivo: cifra cartelle ed elementi in locale e li invia a lotti. */
  async bulkCreate(
    containerId: string, source: string,
    folders: { key: string; name: string; parentKey: string | null }[],
    items: { folderKey: string | null; data: ItemData }[],
    onProgress?: (done: number, total: number) => void,
  ): Promise<number> {
    const k = await this.key(containerId);
    const ids = new Map(folders.map((f) => [f.key, uuid()]));
    const encFolders = folders.map((f) => {
      const id = ids.get(f.key)!;
      return { id, parentId: f.parentKey ? ids.get(f.parentKey)! : null, metaEnc: seal(k.metaKey, json({ name: f.name }), ctxs.folder(containerId, id), `mk:${containerId}`) };
    });
    const BATCH = 500;
    let done = 0;
    for (let i = 0; i < Math.max(items.length, 1); i += BATCH) {
      const slice = items.slice(i, i + BATCH).map((it) => {
        const id = uuid();
        const e = encryptItem(k.ck, k.version, containerId, id, it.data);
        return {
          id, folderId: it.folderKey ? ids.get(it.folderKey)! : null, type: it.data.type,
          ikEnc: e.ikEnc, ikKeyVersion: k.version, dataEnc: e.dataEnc, hostHashes: this.hostHashes(k.ck, it.data),
        };
      });
      await this.api.post(`/containers/${containerId}/import`, { source, folders: i === 0 ? encFolders : [], items: slice });
      done += slice.length;
      onProgress?.(done, items.length);
    }
    return done;
  }

  async deleteItem(itemId: string): Promise<void> { await this.api.del(`/items/${itemId}`); }
  async restoreItem(itemId: string): Promise<void> { await this.api.post(`/items/${itemId}/restore`); }

  async itemVersions(item: Item): Promise<{ revision: number; createdAt: string; by: string; data: ItemData }[]> {
    const k = await this.key(item.containerId);
    const ik = openItemKey(k.ck, item.containerId, item.id, item.ikEnc);
    try {
      const raw = await this.api.get<{ revision: number; dataEnc: string; createdAt: string; by: string }[]>(`/items/${item.id}/versions`);
      return raw.map((v) => ({ revision: v.revision, createdAt: v.createdAt, by: v.by, data: unjson<ItemData>(open(ik, v.dataEnc, `sc:item-data:v1:${item.containerId}:${item.id}`)) }));
    } finally {
      wipe(ik);
    }
  }

  // ---------------------------------------------------------------- allegati

  async addAttachment(item: Item, bytes: Uint8Array, name: string, mime = "application/octet-stream", onProgress?: (done: number, total: number) => void): Promise<string> {
    const k = await this.key(item.containerId);
    const ik = openItemKey(k.ck, item.containerId, item.id, item.ikEnc);
    const id = uuid();
    const fk = newFileKey();
    try {
      const file = encryptFile(fk, id, bytes);
      await this.api.post(`/items/${item.id}/attachments`, {
        id,
        fkEnc: seal(ik, fk, ctxs.fileKey(item.id, id), `ik:${item.id}`),
        metaEnc: seal(ik, json({ name, mime }), ctxs.fileMeta(item.id, id), `ik:${item.id}`),
        header: toB64(file.header), size: bytes.length, chunkCount: file.chunks.length,
      });
      for (let i = 0; i < file.chunks.length; i++) {
        await this.api.putBinary(`/attachments/${id}/chunks/${i}`, file.chunks[i]!);
        onProgress?.(i + 1, file.chunks.length);
      }
      await this.api.post(`/attachments/${id}/complete`);
      return id;
    } finally {
      wipe(ik);
      wipe(fk);
    }
  }

  async downloadAttachment(item: Item, att: Attachment): Promise<Uint8Array> {
    const k = await this.key(item.containerId);
    const ik = openItemKey(k.ck, item.containerId, item.id, item.ikEnc);
    let fk: Uint8Array | undefined;
    try {
      fk = open(ik, att.fkEnc, ctxs.fileKey(item.id, att.id));
      const chunks: Uint8Array[] = [];
      for (let i = 0; i < att.chunkCount; i++) chunks.push(await this.api.getBinary(`/attachments/${att.id}/chunks/${i}`));
      return decryptFile(fk, att.id, { header: fromB64(att.header), chunks });
    } finally {
      wipe(ik);
      wipe(fk);
    }
  }

  async deleteAttachment(attachmentId: string): Promise<void> { await this.api.del(`/attachments/${attachmentId}`); }

  // ---------------------------------------------------------------- condivisione

  async members(containerId: string): Promise<{ userId: string; displayName: string; email: string; permission: Permission; since: string }[]> {
    return this.api.get(`/containers/${containerId}/members`);
  }

  /** Condivide un contenitore. Il destinatario deve avere una chiave certificata dall'organizzazione. */
  async share(containerId: string, userId: string, permission: Permission): Promise<void> {
    const k = await this.key(containerId);
    const recipient = userId === this.me.id ? undefined : (await this.directory(true)).find((u) => u.id === userId);
    if (userId !== this.me.id && !recipient?.verified) throw new SecurityError("Il destinatario non ha una chiave certificata: chiedi a un amministratore di verificarla");
    if (recipient && recipient.status !== "active") throw new SecurityError("Il destinatario è sospeso");
    const grant = grantContainerKey({
      containerKey: k.ck, containerId, keyVersion: k.version, recipientId: userId,
      recipientPublic: recipient?.publicKeys ?? this.keys.publicKeys, permission, grantor: this.self,
    });
    try {
      await this.api.put(`/containers/${containerId}/members`, { grant });
    } catch (e) {
      if (e instanceof ApiError && e.code === "stale_key_version") {
        this.forget(containerId);
        return this.share(containerId, userId, permission);
      }
      throw e;
    }
  }

  /** Revoca e ruota subito la chiave del contenitore. */
  async revoke(containerId: string, userId: string): Promise<void> {
    await this.api.del(`/containers/${containerId}/members/${userId}`);
    await this.rotate(containerId);
  }

  async rotate(containerId: string): Promise<number> {
    this.forget(containerId);
    const c = await this.container(containerId);
    const old = this.cks.get(containerId)!;
    const [live, trash, members, dir] = await Promise.all([
      this.api.get<RawItem[]>(`/containers/${containerId}/items`),
      this.api.get<RawItem[]>(`/containers/${containerId}/items?trash=1`),
      this.members(containerId),
      this.directory(true),
    ]);
    const newVersion = c.keyVersion + 1;
    const ck = newContainerKey();
    const grants = members.map((m) => {
      const pub = m.userId === this.me.id ? this.keys.publicKeys : dir.find((u) => u.id === m.userId && u.verified)?.publicKeys;
      if (!pub) throw new SecurityError(`Chiave non certificata per ${m.displayName}: impossibile ruotare`);
      return grantContainerKey({ containerKey: ck, containerId, keyVersion: newVersion, recipientId: m.userId, recipientPublic: pub, permission: m.permission, grantor: this.self });
    });
    const items = [...live, ...trash].map((i) => ({ id: i.id, ikEnc: rewrapItemKey(old.ck, ck, newVersion, containerId, i.id, i.ikEnc) }));
    await this.api.post(`/containers/${containerId}/rotate`, {
      newKeyVersion: newVersion,
      metaKeyEnc: seal(ck, old.metaKey, ctxs.metaKey(containerId), `ck:${containerId}:${newVersion}`),
      grants, items,
    });
    wipe(old.ck);
    this.cks.set(containerId, { ...old, version: newVersion, ck });
    return newVersion;
  }

  /**
   * Completa le rotazioni rimaste in sospeso (revoche interrotte, colleghi
   * usciti). Solo i gestori possono farlo: va chiamata dopo lo sblocco.
   */
  async completePendingRotations(): Promise<{ done: string[]; failed: { name: string; error: string }[] }> {
    const done: string[] = [];
    const failed: { name: string; error: string }[] = [];
    for (const c of await this.containers()) {
      if (!c.rotationRequired || c.permission !== "manage") continue;
      try {
        await this.rotate(c.id);
        done.push(c.meta.name);
      } catch (e) {
        failed.push({ name: c.meta.name, error: (e as Error).message });
      }
    }
    return { done, failed };
  }

  // ---------------------------------------------------------------- account

  /**
   * Cambio della master password. Verifica la password attuale aprendo le
   * chiavi salvate sul server (protegge un dispositivo lasciato sbloccato),
   * poi registra le nuove credenziali OPAQUE e ricifra le chiavi. Richiede
   * anche il codice MFA. Le altre sessioni vengono chiuse.
   */
  async changePassword(currentPassword: string, newPassword: string, mfaCode: string, kdf?: RegisterParams["kdf"]): Promise<void> {
    const me = await this.refreshMe();
    const oldMk = deriveMasterKey(currentPassword, me.kdfParams);
    try {
      const check = unwrapPrivateKeys(oldMk, me.privateEnc, me.id, me.keyVersion);
      wipe(check.boxPrivate);
      wipe(check.signPrivate);
    } catch {
      throw new SecurityError("La master password attuale non è corretta");
    } finally {
      wipe(oldMk);
    }
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: newPassword });
    const { registrationResponse } = await this.api.post<{ registrationResponse: string }>("/me/password/start", { registrationRequest });
    const { registrationRecord } = opaque.client.finishRegistration({ clientRegistrationState, registrationResponse, password: newPassword });
    const kdfParams = kdf ? newKdfParams(kdf.opsLimit, kdf.memLimitBytes) : newKdfParams();
    const mk = deriveMasterKey(newPassword, kdfParams);
    try {
      await this.api.post("/me/password/finish", {
        registrationRecord, kdfParams, code: mfaCode, privateEnc: wrapPrivateKeys(mk, this.keys, me.id, me.keyVersion),
      });
    } finally {
      wipe(mk);
    }
    await this.refreshMe();
  }

  async mfaStatus(): Promise<{ backupCodesRemaining: number }> {
    return this.api.get("/me/mfa");
  }

  async regenerateBackupCodes(mfaCode: string): Promise<string[]> {
    return (await this.api.post<{ backupCodes: string[] }>("/me/mfa/backup-codes", { code: mfaCode })).backupCodes;
  }

  /**
   * Export completo e cifrato (Argon2id + XChaCha20-Poly1305) di tutto ciò
   * che l'utente può leggere, escluso il contenitore dell'organizzazione.
   * Gli allegati non sono inclusi.
   */
  async exportEncrypted(passphrase: string, kdf?: RegisterParams["kdf"]): Promise<{ file: string; containers: number; items: number; attachmentsSkipped: number }> {
    const containers: ExportData["containers"] = [];
    let items = 0;
    let attachmentsSkipped = 0;
    for (const c of await this.containers()) {
      if (c.kind === "org") continue;
      const detail = await this.container(c.id);
      const list = await this.items(c.id);
      items += list.length;
      attachmentsSkipped += list.reduce((n, i) => n + i.attachments.length, 0);
      containers.push({
        kind: c.kind, meta: c.meta,
        folders: detail.folders.map((f) => ({ key: f.id, name: f.name, parentKey: f.parentId })),
        items: list.map((i) => ({ folderKey: i.folderId, data: i.data })),
      });
      this.report("container.export", c.id);
    }
    const payload: ExportData = { format: "startcredentials-export", version: 1, exportedAt: new Date().toISOString(), exportedBy: this.me.email, containers };
    const kdfParams = kdf ? newKdfParams(kdf.opsLimit, kdf.memLimitBytes) : newKdfParams();
    const key = deriveMasterKey(passphrase, kdfParams);
    try {
      const file = JSON.stringify({ format: "startcredentials-export-encrypted", version: 1, kdfParams, data: seal(key, json(payload), "sc:export:v1", "export") }, null, 1);
      return { file, containers: containers.length, items, attachmentsSkipped };
    } finally {
      wipe(key);
    }
  }

  // ---------------------------------------------------------------- autofill e OTP

  /** Elementi che corrispondono esattamente al nome host della pagina. */
  async lookup(url: string): Promise<{ container: Container; item: Item }[]> {
    const host = normalizeHost(url);
    const containers = await this.containers();
    const queries = containers.map((c) => ({ containerId: c.id, hostHash: hostHash(this.cks.get(c.id)!.ck, host) }));
    const hits = await this.api.post<{ itemId: string; containerId: string }[]>("/lookup", { queries });
    const out: { container: Container; item: Item }[] = [];
    for (const cid of new Set(hits.map((h) => h.containerId))) {
      const container = containers.find((c) => c.id === cid)!;
      const ids = new Set(hits.filter((h) => h.containerId === cid).map((h) => h.itemId));
      for (const item of await this.items(cid)) {
        // Doppio controllo lato client: il server non può far compilare su un altro dominio.
        if (ids.has(item.id) && (item.data.urls ?? []).some((u) => { try { return normalizeHost(u) === host; } catch { return false; } })) {
          out.push({ container, item });
        }
      }
    }
    return out;
  }

  static async totp(uri: string, now = Date.now()): Promise<{ code: string; secondsLeft: number; period: number }> {
    const p = parseOtpauthUri(uri);
    return { ...(await generateTotp(p, now)), period: p.period };
  }

  report(action: "item.reveal" | "item.copy" | "item.fill" | "item.totp_copy" | "container.export", containerId: string, itemId?: string): void {
    this.api.post("/audit/events", { action, containerId, itemId }).catch(() => undefined);
  }

  // ---------------------------------------------------------------- amministrazione

  async users() {
    return this.api.get<{
      id: string; email: string; displayName: string; role: "admin" | "user"; status: string; mfaEnabled: boolean;
      createdAt: string; keyVersion: number; publicKeys: PublicKeys | null; certified: boolean; hasRecovery: boolean; recoveryPending: boolean;
    }[]>("/users");
  }

  async resetMfa(userId: string): Promise<void> {
    await this.api.post(`/users/${userId}/mfa-reset`);
  }

  /** Uscita dall'azienda: sospende e toglie ogni accesso; le rotazioni partono subito dove possibile. */
  async offboard(userId: string, force = false): Promise<{ containers: number; withoutManager: string[]; rotated: string[] }> {
    const r = await this.api.post<{ containers: number; withoutManager: string[] }>(`/users/${userId}/offboard`, { force });
    this.dirCache = undefined;
    const { done } = await this.completePendingRotations();
    return { ...r, rotated: done };
  }

  async invite(email: string, displayName: string, role: "admin" | "user") {
    return this.api.post<{ userId: string; inviteToken: string; inviteUrl: string; emailed: boolean }>("/users/invite", { email, displayName, role });
  }

  async setUser(userId: string, change: { status?: "active" | "suspended"; role?: "admin" | "user" }) {
    await this.api.patch(`/users/${userId}`, change);
  }

  async auditLog(opts: { containerId?: string; before?: number; limit?: number } = {}) {
    const q = new URLSearchParams();
    if (opts.containerId) q.set("containerId", opts.containerId);
    if (opts.before) q.set("before", String(opts.before));
    q.set("limit", String(opts.limit ?? 100));
    return this.api.get<{ id: number; at: string; actorName: string | null; action: string; targetType: string | null; targetId: string | null; containerId: string | null; ip: string | null; details: Record<string, unknown> }[]>(`/audit?${q}`);
  }

  async verifyAudit() {
    return this.api.get<{ ok: boolean; rows: number; brokenAt?: number }>("/audit/verify");
  }

  /**
   * Inizializza l'organizzazione (una sola volta, dal primo amministratore):
   * chiave di firma custodita in un contenitore riservato agli admin e chiave
   * di recupero divisa con Shamir. Le quote vanno stampate e consegnate a
   * persone diverse: non vengono salvate da nessuna parte.
   */
  async initOrg(shares = 3, threshold = 2): Promise<{ shares: string[]; fingerprint: string }> {
    if (this.me.role !== "admin") throw new SecurityError("Solo un amministratore può inizializzare l'organizzazione");
    const org = generateUserKeys();
    const recovery = generateUserKeys();
    const containerId = uuid();
    const itemId = uuid();
    const ck = newContainerKey();
    const metaKey = newSymmetricKey();
    const item = encryptItem(ck, 1, containerId, itemId, {
      type: "note", name: "Chiave di firma dell'organizzazione",
      fields: [{ label: "org_sign_private", value: toB64(org.signPrivate), secret: true }],
    });
    const parts = await split(recovery.boxPrivate, shares, threshold);
    await this.api.post("/org/init", {
      signPublic: org.publicKeys.sign,
      recoveryPublic: recovery.publicKeys.box,
      recoveryThreshold: threshold, recoveryShares: shares,
      container: {
        id: containerId,
        metaKeyEnc: seal(ck, metaKey, ctxs.metaKey(containerId), `ck:${containerId}:1`),
        metaEnc: seal(metaKey, json({ name: "Organizzazione" }), ctxs.meta(containerId), `mk:${containerId}`),
        grant: grantContainerKey({ containerKey: ck, containerId, keyVersion: 1, recipientId: this.me.id, recipientPublic: this.keys.publicKeys, permission: "manage", grantor: this.self }),
      },
      item: { id: itemId, ...item },
      selfCertification: { keyVersion: this.me.keyVersion, certification: certifyUserKeys(this.me.id, this.me.keyVersion, this.keys.publicKeys, org.signPrivate) },
    });
    await this.refreshMe();
    await this.api.put("/me/recovery", { recoveryEnc: sealToPublicKey(serializePrivateKeys(this.keys), recovery.publicKeys.box) });
    const fp = fingerprint({ box: recovery.publicKeys.box, sign: org.publicKeys.sign });
    wipe(org.signPrivate); wipe(org.boxPrivate); wipe(recovery.boxPrivate); wipe(recovery.signPrivate); wipe(ck); wipe(metaKey);
    return { shares: parts.map((p) => `SCR1-${toB64(p)}`), fingerprint: fp };
  }

  /** Salva la copia di recupero se mancante (utenti registrati prima dell'organizzazione). */
  async ensureRecoveryCopy(): Promise<boolean> {
    if (this.me.hasRecovery || !this.me.org) return false;
    await this.api.put("/me/recovery", { recoveryEnc: sealToPublicKey(serializePrivateKeys(this.keys), this.me.org.recoveryPublic) });
    this.me.hasRecovery = true;
    return true;
  }

  private async orgKey(): Promise<Uint8Array> {
    if (this.orgSignPrivate) return this.orgSignPrivate;
    const cid = this.me.org?.containerId;
    if (!cid) throw new SecurityError("Accesso alla chiave dell'organizzazione non disponibile");
    const [item] = await this.items(cid);
    const value = item?.data.fields?.find((f) => f.label === "org_sign_private")?.value;
    if (!value) throw new SecurityError("Chiave dell'organizzazione non trovata");
    this.orgSignPrivate = fromB64(value);
    return this.orgSignPrivate;
  }

  /** Certifica la chiave di un utente dopo averne confrontato l'impronta di persona o al telefono. */
  async certifyUser(userId: string, expectedFingerprint: string): Promise<void> {
    const u = (await this.users()).find((x) => x.id === userId);
    if (!u?.publicKeys) throw new SecurityError("Utente senza chiavi");
    if (fingerprint(u.publicKeys).replace(/\s/g, "") !== expectedFingerprint.replace(/\s/g, "").toUpperCase()) {
      throw new SecurityError("L'impronta non corrisponde: non certificare questa chiave");
    }
    const certification = certifyUserKeys(userId, u.keyVersion, u.publicKeys, await this.orgKey());
    await this.api.post(`/users/${userId}/certify`, { keyVersion: u.keyVersion, certification });
    this.dirCache = undefined;
  }

  /** Dà a un nuovo amministratore l'accesso alla chiave dell'organizzazione. */
  async grantOrgAccess(userId: string): Promise<void> {
    const cid = this.me.org?.containerId;
    if (!cid) throw new SecurityError("Organizzazione non inizializzata");
    await this.share(cid, userId, "manage");
  }

  /**
   * Avvia il recupero dell'account di un utente: richiede almeno `threshold`
   * quote Shamir. Restituisce il codice da comunicare all'utente per un canale
   * diverso dal collegamento.
   */
  async startRecovery(userId: string, shares: string[], kdf?: RegisterParams["kdf"]): Promise<{ recoveryUrl: string; recoveryToken: string; code: string }> {
    if (!this.me.org) throw new SecurityError("Organizzazione non inizializzata");
    const recoveryPrivate = await combine(shares.map((s) => fromB64(s.trim().replace(/^SCR1-/, ""))));
    try {
      if (boxPublicFromPrivate(recoveryPrivate) !== this.me.org.recoveryPublic) throw new SecurityError("Quote di recupero non valide o insufficienti");
      const m = await this.api.get<{ keyVersion: number; recoveryEnc: string; publicKeys: PublicKeys }>(`/users/${userId}/recovery-material`);
      const payload = openSealed(m.recoveryEnc, this.me.org.recoveryPublic, recoveryPrivate);
      const keys = parsePrivateKeys(payload);
      if (keys.publicKeys.box !== m.publicKeys.box || keys.publicKeys.sign !== m.publicKeys.sign) throw new SecurityError("Materiale di recupero non coerente");
      const raw = globalThis.crypto.getRandomValues(new Uint8Array(20));
      const code = base32(raw);
      const kdfParams = kdf ? newKdfParams(kdf.opsLimit, kdf.memLimitBytes) : newKdfParams();
      const codeKey = deriveMasterKey(code, kdfParams);
      const data = seal(codeKey, json({ keyVersion: m.keyVersion, keys: toB64(payload) }), ctxs.recovery(userId), `recovery:${userId}`);
      wipe(codeKey); wipe(payload); wipe(keys.boxPrivate); wipe(keys.signPrivate);
      const r = await this.api.post<{ recoveryUrl: string; recoveryToken: string }>(`/users/${userId}/recovery`, { blob: { data, kdfParams } });
      return { ...r, code: code.match(/.{4}/g)!.join("-") };
    } finally {
      wipe(recoveryPrivate);
    }
  }
}

function base32(b: Uint8Array): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, out = "";
  for (const x of b) {
    value = (value << 8) | x;
    bits += 8;
    while (bits >= 5) {
      out += A[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += A[(value << (5 - bits)) & 31];
  return out;
}

// ------------------------------------------------------------------ generatore di password

export function generatePassword(opts: { length?: number; upper?: boolean; lower?: boolean; digits?: boolean; symbols?: boolean } = {}): string {
  const length = Math.min(Math.max(opts.length ?? 20, 8), 128);
  const sets = [
    opts.lower !== false ? "abcdefghijkmnopqrstuvwxyz" : "",
    opts.upper !== false ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "",
    opts.digits !== false ? "23456789" : "",
    opts.symbols !== false ? "!#$%&*+-=?@^_" : "",
  ].filter(Boolean);
  if (!sets.length) throw new Error("Seleziona almeno un tipo di carattere");
  const all = sets.join("");
  const pick = (s: string) => {
    const lim = 256 - (256 % s.length);
    for (;;) {
      const b = globalThis.crypto.getRandomValues(new Uint8Array(1))[0]!;
      if (b < lim) return s[b % s.length]!;
    }
  };
  for (;;) {
    let out = "";
    for (let i = 0; i < length; i++) out += pick(all);
    if (sets.every((s) => [...out].some((c) => s.includes(c)))) return out;
  }
}

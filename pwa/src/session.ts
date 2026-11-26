/**
 * Sessione della PWA. Il Vault sbloccato (chiavi in chiaro) vive SOLO qui, in RAM:
 * mai scritto su disco. Ad ogni riapertura serve un nuovo sblocco.
 *
 * - online: `login` OPAQUE → token in RAM → `Vault.unlock` (scarica /me e lo mette in cache);
 * - offline: `Vault.unlock` legge /me dalla cache e ri-deriva la master key localmente.
 *
 * Auto-lock sull'inattività; `logout()` azzera la RAM e cancella la cache offline.
 */
import { Api, ApiError, login, ready, Vault } from "@startcredentials/client";
import { makeOfflineFetch, NetState } from "./offlineFetch.js";
import { deriveCacheKey } from "./cacheCrypto.js";
import { getCached, getMeta, setMeta, wipeAll } from "./db.js";

export interface Settings {
  serverUrl?: string;
  email?: string;
  pinnedOrgSignPublic?: string;
  autoLockMinutes: number;
}
const DEFAULTS: Settings = { autoLockMinutes: 5 };

export async function getSettings(): Promise<Settings> {
  return { ...DEFAULTS, ...((await getMeta<Partial<Settings>>("settings")) ?? {}) };
}
export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await getSettings()), ...patch };
  await setMeta("settings", next);
  return next;
}

export class SessionError extends Error {}

class Session {
  vault: Vault | null = null;
  private token: string | null = null;
  /** H2: chiave di cifratura della cache, solo in RAM mentre il vault è sbloccato. */
  private cacheKey: CryptoKey | null = null;
  net: NetState = { offline: !navigator.onLine };
  onLock: (() => void) | null = null;
  onNetChange: ((offline: boolean) => void) | null = null;
  private lockTimer: ReturnType<typeof setTimeout> | null = null;

  private async api(): Promise<Api> {
    const s = await getSettings();
    if (!s.serverUrl) throw new SessionError("Server non configurato");
    const origin = new URL(s.serverUrl).origin;
    this.net.onChange = (off) => this.onNetChange?.(off);
    return new Api({ baseUrl: s.serverUrl, token: this.token ?? undefined, fetch: makeOfflineFetch(origin, this.net, () => this.cacheKey) });
  }

  /** Accesso online: OPAQUE + sblocco. Lo scheletro gestisce solo lo stato "active". */
  async signIn(email: string, password: string): Promise<void> {
    await ready();
    await saveSettings({ email });
    const api = await this.api();
    const res = await login(api, email, password);
    if (res.state !== "active") {
      throw new SessionError(
        res.state === "mfa_setup" ? "Questo account richiede la configurazione MFA (non nello scheletro)." : "Serve un codice MFA (non nello scheletro).",
      );
    }
    this.token = api.token ?? null;
    const s = await getSettings();
    const vault = await Vault.unlock(api, password, { pinnedOrgSignPublic: s.pinnedOrgSignPublic });
    await this.adopt(vault);
  }

  /** Sblocco offline (o online senza ri-login): /me arriva dalla cache, la master key si ri-deriva qui. */
  async unlockLocal(password: string): Promise<void> {
    await ready();
    const api = await this.api();
    const s = await getSettings();
    const vault = await Vault.unlock(api, password, { pinnedOrgSignPublic: s.pinnedOrgSignPublic });
    await this.adopt(vault);
  }

  private async adopt(vault: Vault): Promise<void> {
    this.vault = vault;
    // H2: deriva la chiave di cifratura della cache dal materiale di chiave del vault (solo RAM).
    this.cacheKey = await deriveCacheKey(vault.serialize().keys).catch(() => null);
    // Org pinning (TOFU): fissa/aggiorna la chiave dopo una rotazione legittima già verificata da unlock.
    if (vault.me.org) await saveSettings({ pinnedOrgSignPublic: vault.me.org.signPublic });
    this.resetAutoLock();
  }

  /** C'è un bundle avvolto in cache? Allora è possibile uno sblocco offline. */
  async canUnlockLocal(): Promise<boolean> {
    const s = await getSettings();
    if (!s.serverUrl) return false;
    const origin = new URL(s.serverUrl).origin;
    return !!(await getCached(origin, "/api/v1/me").catch(() => null));
  }

  resetAutoLock(): void {
    if (this.lockTimer) clearTimeout(this.lockTimer);
    void getSettings().then((s) => {
      if (!this.vault) return;
      this.lockTimer = setTimeout(() => this.lock(), Math.max(1, s.autoLockMinutes) * 60_000);
    });
  }

  lock(): void {
    if (this.lockTimer) clearTimeout(this.lockTimer);
    this.lockTimer = null;
    this.vault?.lock();
    this.vault = null;
    this.token = null;
    this.cacheKey = null; // H2: via la chiave di cache dalla RAM
    this.onLock?.();
  }

  /** Uscita completa: azzera la RAM e cancella la cache offline (ciphertext + bundle avvolto). */
  async logout(): Promise<void> {
    const api = await this.api().catch(() => null);
    if (api && this.token) await import("@startcredentials/client").then((m) => m.logout(api)).catch(() => undefined);
    this.lock();
    await wipeAll().catch(() => undefined);
  }
}

export const session = new Session();
export { ApiError };

/**
 * Stato condiviso tra popup, applicazione e service worker.
 *
 * - chrome.storage.local: solo impostazioni non segrete (server, email,
 *   chiave dell'organizzazione fissata al primo accesso).
 * - chrome.storage.session: token di sessione e chiavi sbloccate. Vive solo in
 *   memoria, non è accessibile agli script delle pagine web e si svuota alla
 *   chiusura del browser o al blocco.
 */
import { Api, SerializedSession, Vault } from "@startcredentials/client";

export interface Settings {
  serverUrl?: string;
  email?: string;
  pinnedOrgSignPublic?: string;
  autoLockMinutes: number;
  clipboardSeconds: number;
  inlineIcon?: boolean;
  /** Proposta di salvare le password inviate sui siti (richiede l'icona nei campi). */
  saveOffer?: boolean;
}

const DEFAULTS: Settings = { autoLockMinutes: 15, clipboardSeconds: 30 };

export async function getSettings(): Promise<Settings> {
  const s = await chrome.storage.local.get("settings");
  return { ...DEFAULTS, ...(s.settings ?? {}) };
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.local.set({ settings: next });
  return next;
}

interface SessionData {
  token?: string;
  vault?: SerializedSession;
  lastActivity?: number;
}

async function getSession(): Promise<SessionData> {
  return (await chrome.storage.session.get("s")).s ?? {};
}

async function setSession(patch: Partial<SessionData>): Promise<void> {
  await chrome.storage.session.set({ s: { ...(await getSession()), ...patch } });
}

export async function api(): Promise<Api> {
  const [settings, session] = await Promise.all([getSettings(), getSession()]);
  if (!settings.serverUrl) throw new Error("Server non configurato");
  return new Api({ baseUrl: settings.serverUrl, token: session.token });
}

export async function saveToken(token: string | undefined): Promise<void> {
  await setSession({ token, lastActivity: Date.now() });
}

let cached: Vault | null = null;

export async function currentVault(): Promise<Vault | null> {
  const session = await getSession();
  if (!session.vault || !session.token) {
    cached = null;
    return null;
  }
  if (cached && cached.api.token === session.token) return cached;
  const settings = await getSettings();
  cached = await Vault.restore(new Api({ baseUrl: settings.serverUrl!, token: session.token }), session.vault, {
    pinnedOrgSignPublic: settings.pinnedOrgSignPublic,
  });
  // Rotazione legittima della chiave dell'organizzazione (catena verificata): aggiorna la chiave fissata.
  if (cached.me.org && settings.pinnedOrgSignPublic !== cached.me.org.signPublic) {
    await saveSettings({ pinnedOrgSignPublic: cached.me.org.signPublic });
    await chrome.storage.session.set({ s: { ...(await getSession()), vault: cached.serialize() } });
    await cached.ensureRecoveryCopy().catch(() => undefined);
  }
  return cached;
}

/** Dopo lo sblocco: fissa la chiave dell'organizzazione (TOFU) e salva la sessione. */
export async function storeVault(v: Vault): Promise<void> {
  const settings = await getSettings();
  // Primo accesso (TOFU) o rotazione già verificata nello sblocco: si fissa la chiave attuale.
  if (v.me.org && settings.pinnedOrgSignPublic !== v.me.org.signPublic) await saveSettings({ pinnedOrgSignPublic: v.me.org.signPublic });
  cached = v;
  await setSession({ vault: v.serialize(), token: v.api.token, lastActivity: Date.now() });
}

/** Blocca: le chiavi spariscono, il token resta (basta la master password per riaprire). */
export async function lock(): Promise<void> {
  cached?.lock();
  cached = null;
  await setSession({ vault: undefined });
}

export async function signOut(): Promise<void> {
  try {
    const a = await api();
    if (a.token) await a.post("/auth/logout");
  } catch {
    /* sessione già scaduta */
  }
  cached?.lock();
  cached = null;
  await chrome.storage.session.clear();
}

export async function touch(): Promise<void> {
  const s = await getSession();
  if (s.vault) await setSession({ lastActivity: Date.now() });
}

export async function hasToken(): Promise<boolean> {
  return !!(await getSession()).token;
}

/** Chiamato dal service worker ogni minuto. */
export async function lockIfIdle(): Promise<void> {
  const [s, settings] = await Promise.all([getSession(), getSettings()]);
  if (s.vault && s.lastActivity && Date.now() - s.lastActivity > settings.autoLockMinutes * 60_000) await lock();
}

/** Copia negli appunti e chiede al service worker di svuotarli dopo qualche secondo. */
export async function copySecret(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  const { clipboardSeconds } = await getSettings();
  chrome.runtime.sendMessage({ type: "clear-clipboard", afterSeconds: clipboardSeconds }).catch(() => undefined);
}

/** Permesso di contattare il server: richiesto una sola volta, solo per quell'origine. */
export async function ensureServerPermission(serverUrl: string): Promise<boolean> {
  const origin = `${new URL(serverUrl).origin}/*`;
  if (await chrome.permissions.contains({ origins: [origin] })) return true;
  return chrome.permissions.request({ origins: [origin] });
}

const INLINE_ID = "sc-inline";

/** Attiva l'icona nei campi: chiede il permesso per le pagine HTTPS e registra lo script. */
export async function enableInlineIcon(): Promise<boolean> {
  const ok = await chrome.permissions.request({ origins: ["https://*/*"] });
  if (!ok) return false;
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [INLINE_ID] });
  if (!existing.length) {
    await chrome.scripting.registerContentScripts([{
      id: INLINE_ID, js: ["inline.js"], matches: ["https://*/*"], runAt: "document_idle", allFrames: false, persistAcrossSessions: true,
    }]);
  }
  await saveSettings({ inlineIcon: true });
  return true;
}

export async function disableInlineIcon(): Promise<void> {
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [INLINE_ID] });
  if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [INLINE_ID] });
  // Il permesso sulle pagine HTTPS non viene revocato da qui: comprende anche il
  // server StartCredentials. Senza lo script registrato non viene comunque usato.
  await saveSettings({ inlineIcon: false });
}

export function initials(name: string): string {
  const parts = name.replace(/[^\p{L}\p{N} ]/gu, " ").split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

const TINTS = [
  ["#E8F2FC", "#00519F"], ["#FBEBD6", "#6B3A05"], ["#E3E9F8", "#1F3B78"], ["#F1E4F2", "#5A2563"],
  ["#E4EFDB", "#2C5A16"], ["#F6E2DC", "#7A2A12"], ["#DDF0F2", "#0E5560"], ["#F3EBD3", "#5E4A0B"],
];
export function tint(seed: string): { bg: string; fg: string } {
  let h = 0;
  for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const [bg, fg] = TINTS[h % TINTS.length]!;
  return { bg, fg };
}

export function relTime(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "adesso";
  if (s < 3600) return `${Math.floor(s / 60)} min fa`;
  if (s < 86400) return `${Math.floor(s / 3600)} h fa`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)} g fa`;
  return new Date(iso).toLocaleDateString("it-IT");
}

export function errorText(e: unknown): string {
  const map: Record<string, string> = {
    invalid_credentials: "Email o master password non corretti.",
    invalid_code: "Codice non valido o già usato: attendi il prossimo e riprova.",
    rate_limited: "Troppi tentativi: attendi un minuto.",
    invalid_invite: "Invito non valido o scaduto: chiedine uno nuovo all'amministratore.",
    bootstrap_used: "L'amministratore iniziale è già stato creato.",
    revision_conflict: "Qualcun altro ha modificato questo elemento: ricarica e riprova.",
    write_required: "Hai solo il permesso di lettura su questo cliente.",
    manage_required: "Serve il permesso di gestione su questo cliente.",
    last_manager: "Il cliente deve avere almeno una persona con permesso di gestione.",
    recipient_not_certified: "La chiave del destinatario non è ancora certificata da un amministratore.",
    attachment_too_large: "Il file supera il limite consentito dal server.",
    unauthorized: "Sessione scaduta: accedi di nuovo.",
    email_taken: "Esiste già un utente con questa email.",
    cannot_modify_self: "Questa operazione non si può fare sul proprio account.",
    group_name_taken: "Esiste già un gruppo con questo nome.",
    group_rotation_pending: "La chiave del gruppo deve prima essere ruotata da un suo gestore.",
    last_group_manager: "Il gruppo deve avere almeno un gestore.",
    group_managers_must_be_admins: "Solo gli amministratori possono essere gestori di un gruppo.",
    group_manager_required: "Solo i gestori del gruppo possono modificarlo.",
  };
  const err = e as { code?: string; message?: string };
  return (err.code && map[err.code]) || err.message || "Errore imprevisto.";
}

export function download(bytes: Uint8Array, name: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * Cartelle aperte per cliente (solo identificativi, nessun dato riservato).
 * Di base le cartelle sono chiuse: aprendo un cliente si vedono subito gli elementi senza cartella.
 */
export async function loadExpanded(containerId: string): Promise<string[]> {
  const r = await chrome.storage.local.get("expanded");
  return r.expanded?.[containerId] ?? [];
}

export async function saveExpanded(containerId: string, ids: string[]): Promise<void> {
  const r = await chrome.storage.local.get("expanded");
  await chrome.storage.local.set({ expanded: { ...(r.expanded ?? {}), [containerId]: ids } });
}

/**
 * Preferiti: solo identificativi (nessun dato riservato), per utente, su questo browser.
 * Un evento avvisa le altre viste aperte quando cambiano.
 */
export interface Favorite { itemId: string; containerId: string }

export async function loadFavorites(userId: string): Promise<Favorite[]> {
  const r = await chrome.storage.local.get("favorites");
  return r.favorites?.[userId] ?? [];
}

export async function saveFavorites(userId: string, favs: Favorite[]): Promise<void> {
  const r = await chrome.storage.local.get("favorites");
  await chrome.storage.local.set({ favorites: { ...(r.favorites ?? {}), [userId]: favs } });
  window.dispatchEvent(new CustomEvent("sc-favorites"));
}

export type ClientsView = "list" | "grid";

/** Vista dell'elenco clienti scelta dall'utente (elenco compatto o caselle). */
export async function loadClientsView(): Promise<ClientsView> {
  const r = await chrome.storage.local.get("clientsView");
  return r.clientsView === "grid" ? "grid" : "list";
}

export async function saveClientsView(v: ClientsView): Promise<void> {
  await chrome.storage.local.set({ clientsView: v });
}

export interface PendingSave { tabId: number; host: string; username: string; password: string; at: number }

/** Accesso in attesa di essere salvato, se ancora valido (5 minuti). */
export async function getPendingSave(): Promise<PendingSave | null> {
  const { pendingSave } = await chrome.storage.session.get("pendingSave");
  if (!pendingSave || Date.now() - pendingSave.at > 5 * 60_000) return null;
  return pendingSave;
}

export async function clearPendingSave(tabId?: number): Promise<void> {
  await chrome.storage.session.remove("pendingSave");
  if (tabId) await chrome.action.setBadgeText({ text: "", tabId }).catch(() => undefined);
}

// ------------------------------------------------------------------ dispositivo attendibile

export interface DeviceTrust { token: string; deviceId: string; expiresAt: string; email: string; serverUrl: string }

/** Token del dispositivo attendibile per questo utente e server, se ancora valido. */
export async function getDeviceTrust(email: string): Promise<DeviceTrust | null> {
  const [{ deviceTrust }, settings] = await Promise.all([chrome.storage.local.get("deviceTrust"), getSettings()]);
  const t = deviceTrust as DeviceTrust | undefined;
  if (!t || t.serverUrl !== settings.serverUrl || t.email.toLowerCase() !== email.toLowerCase() || new Date(t.expiresAt) < new Date()) return null;
  return t;
}

export async function saveDeviceTrust(t: DeviceTrust): Promise<void> {
  await chrome.storage.local.set({ deviceTrust: t });
}

export async function clearDeviceTrust(): Promise<void> {
  await chrome.storage.local.remove("deviceTrust");
}

/** Nome leggibile del dispositivo, es. "Chrome su Windows". */
export function deviceName(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "dispositivo";
  return `${browser} su ${os}`;
}

// ------------------------------------------------------------------ versioni

export interface Versions { extension: string; server: string | null; mismatch: boolean }

/** Versione dell'estensione (manifest) e del server (indirizzo pubblico /api/v1/version). */
export async function loadVersions(): Promise<Versions> {
  const extension = chrome.runtime.getManifest?.().version ?? "?";
  let server: string | null = null;
  try {
    const { serverUrl } = await getSettings();
    if (serverUrl) {
      const r = await fetch(`${serverUrl}/api/v1/version`, { cache: "no-store" });
      if (r.ok) server = ((await r.json()) as { version?: string }).version ?? null;
    }
  } catch {
    server = null;
  }
  // Disallineate se cambia la versione principale o intermedia (es. 0.6.x contro 0.7.x).
  const mm = (v: string) => v.split(".").slice(0, 2).join(".");
  return { extension, server, mismatch: !!server && mm(server) !== mm(extension) };
}

/** Nomi in italiano delle azioni del registro attività. */
export const ACTION_LABEL: Record<string, string> = {
  "auth.login": "Accesso", "auth.login_failed": "Accesso non riuscito", "auth.mfa_enabled": "MFA attivata", "auth.mfa_failed": "Codice MFA errato",
  "user.registered": "Registrazione", "user.invited": "Invito", "user.updated": "Utente modificato", "user.key_certified": "Chiave certificata",
  "user.recovery_started": "Recupero avviato", "user.recovery_completed": "Recupero completato", "org.initialized": "Organizzazione inizializzata",
  "container.created": "Cliente creato", "container.updated": "Cliente modificato", "container.deleted": "Cliente eliminato",
  "container.member_set": "Accesso concesso", "container.member_removed": "Accesso rimosso", "container.key_rotated": "Chiave ruotata",
  "container.imported": "Import", "container.export": "Export", "folder.created": "Cartella creata", "folder.deleted": "Cartella eliminata",
  "item.created": "Elemento creato", "item.updated": "Elemento modificato", "item.deleted": "Elemento nel cestino", "item.restored": "Elemento ripristinato",
  "item.reveal": "Password mostrata", "item.copy": "Password copiata", "item.fill": "Compilazione automatica", "item.totp_copy": "OTP copiato",
  "attachment.added": "Allegato aggiunto", "attachment.deleted": "Allegato eliminato",
  "audit.pruned": "Pulizia del registro", "item.moved": "Elemento spostato", "org.key_rotated": "Chiave dell'organizzazione ruotata",
  "group.created": "Gruppo creato", "group.member_set": "Membro del gruppo", "group.member_removed": "Uscita dal gruppo", "group.key_rotated": "Chiave del gruppo ruotata",
  "user.offboarded": "Uscita dall'azienda", "user.mfa_reset": "MFA reimpostata", "user.password_changed": "Master password cambiata",
  "item.shared": "Password condivisa singolarmente", "item.unshared": "Condivisione singola tolta", "item.rekeyed": "Chiave dell'elemento rinnovata",
  "send.created": "Invio sicuro creato", "send.opened": "Invio sicuro aperto", "send.revoked": "Invio sicuro revocato",
  "container.group_set": "Accesso concesso a un gruppo", "container.group_removed": "Accesso tolto a un gruppo",
  "auth.device_trusted": "Dispositivo attendibile", "auth.device_revoked": "Dispositivo revocato",
  "auth.mfa_backup_used": "Codice di riserva MFA usato", "auth.mfa_backup_regenerated": "Codici di riserva MFA rigenerati",
  "group.deleted": "Gruppo eliminato", "group.renamed": "Gruppo rinominato", "user.recovery_email_set": "Email di recupero impostata",
};

/**
 * Service worker: blocco automatico per inattività e svuotamento degli appunti.
 * Volutamente senza dipendenze crittografiche: non tiene né usa chiavi.
 */
chrome.runtime.onInstalled.addListener((d) => {
  chrome.alarms.create("autolock", { periodInMinutes: 1 });
  void ensureSiteScript();
  if (d.reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("app.html") });
});
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create("autolock", { periodInMinutes: 1 });
  void ensureSiteScript();
});

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "autolock") await lockIfIdle();
  if (a.name === "clear-clipboard") await clearClipboard();
  if (a.name === "pending-save-expire") await chrome.storage.session.remove("pendingSave");
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (sender.id !== chrome.runtime.id) return;
  if (msg?.type === "server-configured") {
    void ensureSiteScript();
    return;
  }
  // Clic sull'icona nei campi: apre il popup, dove avvengono ricerca e compilazione.
  if (msg?.type === "open-popup" && sender.tab) {
    chrome.action.openPopup({ windowId: sender.tab.windowId }).catch(() => {
      // Browser che non permettono l'apertura: segnaliamo sull'icona della barra.
      if (sender.tab?.id) {
        chrome.action.setBadgeBackgroundColor({ color: "#0068CF", tabId: sender.tab.id });
        chrome.action.setBadgeText({ text: "1", tabId: sender.tab.id });
      }
    });
    return;
  }
  if (msg?.type === "open-app" && sender.tab?.id && sender.url) {
    void openAppFromSite(sender.tab.id, sender.url, String(msg.hash ?? ""));
    return;
  }
  if (msg?.type === "login-captured" && sender.tab?.id && sender.url) {
    void storeCapture(sender.tab.id, sender.url, String(msg.username ?? ""), String(msg.password ?? ""));
    return;
  }
  if (msg?.type === "clear-clipboard") {
    const seconds = Math.max(30, Math.min(300, Number(msg.afterSeconds) || 30));
    chrome.alarms.create("clear-clipboard", { when: Date.now() + seconds * 1000 });
  }
});

/** Dalla pagina del server: apre l'applicazione, eventualmente con l'invito o il recupero. */
async function openAppFromSite(tabId: number, url: string, hash: string): Promise<void> {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings?.serverUrl || new URL(url).origin !== new URL(settings.serverUrl).origin) return;
  const safe = /^#(invite|recover)=[A-Za-z0-9_-]{16,200}$/.test(hash) ? hash : "";
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`app.html${safe}`) });
}

/** Registra lo script di riconoscimento sulle pagine del server configurato. */
async function ensureSiteScript(): Promise<void> {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings?.serverUrl) return;
  const u = new URL(settings.serverUrl);
  const match = `${u.protocol}//${u.hostname}/*`;
  if (!(await chrome.permissions.contains({ origins: [`${u.origin}/*`] }))) return;
  const [existing] = await chrome.scripting.getRegisteredContentScripts({ ids: ["sc-site"] });
  if (existing?.matches?.[0] === match) return;
  if (existing) await chrome.scripting.unregisterContentScripts({ ids: ["sc-site"] });
  await chrome.scripting.registerContentScripts([{ id: "sc-site", js: ["site.js"], matches: [match], runAt: "document_idle", allFrames: false, persistAcrossSessions: true }]);
}

/** Accesso appena inviato su un sito: resta solo in memoria di sessione, per 5 minuti. */
async function storeCapture(tabId: number, url: string, username: string, password: string): Promise<void> {
  const { settings } = await chrome.storage.local.get("settings");
  if (settings?.saveOffer === false || !password || password.length > 512) return;
  let host: string;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return;
    host = u.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return;
  }
  await chrome.storage.session.set({ pendingSave: { tabId, host, username: username.slice(0, 256), password, at: Date.now() } });
  chrome.alarms.create("pending-save-expire", { when: Date.now() + 5 * 60_000 });
  await chrome.action.setBadgeBackgroundColor({ color: "#0068CF", tabId });
  await chrome.action.setBadgeText({ text: "+", tabId });
}

async function lockIfIdle(): Promise<void> {
  const { s } = await chrome.storage.session.get("s");
  const { settings } = await chrome.storage.local.get("settings");
  const minutes = Number(settings?.autoLockMinutes ?? 15);
  if (s?.vault && s.lastActivity && Date.now() - s.lastActivity > minutes * 60_000) {
    await chrome.storage.session.set({ s: { ...s, vault: undefined } });
  }
}

async function clearClipboard(): Promise<void> {
  if (!(await chrome.offscreen.hasDocument())) {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: "Svuotare gli appunti dopo la copia di una password",
    });
  }
  await chrome.runtime.sendMessage({ type: "offscreen-clear" });
  await chrome.offscreen.closeDocument();
}

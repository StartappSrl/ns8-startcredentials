/**
 * Service worker: blocco automatico per inattività e svuotamento degli appunti.
 * Volutamente senza dipendenze crittografiche: non tiene né usa chiavi.
 */
chrome.runtime.onInstalled.addListener((d) => {
  chrome.alarms.create("autolock", { periodInMinutes: 1 });
  if (d.reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("app.html") });
});
chrome.runtime.onStartup.addListener(() => chrome.alarms.create("autolock", { periodInMinutes: 1 }));

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "autolock") await lockIfIdle();
  if (a.name === "clear-clipboard") await clearClipboard();
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (sender.id !== chrome.runtime.id) return;
  if (msg?.type === "clear-clipboard") {
    const seconds = Math.max(30, Math.min(300, Number(msg.afterSeconds) || 30));
    chrome.alarms.create("clear-clipboard", { when: Date.now() + seconds * 1000 });
  }
});

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

/**
 * Compilazione dei campi di accesso. Prima di iniettare verifica che la scheda
 * sia ancora sullo stesso nome host dell'elemento e che sia in HTTPS; inietta
 * solo nel frame principale, mai in iframe di altri siti.
 */
import { normalizeHost } from "@startcredentials/client";

export async function fillTab(tabId: number, expectedHost: string, username: string | undefined, password: string | undefined, otp?: string): Promise<void> {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url) throw new Error("Impossibile leggere l'indirizzo della scheda");
  const url = new URL(tab.url);
  if (url.protocol !== "https:" && url.hostname !== "localhost") throw new Error("Compilazione consentita solo su pagine HTTPS");
  if (normalizeHost(url.hostname) !== normalizeHost(expectedHost)) throw new Error("La pagina è cambiata: compilazione annullata");
  const [res] = await chrome.scripting.executeScript({
    target: { tabId, frameIds: [0] },
    func: injectedFill,
    args: [normalizeHost(expectedHost), username ?? "", password ?? "", otp ?? ""],
  });
  if (!res?.result) throw new Error("Nessun campo di accesso trovato nella pagina");
}

// Gira nella pagina: nessun riferimento a variabili esterne.
function injectedFill(host: string, username: string, password: string, otp: string): boolean {
  if (location.hostname.toLowerCase().replace(/\.$/, "") !== host) return false;
  const visible = (el: HTMLElement) => {
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && st.visibility !== "hidden" && st.display !== "none";
  };
  const set = (el: HTMLInputElement, v: string) => {
    const proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    proto?.set?.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = Array.from(document.querySelectorAll("input")).filter((i) => visible(i) && !i.disabled && !i.readOnly);
  const pwd = inputs.find((i) => i.type === "password");
  const scope: ParentNode = pwd?.form ?? document;
  const candidates = Array.from(scope.querySelectorAll("input")).filter((i) => inputs.includes(i));
  const before = pwd ? candidates.slice(0, candidates.indexOf(pwd)) : candidates;
  const user = [...before].reverse().find((i) => ["text", "email", "tel", ""].includes(i.type) &&
    /user|login|mail|account|name|utente|id/i.test(`${i.name} ${i.id} ${i.autocomplete} ${i.placeholder}`))
    ?? [...before].reverse().find((i) => ["text", "email"].includes(i.type));
  let done = false;
  if (user && username) { set(user, username); done = true; }
  if (pwd && password) { set(pwd, password); pwd.focus(); done = true; }
  // Campo del codice OTP (stessa pagina o pagina successiva del login).
  if (otp) {
    const otpField = inputs.find((i) => i !== user && i !== pwd && ["text", "tel", "number", ""].includes(i.type) && (
      i.autocomplete === "one-time-code" ||
      /otp|totp|2fa|mfa|one.?time|codice|verification|verifica|auth.?code|token/i.test(`${i.name} ${i.id} ${i.placeholder} ${i.getAttribute("aria-label") ?? ""}`)));
    if (otpField) { set(otpField, otp); if (!pwd) otpField.focus(); done = true; }
  }
  return done;
}

/**
 * Icona StartCredentials nei campi di accesso (funzione facoltativa).
 * Non contiene chiavi né dati: al clic chiede al service worker di aprire il
 * popup, dove avvengono la ricerca e la compilazione con i controlli di dominio.
 */
(() => {
  if (window.top !== window || (window as unknown as { __scInline?: boolean }).__scInline) return;
  (window as unknown as { __scInline?: boolean }).__scInline = true;

  let host: HTMLDivElement | null = null;
  let button: HTMLButtonElement | null = null;
  let current: HTMLInputElement | null = null;
  let hideTimer: number | undefined;

  const visible = (el: HTMLElement) => {
    const r = el.getBoundingClientRect();
    return r.width > 30 && r.height > 12;
  };

  function isLoginField(t: EventTarget | null): t is HTMLInputElement {
    if (!(t instanceof HTMLInputElement) || t.disabled || t.readOnly || !visible(t)) return false;
    if (t.type === "password") return true;
    if (!["text", "email", "tel", ""].includes(t.type)) return false;
    const hint = `${t.name} ${t.id} ${t.autocomplete} ${t.placeholder} ${t.getAttribute("aria-label") ?? ""}`;
    if (!/user|login|mail|account|utente|accesso|username/i.test(hint)) return false;
    // Solo nei moduli che contengono anche un campo password.
    const scope: ParentNode = t.form ?? document;
    return !!scope.querySelector('input[type="password"]');
  }

  function ensureUi() {
    if (host) return;
    host = document.createElement("div");
    host.style.cssText = "position:absolute;top:0;left:0;width:0;height:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        button { all: initial; position: absolute; display: none; width: 24px; height: 24px; border-radius: 6px;
                 background: #0068CF; cursor: pointer; box-shadow: 0 1px 3px rgba(0,0,0,.35); }
        button:hover { background: #00519F; }
        button:focus-visible { outline: 2px solid #0068CF; outline-offset: 2px; }
        svg { display: block; width: 14px; height: 14px; margin: 5px; }
      </style>
      <button type="button" title="Compila con StartCredentials" aria-label="Compila con StartCredentials">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="4" y="10" width="16" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
        </svg>
      </button>`;
    button = root.querySelector("button");
    // mousedown non deve togliere il focus al campo.
    button!.addEventListener("mousedown", (e) => e.preventDefault());
    button!.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      chrome.runtime.sendMessage({ type: "open-popup" }).catch(() => undefined);
    });
    document.documentElement.appendChild(host);
  }

  function place() {
    if (!button || !current || !current.isConnected || !visible(current)) return hide();
    const r = current.getBoundingClientRect();
    const size = 24;
    button.style.left = `${window.scrollX + r.right - size - 6}px`;
    button.style.top = `${window.scrollY + r.top + Math.max(0, (r.height - size) / 2)}px`;
    button.style.display = "block";
  }

  function hide() {
    if (button) button.style.display = "none";
    current = null;
  }

  document.addEventListener("focusin", (e) => {
    if (!isLoginField(e.target)) return;
    clearTimeout(hideTimer);
    ensureUi();
    current = e.target;
    place();
  }, true);
  document.addEventListener("focusout", () => {
    hideTimer = window.setTimeout(hide, 200);
  }, true);
  window.addEventListener("scroll", () => current && place(), true);
  window.addEventListener("resize", () => current && place());
})();

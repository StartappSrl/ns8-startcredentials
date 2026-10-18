/**
 * Icona StartCredentials nei campi di accesso (funzione facoltativa).
 * Non contiene chiavi né dati: al clic apre sotto il campo il menu
 * dell'estensione (riquadro isolato), dove avvengono ricerca e compilazione.
 */
(() => {
  if (window.top !== window || (window as unknown as { __scInline?: boolean }).__scInline) return;
  (window as unknown as { __scInline?: boolean }).__scInline = true;

  let host: HTMLDivElement | null = null;
  let button: HTMLButtonElement | null = null;
  let frame: HTMLIFrameElement | null = null;
  let current: HTMLInputElement | null = null;
  let kind: "login" | "otp" = "login";
  let hideTimer: number | undefined;

  const visible = (el: HTMLElement) => {
    const r = el.getBoundingClientRect();
    return r.width > 30 && r.height > 12;
  };

  /** Campo di accesso o campo del codice OTP; null per tutti gli altri. */
  function classify(t: EventTarget | null): "login" | "otp" | null {
    if (!(t instanceof HTMLInputElement) || t.disabled || t.readOnly || !visible(t)) return null;
    if (t.type === "password") return "login";
    if (!["text", "email", "tel", "number", ""].includes(t.type)) return null;
    const hint = `${t.name} ${t.id} ${t.autocomplete} ${t.placeholder} ${t.getAttribute("aria-label") ?? ""}`;
    if (t.autocomplete === "one-time-code" || /otp|totp|2fa|mfa|one.?time|codice di verifica|verification code|auth.?code/i.test(hint)) return "otp";
    if (!/user|login|mail|account|utente|accesso|username/i.test(hint)) return null;
    // Solo nei moduli che contengono anche un campo password.
    const scope: ParentNode = t.form ?? document;
    return scope.querySelector('input[type="password"]') ? "login" : null;
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
        iframe { position: absolute; display: none; width: 300px; height: 240px; border: 1px solid #CFDBEA; border-radius: 10px;
                 box-shadow: 0 8px 24px rgba(11,27,46,.18); background: #fff; color-scheme: normal; }
      </style>
      <button type="button" title="StartCredentials" aria-label="Apri le credenziali di StartCredentials">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="4" y="10" width="16" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
        </svg>
      </button>
      <iframe title="StartCredentials"></iframe>`;
    button = root.querySelector("button");
    frame = root.querySelector("iframe");
    // mousedown non deve togliere il focus al campo.
    button!.addEventListener("mousedown", (e) => e.preventDefault());
    button!.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (frame!.style.display === "block") closeMenu();
      else openMenu();
    });
    document.documentElement.appendChild(host);
  }

  function openMenu() {
    if (!frame || !current) return;
    frame.src = `${chrome.runtime.getURL("inline-menu.html")}#field=${kind}`;
    const r = current.getBoundingClientRect();
    frame.style.left = `${window.scrollX + Math.max(4, r.left)}px`;
    frame.style.top = `${window.scrollY + r.bottom + 4}px`;
    frame.style.display = "block";
  }

  function closeMenu() {
    if (frame) {
      frame.style.display = "none";
      frame.removeAttribute("src");
    }
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
    // Con il menu aperto (focus dentro il riquadro) l'icona resta.
    if (frame?.style.display === "block") return;
    if (button) button.style.display = "none";
    current = null;
  }

  document.addEventListener("focusin", (e) => {
    const k = classify(e.target);
    if (!k) return;
    clearTimeout(hideTimer);
    ensureUi();
    if (current !== e.target) closeMenu();
    current = e.target as HTMLInputElement;
    kind = k;
    place();
  }, true);
  document.addEventListener("focusout", () => {
    hideTimer = window.setTimeout(hide, 200);
  }, true);
  document.addEventListener("mousedown", (e) => {
    if (host && !e.composedPath().includes(host)) closeMenu();
  }, true);
  // Il menu (pagina dell'estensione) chiede di chiudersi dopo la compilazione.
  window.addEventListener("message", (e) => {
    if (e.origin === new URL(chrome.runtime.getURL("")).origin && e.data?.type === "sc-inline-close") {
      closeMenu();
      hide();
    }
  });
  window.addEventListener("scroll", () => current && place(), true);
  window.addEventListener("resize", () => current && place());

  // ---------------------------------------------------------------- proposta di salvataggio
  // All'invio di un modulo di accesso, utente e password vanno al service worker
  // (solo memoria di sessione, scadenza 5 minuti) per proporre il salvataggio nel popup.
  let lastSent = "";
  function capture(scope: ParentNode) {
    const pwds = Array.from(scope.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter((p) => p.value);
    const pwd = pwds[0];
    // Più password compilate (es. cambio password): non indoviniamo quale salvare.
    if (!pwd || pwds.length > 1) return;
    const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>("input"));
    const before = inputs.slice(0, inputs.indexOf(pwd)).reverse();
    const user = before.find((i) => ["text", "email", "tel", ""].includes(i.type) && i.value.trim());
    const sig = `${location.hostname}|${user?.value ?? ""}|${pwd.value}`;
    if (sig === lastSent) return;
    lastSent = sig;
    chrome.runtime.sendMessage({ type: "login-captured", username: user?.value.trim() ?? "", password: pwd.value }).catch(() => undefined);
  }
  document.addEventListener("submit", (e) => capture(e.target as HTMLFormElement), true);
  document.addEventListener("click", (e) => {
    const b = (e.target as Element | null)?.closest?.('button, input[type="submit"], [role="button"]');
    if (!b) return;
    const form = b.closest("form");
    capture(form ?? document);
  }, true);
  document.addEventListener("keydown", (e) => {
    const t = e.target;
    if (e.key === "Enter" && t instanceof HTMLInputElement && t.type === "password") capture(t.form ?? document);
  }, true);
})();

/**
 * Script inserito dall'estensione SOLO nelle pagine del server StartCredentials
 * configurato. Fa riconoscere l'estensione installata e permette di aprire un
 * collegamento di invito o di recupero direttamente nell'estensione.
 * Non legge né invia nulla della pagina oltre al frammento #invite=/#recover=.
 */
(() => {
  const installed = document.getElementById("sc-installed");
  if (!installed) return;
  document.getElementById("sc-install")?.setAttribute("hidden", "");
  installed.removeAttribute("hidden");

  const h = new URLSearchParams(location.hash.replace(/^#/, ""));
  const valid = (t: string | null) => !!t && /^[A-Za-z0-9_-]{16,200}$/.test(t);
  const invite = h.get("invite");
  const recover = h.get("recover");
  const hash = valid(invite) ? `#invite=${invite}` : valid(recover) ? `#recover=${recover}` : "";

  if (hash) {
    document.getElementById("sc-invite")?.removeAttribute("hidden");
    const kind = document.getElementById("sc-invite-kind");
    if (kind) kind.textContent = invite ? "di invito" : "di recupero dell'account";
    const accept = document.getElementById("sc-accept");
    if (accept) {
      accept.removeAttribute("hidden");
      accept.textContent = invite ? "Attiva l'invito nell'estensione" : "Recupera l'account nell'estensione";
      accept.addEventListener("click", () => chrome.runtime.sendMessage({ type: "open-app", hash }).catch(() => undefined));
    }
  }
  document.getElementById("sc-open")?.addEventListener("click", () => chrome.runtime.sendMessage({ type: "open-app", hash: "" }).catch(() => undefined));
})();

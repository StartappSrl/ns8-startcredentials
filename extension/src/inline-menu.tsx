/**
 * Menu sotto i campi di accesso: pagina dell'estensione in un riquadro isolato,
 * illeggibile per gli script del sito. Il dominio si ricava dalla scheda, non
 * dalla pagina; la compilazione verifica sempre la corrispondenza esatta.
 */
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Container, effectiveTotpUri, Item, normalizeHost, ready, Vault } from "@startcredentials/client";
import { currentVault } from "./shared";
import { fillTab } from "./fill";
import { useAction } from "./ui/kit";

type Hit = { container: Container; item: Item };
const field = new URLSearchParams(location.hash.slice(1)).get("field") === "otp" ? "otp" : "login";
const close = () => window.parent.postMessage({ type: "sc-inline-close" }, "*");

function Code({ uri }: { uri: string }) {
  const [c, setC] = useState<{ code: string; secondsLeft: number } | null>(null);
  useEffect(() => {
    const tick = () => Vault.totp(uri).then(setC).catch(() => undefined);
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [uri]);
  return c ? <span class="mono">{c.code.slice(0, 3)} {c.code.slice(3)} <span class="muted small">{c.secondsLeft}s</span></span> : null;
}

function Menu() {
  const [state, setState] = useState<"loading" | "locked" | "ready">("loading");
  const [hits, setHits] = useState<Hit[]>([]);
  const [tab, setTab] = useState<chrome.tabs.Tab | null>(null);
  const { error, run } = useAction();

  useEffect(() => {
    run(async () => {
      await ready();
      const t = await chrome.tabs.getCurrent();
      setTab(t ?? null);
      const v = await currentVault().catch(() => null);
      if (!v || !t?.url) return setState("locked");
      const found = await v.lookup(t.url);
      setHits(field === "otp" ? found.filter((h) => effectiveTotpUri(h.item.data)) : found);
      setState("ready");
    });
    const esc = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, []);

  const fill = (h: Hit) => run(async () => {
    if (!tab?.id || !tab.url) return;
    const uri = effectiveTotpUri(h.item.data);
    const otp = uri ? (await Vault.totp(uri)).code : undefined;
    const host = normalizeHost(tab.url);
    if (field === "otp") await fillTab(tab.id, host, undefined, undefined, otp);
    else await fillTab(tab.id, host, h.item.data.username, h.item.data.password, otp);
    (await currentVault())?.report("item.fill", h.container.id, h.item.id);
    close();
  });

  return (
    <div class="im">
      <div class="im-head"><img src="icons/32.png" alt="" width="16" height="16" /><span>StartCredentials</span><button class="im-x" aria-label="Chiudi" onClick={close}>✕</button></div>
      {state === "loading" && <div class="im-empty">…</div>}
      {state === "locked" && (
        <div class="im-empty">
          <p>Cassaforte bloccata.</p>
          <button class="btn sm primary" onClick={() => { chrome.runtime.sendMessage({ type: "open-popup" }).catch(() => undefined); close(); }}>Sblocca</button>
        </div>
      )}
      {state === "ready" && hits.length === 0 && (
        <div class="im-empty">{field === "otp" ? "Nessun codice OTP salvato per questo sito." : "Nessuna credenziale salvata per questo sito."}</div>
      )}
      {state === "ready" && hits.map((h) => {
        const uri = effectiveTotpUri(h.item.data);
        return (
          <button class="im-item" onClick={() => fill(h)}>
            <span class="im-name ellipsis">{h.item.data.name}</span>
            <span class="im-sub ellipsis">{field === "otp" && uri ? <Code uri={uri} /> : (h.item.data.username || "senza utente")}{h.container.kind === "personal" ? " · Area personale" : ` · ${h.container.meta.name}`}</span>
          </button>
        );
      })}
      {error && <div class="im-empty notice error">{error}</div>}
    </div>
  );
}

render(<Menu />, document.getElementById("root")!);

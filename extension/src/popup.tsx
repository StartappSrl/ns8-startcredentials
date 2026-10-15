import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Container, generatePassword, Item, normalizeHost, ready, Vault } from "@startcredentials/client";
import { api, currentVault, getSettings, hasToken, lock } from "./shared";
import { fillTab } from "./fill";
import { Brand, CopyButton, ErrorNote, OtpCode, ToastHost, useAction, useToast } from "./ui/kit";
import { unlockWith } from "./ui/auth";

const openApp = (hash = "") => chrome.tabs.create({ url: chrome.runtime.getURL(`app.html${hash}`) }).then(() => window.close());

function Popup() {
  const [state, setState] = useState<"loading" | "setup" | "app" | "locked" | "ready">("loading");
  const [vault, setVault] = useState<Vault | null>(null);
  useEffect(() => {
    (async () => {
      await ready();
      const s = await getSettings();
      if (!s.serverUrl || !(await hasToken())) return setState("setup");
      const v = await currentVault().catch(() => null);
      if (v) {
        setVault(v);
        return setState("ready");
      }
      const sess = await (await api()).get<{ state: string }>("/auth/session").catch(() => null);
      setState(sess?.state === "active" ? "locked" : "app");
    })();
  }, []);

  if (state === "loading") return null;
  if (state === "setup" || state === "app") {
    return (
      <div class="pop-body" style="padding:24px;gap:16px">
        <Brand small />
        <p class="muted">{state === "setup" ? "Collega il server della tua azienda e accedi dall'applicazione." : "Completa l'accesso nell'applicazione."}</p>
        <button class="btn primary" onClick={() => openApp()}>Apri StartCredentials</button>
      </div>
    );
  }
  if (state === "locked") return <PopupUnlock onDone={(v) => { setVault(v); setState("ready"); }} />;
  return <Unlocked vault={vault!} />;
}

function PopupUnlock({ onDone }: { onDone: (v: Vault) => void }) {
  const [pw, setPw] = useState("");
  const { busy, error, run } = useAction();
  return (
    <form class="pop-body" style="padding:24px;gap:14px" onSubmit={(e) => { e.preventDefault(); run(async () => onDone(await unlockWith(pw))); }}>
      <Brand small />
      <p class="muted">Cassaforte bloccata</p>
      <input class="input" type="password" aria-label="Master password" placeholder="Master password" autoFocus required value={pw} onInput={(e) => setPw(e.currentTarget.value)} />
      <ErrorNote error={error} />
      <button class="btn primary" disabled={busy}>{busy ? "Sblocco…" : "Sblocca"}</button>
    </form>
  );
}

type Hit = { container: Container; item: Item };

function Unlocked({ vault }: { vault: Vault }) {
  const [tab, setTab] = useState<chrome.tabs.Tab | null>(null);
  const [host, setHost] = useState<string | null>(null);
  const [matches, setMatches] = useState<Hit[] | null>(null);
  const [q, setQ] = useState("");
  const [all, setAll] = useState<Hit[] | null>(null);
  const { error, run } = useAction();
  const toast = useToast();

  useEffect(() => {
    run(async () => {
      const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
      setTab(t ?? null);
      let h: string | null = null;
      try {
        if (t?.url && /^https?:/.test(t.url)) h = normalizeHost(t.url);
      } catch {
        h = null;
      }
      setHost(h);
      setMatches(h ? await vault.lookup(t!.url!) : []);
    });
  }, []);

  useEffect(() => {
    if (!q || all) return;
    run(async () => {
      const out: Hit[] = [];
      for (const c of await vault.containers()) {
        if (c.kind === "org") continue;
        for (const item of await vault.items(c.id)) out.push({ container: c, item });
      }
      setAll(out);
    });
  }, [q]);

  const s = q.toLowerCase();
  const results = q && all
    ? all.filter(({ item, container }) => [item.data.name, item.data.username, container.meta.name, ...(item.data.urls ?? [])].some((v) => v?.toLowerCase().includes(s))).slice(0, 30)
    : null;
  const list = results ?? matches ?? [];

  const fill = (hit: Hit) => run(async () => {
    if (!tab?.id || !host) throw new Error("Nessuna pagina da compilare");
    await fillTab(tab.id, host, hit.item.data.username, hit.item.data.password);
    vault.report("item.fill", hit.container.id, hit.item.id);
    window.close();
  });

  return (
    <>
      <div class="pop-head">
        <img src="icons/128.png" alt="" width="26" height="26" />
        <input class="input grow" type="search" aria-label="Cerca in tutti i clienti" placeholder="Cerca in tutti i clienti…" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
        <button class="btn icon-btn sm" aria-label="Apri l'applicazione" title="Apri l'applicazione" onClick={() => openApp()}>
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></svg>
        </button>
        <button class="btn icon-btn sm" aria-label="Blocca" title="Blocca" onClick={async () => { await lock(); window.close(); }}>
          <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></svg>
        </button>
      </div>
      <div class="pop-body">
        {!q && (
          <div class="row small" style="gap:8px">
            <span style="width:8px;height:8px;border-radius:50%;background:var(--accent)" />
            <span class="muted">{host ? <><b style="color:var(--ink)">{host}</b> · {matches === null ? "ricerca…" : `${matches.length} ${matches.length === 1 ? "corrispondenza" : "corrispondenze"}`}</> : "Nessun sito aperto in questa scheda"}</span>
          </div>
        )}
        <ErrorNote error={error} />
        {list.map((hit) => {
          const d = hit.item.data;
          const isMatch = !q;
          return (
            <div class={`pop-item${isMatch ? " match" : ""}`}>
              <div>
                <div style="font-weight:500" class="ellipsis">{d.name}</div>
                <div class="small muted ellipsis">{hit.container.kind === "personal" ? "Area personale" : hit.container.meta.name}{d.username ? ` · ${d.username}` : ""}</div>
              </div>
              {d.totpUri && <OtpCode uri={d.totpUri} compact onCopy={() => vault.report("item.totp_copy", hit.container.id, hit.item.id)} />}
              <div class="row" style="gap:6px">
                {isMatch && (d.password || d.username) && <button class="btn primary sm grow" onClick={() => fill(hit)}>Compila</button>}
                {d.username && <CopyButton value={d.username} label="Copia utente" />}
                {d.password && <CopyButton value={d.password} label="Copia password" onCopied={() => vault.report("item.copy", hit.container.id, hit.item.id)} />}
              </div>
            </div>
          );
        })}
        {q && !all && <p class="muted small">Decifratura in corso…</p>}
        {q && results?.length === 0 && <p class="muted small">Nessun risultato.</p>}
        {!q && matches?.length === 0 && host && (
          <p class="muted small">Nessuna credenziale salvata per questo sito. Gli indirizzi devono corrispondere esattamente, sottodominio compreso.</p>
        )}
        <div class="row" style="margin-top:4px">
          <button class="btn sm" onClick={async () => {
            await navigator.clipboard.writeText(generatePassword({ length: 24 }));
            chrome.runtime.sendMessage({ type: "clear-clipboard", afterSeconds: 30 }).catch(() => undefined);
            toast("Password generata e copiata");
          }}>Genera e copia password</button>
        </div>
      </div>
    </>
  );
}

chrome.action.setBadgeText({ text: "" }).catch(() => undefined);
render(<ToastHost><Popup /></ToastHost>, document.getElementById("root")!);

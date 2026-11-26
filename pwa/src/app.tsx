/**
 * Scheletro UI della PWA (Opzione B del documento di scoping): setup → accesso →
 * sblocco → lista vault in SOLA LETTURA, sopra @startcredentials/client.
 *
 * A regime si punta all'Opzione A: riuso dell'intera UI Preact dell'estensione
 * dietro un layer `Platform`. Qui si dimostra solo il percorso end-to-end
 * (hosting, offline, sblocco locale, auto-lock).
 */
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Container, Item, Vault } from "@startcredentials/client";
import { ApiError, getSettings, saveSettings, session, SessionError } from "./session.js";
import { requestPersistence } from "./db.js";

type Phase =
  | { p: "loading" }
  | { p: "setup" }
  | { p: "signin"; canLocal: boolean }
  | { p: "unlock" }
  | { p: "ready" };

/** Nome mostrato di un contenitore, usato anche come chiave di ordinamento. */
const containerLabel = (c: Container) => c.meta.name || (c.kind === "personal" ? "Personale" : "Senza nome");

function App() {
  const [phase, setPhase] = useState<Phase>({ p: "loading" });
  const [offline, setOffline] = useState<boolean>(!navigator.onLine);

  useEffect(() => {
    session.onLock = () => setPhase({ p: "signin", canLocal: true });
    session.onNetChange = setOffline;
    const on = () => setOffline(false);
    const off = () => setOffline(true);
    addEventListener("online", on);
    addEventListener("offline", off);
    void decide();
    return () => { removeEventListener("online", on); removeEventListener("offline", off); };
  }, []);

  async function decide() {
    let s = await getSettings();
    // H3: servita da un backend (es. /m), il server è la stessa origine che ci ha serviti.
    // Niente campo libero (coerente con la CSP connect-src 'self'); Setup resta solo per file://.
    if (!s.serverUrl && location.protocol.startsWith("http")) s = await saveSettings({ serverUrl: location.origin });
    if (!s.serverUrl) return setPhase({ p: "setup" });
    setPhase({ p: "signin", canLocal: await session.canUnlockLocal() });
  }

  switch (phase.p) {
    case "loading":
      return null;
    case "setup":
      return <Setup onDone={() => void decide()} />;
    case "signin":
      return <SignIn canLocal={phase.canLocal} onUnlocked={() => setPhase({ p: "ready" })} onLocal={() => setPhase({ p: "unlock" })} />;
    case "unlock":
      return <UnlockLocal onUnlocked={() => setPhase({ p: "ready" })} onBack={() => void decide()} />;
    case "ready":
      return session.vault ? <Main vault={session.vault} offline={offline} /> : null;
  }
}

function Frame({ title, children }: { title: string; children: preact.ComponentChildren }) {
  return (
    <div class="card">
      <h1>{title}</h1>
      {children}
    </div>
  );
}

function ErrBox({ error }: { error: string | null }) {
  return error ? <p class="err">{error}</p> : null;
}

function Setup({ onDone }: { onDone: () => void }) {
  const [url, setUrl] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const u = new URL(url);
      if (u.protocol !== "https:" && u.hostname !== "localhost") throw new Error("Usa un indirizzo https.");
      await saveSettings({ serverUrl: u.origin });
      onDone();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="StartCredentials">
      <form onSubmit={submit}>
        <label>Indirizzo del server</label>
        <input type="url" inputMode="url" placeholder="https://credenziali.azienda.it" value={url} onInput={(e) => setUrl((e.target as HTMLInputElement).value)} required />
        <ErrBox error={err} />
        <button class="primary" disabled={busy}>Continua</button>
      </form>
    </Frame>
  );
}

function SignIn({ canLocal, onUnlocked, onLocal }: { canLocal: boolean; onUnlocked: () => void; onLocal: () => void }) {
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { void getSettings().then((s) => s.email && setEmail(s.email)); }, []);
  const submit = async (e: Event) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await session.signIn(email.trim(), pw);
      await requestPersistence();
      setPw("");
      onUnlocked();
    } catch (e2) {
      setErr(e2 instanceof ApiError ? "Email o master password non corrette." : e2 instanceof SessionError ? e2.message : (e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Accedi">
      <form onSubmit={submit}>
        <label>Email</label>
        <input type="email" inputMode="email" autoComplete="username" value={email} onInput={(e) => setEmail((e.target as HTMLInputElement).value)} required />
        <label>Master password</label>
        <input type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} required />
        <ErrBox error={err} />
        <button class="primary" disabled={busy}>{busy ? "Sblocco…" : "Accedi"}</button>
      </form>
      {canLocal && (
        <button class="link" onClick={onLocal}>Sblocca offline (dati salvati su questo telefono)</button>
      )}
    </Frame>
  );
}

function UnlockLocal({ onUnlocked, onBack }: { onUnlocked: () => void; onBack: () => void }) {
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await session.unlockLocal(pw);
      setPw("");
      onUnlocked();
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Sblocco offline">
      <p class="muted">Inserisci la master password per aprire la copia salvata su questo telefono.</p>
      <form onSubmit={submit}>
        <input type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} required autoFocus />
        <ErrBox error={err} />
        <button class="primary" disabled={busy}>{busy ? "Sblocco…" : "Sblocca"}</button>
      </form>
      <button class="link" onClick={onBack}>Torna all'accesso</button>
    </Frame>
  );
}

function Main({ vault, offline }: { vault: Vault; offline: boolean }) {
  const [containers, setContainers] = useState<Container[] | null>(null);
  const [open, setOpen] = useState<Container | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const activity = () => session.resetAutoLock();
    // H1: blocca subito quando l'app va in background (cambio app / chiusura), oltre all'auto-lock su inattività.
    const onHidden = () => { if (document.visibilityState === "hidden") session.lock(); };
    const onPageHide = () => session.lock();
    addEventListener("pointerdown", activity);
    addEventListener("keydown", activity);
    document.addEventListener("visibilitychange", onHidden);
    addEventListener("pagehide", onPageHide);
    vault.containers().then(setContainers).catch((e) => setErr((e as Error).message));
    return () => {
      removeEventListener("pointerdown", activity);
      removeEventListener("keydown", activity);
      document.removeEventListener("visibilitychange", onHidden);
      removeEventListener("pagehide", onPageHide);
    };
  }, []);

  if (open) return <ContainerView vault={vault} container={open} offline={offline} onBack={() => setOpen(null)} />;

  return (
    <div class="app">
      <header>
        <strong>StartCredentials</strong>
        <div>
          {offline && <span class="badge">offline</span>}
          <button class="link" onClick={() => session.lock()}>Blocca</button>
          <button class="link danger" onClick={() => void session.logout()}>Esci</button>
        </div>
      </header>
      {offline && <div class="note">Sola lettura: nessuna rete. Le modifiche richiedono la connessione.</div>}
      <ErrBox error={err} />
      {!containers ? (
        <p class="muted">Decifratura…</p>
      ) : (
        <ul class="list">
          {[...containers].sort((a, b) => containerLabel(a).localeCompare(containerLabel(b), "it", { sensitivity: "base" })).map((c) => (
            <li key={c.id} onClick={() => setOpen(c)}>
              <span class="dot" style={{ background: c.meta.color ?? "#888" }} />
              <span class="name">{containerLabel(c)}</span>
              <span class="count">{c.items}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ContainerView({ vault, container, offline, onBack }: { vault: Vault; container: Container; offline: boolean; onBack: () => void }) {
  const [items, setItems] = useState<Item[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    vault.items(container.id).then(setItems).catch((e) => setErr((e as Error).message));
  }, [container.id]);
  return (
    <div class="app">
      <header>
        <button class="link" onClick={onBack}>‹ Indietro</button>
        <strong>{container.meta.name || "Personale"}</strong>
        {offline && <span class="badge">offline</span>}
      </header>
      <ErrBox error={err} />
      {!items ? (
        <p class="muted">Decifratura…</p>
      ) : (
        <ul class="list">
          {[...items].sort((a, b) => a.data.name.localeCompare(b.data.name, "it", { sensitivity: "base" })).map((it) => (
            <li key={it.id}>
              <span class="type">{it.type}</span>
              <span class="name">{it.data.name || "—"}</span>
              <span class="sub">{it.data.username ?? ""}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const root = document.getElementById("root");
if (root) render(<App />, root);

// Registra il service worker (solo app-shell; non intercetta /api).
if ("serviceWorker" in navigator) {
  addEventListener("load", () => void navigator.serviceWorker.register("sw.js", { scope: "./" }).catch(() => undefined));
}

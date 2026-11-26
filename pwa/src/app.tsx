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
import { effectiveTotpUri } from "@startcredentials/client";
import { generateTotp, parseOtpauthUri } from "@startcredentials/crypto";
import { ApiError, getSettings, saveSettings, session, SessionError } from "./session.js";
import { requestPersistence } from "./db.js";

type Phase =
  | { p: "loading" }
  | { p: "setup" }
  | { p: "signin"; canLocal: boolean }
  | { p: "mfa" }
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
      return <SignIn canLocal={phase.canLocal} onUnlocked={() => setPhase({ p: "ready" })} onMfa={() => setPhase({ p: "mfa" })} onLocal={() => setPhase({ p: "unlock" })} />;
    case "mfa":
      return <Mfa onUnlocked={() => setPhase({ p: "ready" })} onCancel={() => { session.cancelMfa(); void decide(); }} />;
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

function SignIn({ canLocal, onUnlocked, onMfa, onLocal }: { canLocal: boolean; onUnlocked: () => void; onMfa: () => void; onLocal: () => void }) {
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
      const r = await session.signIn(email.trim(), pw);
      setPw(""); // la password non serve più qui: per l'MFA è tenuta in RAM dalla sessione
      if (r === "mfa") return onMfa();
      await requestPersistence();
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

function Mfa({ onUnlocked, onCancel }: { onUnlocked: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await session.completeMfa(code, trust);
      setCode("");
      await requestPersistence();
      onUnlocked();
    } catch (e2) {
      setErr(e2 instanceof ApiError ? "Codice non valido o scaduto." : e2 instanceof SessionError ? e2.message : (e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Codice di verifica">
      <p class="muted">Inserisci il codice a 6 cifre della tua app di autenticazione. Senza il telefono, usa un codice di riserva.</p>
      <form onSubmit={submit}>
        <input
          inputMode="numeric" autoComplete="one-time-code" autoFocus required
          pattern="[0-9]{6}|[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}" placeholder="123456"
          style="text-align:center;letter-spacing:.3em;font-size:1.2rem"
          value={code} onInput={(e) => setCode((e.target as HTMLInputElement).value)}
        />
        <label class="check">
          <input type="checkbox" checked={trust} onChange={(e) => setTrust((e.target as HTMLInputElement).checked)} />
          <span>Fidati di questo dispositivo: non chiederà più il codice (solo la master password).</span>
        </label>
        <ErrBox error={err} />
        <button class="primary" disabled={busy}>{busy ? "Verifica…" : "Verifica"}</button>
      </form>
      <button class="link" onClick={onCancel}>Annulla</button>
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
  const [open, setOpen] = useState<Item | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    vault.items(container.id).then(setItems).catch((e) => setErr((e as Error).message));
  }, [container.id]);

  if (open) return <ItemDetail item={open} offline={offline} onBack={() => setOpen(null)} />;

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
            <li key={it.id} onClick={() => setOpen(it)}>
              <span class="type">{it.type}</span>
              <span class="name">{it.data.name || "—"}</span>
              <span class="sub">{it.data.username ?? ""}</span>
              <span class="chev">›</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Pulsante "copia" con conferma; usa la clipboard solo su gesto dell'utente. */
function CopyBtn({ value, label = "Copia" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch { /* clipboard non disponibile (contesto non sicuro o permesso negato) */ }
  };
  return <button type="button" class="chip" onClick={copy}>{done ? "Copiato ✓" : label}</button>;
}

function Field({ label, value, mono, children }: { label: string; value?: string; mono?: boolean; children?: preact.ComponentChildren }) {
  return (
    <div class="field">
      {label && <div class="field-label">{label}</div>}
      <div class="field-row">
        {value !== undefined && <span class={mono ? "field-val mono" : "field-val"}>{value}</span>}
        {children}
      </div>
    </div>
  );
}

/** Campo segreto: nascosto di default, si rivela su richiesta e si può copiare. */
function SecretField({ label, value }: { label: string; value: string }) {
  const [show, setShow] = useState(false);
  return (
    <div class="field">
      <div class="field-label">{label}</div>
      <div class="field-row">
        <span class="field-val mono secret">{show ? value : "•".repeat(Math.min(14, Math.max(8, value.length)))}</span>
        <button type="button" class="chip" onClick={() => setShow((v) => !v)}>{show ? "Nascondi" : "Mostra"}</button>
        <CopyBtn value={value} />
      </div>
    </div>
  );
}

/** Codice OTP (2FA) calcolato in locale, aggiornato ogni secondo. */
function TotpField({ uri }: { uri: string }) {
  const [state, setState] = useState<{ code: string; secondsLeft: number } | null>(null);
  const [errored, setErrored] = useState(false);
  useEffect(() => {
    let alive = true;
    let params: ReturnType<typeof parseOtpauthUri>;
    try { params = parseOtpauthUri(uri); } catch { setErrored(true); return; }
    const tick = async () => {
      try { const r = await generateTotp(params); if (alive) setState(r); }
      catch { if (alive) setErrored(true); }
    };
    void tick();
    const id = setInterval(() => void tick(), 1000);
    return () => { alive = false; clearInterval(id); };
  }, [uri]);
  if (errored) return null;
  const pretty = state && state.code.length === 6 ? `${state.code.slice(0, 3)} ${state.code.slice(3)}` : state?.code ?? "…";
  return (
    <div class="field">
      <div class="field-label">Codice OTP (2FA)</div>
      <div class="field-row">
        <span class="field-val mono totp">{pretty}</span>
        {state && <span class="totp-left">{state.secondsLeft}s</span>}
        {state && <CopyBtn value={state.code} />}
      </div>
    </div>
  );
}

/** Dettaglio di un elemento in sola lettura: rivela/copia password, OTP, campi. */
function ItemDetail({ item, offline, onBack }: { item: Item; offline: boolean; onBack: () => void }) {
  const d = item.data;
  const totpUri = effectiveTotpUri(d);
  return (
    <div class="app">
      <header>
        <button class="link" onClick={onBack}>‹ Indietro</button>
        <strong>{d.name || "—"}</strong>
        {offline && <span class="badge">offline</span>}
      </header>
      <div class="detail">
        {d.username && (
          <Field label="Nome utente" value={d.username} mono><CopyBtn value={d.username} /></Field>
        )}
        {d.password && <SecretField label="Password" value={d.password} />}
        {totpUri && <TotpField uri={totpUri} />}
        {(d.urls ?? []).filter(Boolean).map((u, i) => (
          <Field key={`u${i}`} label={i === 0 ? "Indirizzo" : ""}>
            <a class="field-val link-a" href={u} target="_blank" rel="noopener noreferrer">{u}</a>
            <CopyBtn value={u} />
          </Field>
        ))}
        {(d.fields ?? []).filter((f) => f.value).map((f, i) => (
          f.secret
            ? <SecretField key={`f${i}`} label={f.label || "Campo"} value={f.value} />
            : <Field key={`f${i}`} label={f.label || "Campo"} value={f.value}><CopyBtn value={f.value} /></Field>
        ))}
        {d.notes && (
          <Field label="Note"><span class="field-val notes">{d.notes}</span></Field>
        )}
        {!d.password && !totpUri && !d.username && !(d.notes) && !(d.fields?.length) && (
          <p class="muted">Nessun dettaglio da mostrare.</p>
        )}
      </div>
    </div>
  );
}

const root = document.getElementById("root");
if (root) render(<App />, root);

// Registra il service worker (solo app-shell; non intercetta /api).
if ("serviceWorker" in navigator) {
  addEventListener("load", () => void navigator.serviceWorker.register("sw.js", { scope: "./" }).catch(() => undefined));
}

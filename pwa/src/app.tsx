/**
 * UI della PWA (Opzione B del documento di scoping): setup → accesso → MFA →
 * sblocco → lista vault e dettaglio elemento in SOLA LETTURA, sopra
 * @startcredentials/client. Stile allineato all'app/estensione (stessi token).
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

function Brand() {
  return (
    <div class="brand">
      <img class="brand-logo" src="icon.svg" alt="" width="34" height="34" />
      <span class="brand-name">StartCredentials</span>
    </div>
  );
}

/** Cornice delle schermate di accesso (accesso/MFA/sblocco/setup). */
function Frame({ title, children }: { title: string; children: preact.ComponentChildren }) {
  return (
    <div class="auth-wrap">
      <div class="auth stack-lg">
        <Brand />
        <div class="card pad stack">
          <h1>{title}</h1>
          {children}
        </div>
      </div>
    </div>
  );
}

function ErrBox({ error }: { error: string | null }) {
  return error ? <div class="notice error">{error}</div> : null;
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
      <form onSubmit={submit} class="stack">
        <label class="field">Indirizzo del server
          <input class="input" type="url" inputMode="url" placeholder="https://credenziali.azienda.it" value={url} onInput={(e) => setUrl((e.target as HTMLInputElement).value)} required />
        </label>
        <ErrBox error={err} />
        <button class="btn primary" disabled={busy}>Continua</button>
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
      <form onSubmit={submit} class="stack">
        <label class="field">Email
          <input class="input" type="email" inputMode="email" autoComplete="username" value={email} onInput={(e) => setEmail((e.target as HTMLInputElement).value)} required />
        </label>
        <label class="field">Master password
          <input class="input" type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} required />
        </label>
        <ErrBox error={err} />
        <button class="btn primary" disabled={busy}>{busy ? "Sblocco…" : "Accedi"}</button>
      </form>
      {canLocal && (
        <button class="btn ghost sm" onClick={onLocal}>Sblocca offline (dati salvati su questo telefono)</button>
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
      <p class="muted small">Inserisci il codice a 6 cifre della tua app di autenticazione. Senza il telefono, usa un codice di riserva.</p>
      <form onSubmit={submit} class="stack">
        <input
          class="input mono" inputMode="numeric" autoComplete="one-time-code" autoFocus required
          pattern="[0-9]{6}|[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}" placeholder="123456"
          style="text-align:center;letter-spacing:.3em;font-size:20px"
          value={code} onInput={(e) => setCode((e.target as HTMLInputElement).value)}
        />
        <label class="check">
          <input type="checkbox" checked={trust} onChange={(e) => setTrust((e.target as HTMLInputElement).checked)} />
          <span>Fidati di questo dispositivo: non chiederà più il codice (solo la master password).</span>
        </label>
        <ErrBox error={err} />
        <button class="btn primary" disabled={busy}>{busy ? "Verifica…" : "Verifica"}</button>
      </form>
      <button class="btn ghost sm" onClick={onCancel}>Annulla</button>
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
      <p class="muted small">Inserisci la master password per aprire la copia salvata su questo telefono.</p>
      <form onSubmit={submit} class="stack">
        <input class="input" type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} required autoFocus />
        <ErrBox error={err} />
        <button class="btn primary" disabled={busy}>{busy ? "Sblocco…" : "Sblocca"}</button>
      </form>
      <button class="btn ghost sm" onClick={onBack}>Torna all'accesso</button>
    </Frame>
  );
}

/** Secondi dopo i quali gli appunti vengono svuotati (come l'estensione). */
const CLIPBOARD_CLEAR_SECONDS = 30;

/** Pulsante "copia" con conferma; usa la clipboard solo su gesto dell'utente. */
function CopyBtn({ value, label = "Copia" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
      // Auto-pulizia dopo N secondi, come l'estensione: svuota SOLO se gli appunti
      // contengono ancora il valore copiato (per non cancellare altro). Best-effort:
      // su mobile readText può non essere permesso senza gesto → in tal caso si lascia stare.
      setTimeout(async () => {
        try {
          const cur = await navigator.clipboard.readText();
          if (cur === value) await navigator.clipboard.writeText("");
        } catch { /* readText non permesso o pagina non a fuoco: niente auto-pulizia */ }
      }, CLIPBOARD_CLEAR_SECONDS * 1000);
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
  const low = !!state && state.secondsLeft <= 5;
  return (
    <div class="field">
      <div class="field-label">Codice OTP (2FA)</div>
      <div class="otp">
        <span class={low ? "otp-code low" : "otp-code"}>{pretty}</span>
        {state && <span class="otp-left">{state.secondsLeft}s</span>}
        {state && <CopyBtn value={state.code} />}
      </div>
    </div>
  );
}

/** Dettaglio di un elemento in sola lettura: rivela/copia password, OTP, campi. */
function ItemDetail({ item, offline, onBack }: { item: Item; offline: boolean; onBack: () => void }) {
  const d = item.data;
  const totpUri = effectiveTotpUri(d);
  const empty = !d.password && !totpUri && !d.username && !d.notes && !(d.fields?.length) && !(d.urls?.length);
  return (
    <div class="screen">
      <header class="topbar">
        <button class="back" onClick={onBack}>‹ Indietro</button>
        <span class="title ellipsis">{d.name || "—"}</span>
        {offline ? <span class="badge warn">offline</span> : <span />}
      </header>
      <div class="content">
        <div class="card pad">
          <div class="detail">
            {d.username && (
              <Field label="Nome utente" value={d.username} mono><CopyBtn value={d.username} /></Field>
            )}
            {d.password && <SecretField label="Password" value={d.password} />}
            {totpUri && <TotpField uri={totpUri} />}
            {(d.urls ?? []).filter(Boolean).map((u, i) => (
              <Field key={`u${i}`} label={i === 0 ? "Indirizzo" : ""}>
                <a class="site-link" href={u} target="_blank" rel="noopener noreferrer">{u}</a>
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
            {empty && <p class="muted">Nessun dettaglio da mostrare.</p>}
          </div>
        </div>
      </div>
    </div>
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
    <div class="screen">
      <header class="topbar">
        <Brand />
        <div class="row">
          {offline && <span class="badge warn">offline</span>}
          <button class="btn ghost sm" onClick={() => session.lock()}>Blocca</button>
          <button class="btn ghost sm danger" onClick={() => void session.logout()}>Esci</button>
        </div>
      </header>
      <div class="content">
        {offline && <div class="notice info">Sola lettura: nessuna rete. Le modifiche richiedono la connessione.</div>}
        <ErrBox error={err} />
        {!containers ? (
          <p class="muted">Decifratura…</p>
        ) : (
          <div class="card list">
            {[...containers].sort((a, b) => containerLabel(a).localeCompare(containerLabel(b), "it", { sensitivity: "base" })).map((c) => (
              <button key={c.id} class="item-row" onClick={() => setOpen(c)}>
                <span class="dot" style={{ background: c.meta.color ?? "var(--muted)" }} />
                <span class="grow ellipsis name">{containerLabel(c)}</span>
                <span class="count">{c.items}</span>
                <span class="chev">›</span>
              </button>
            ))}
          </div>
        )}
      </div>
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
    <div class="screen">
      <header class="topbar">
        <button class="back" onClick={onBack}>‹ Indietro</button>
        <span class="title ellipsis">{container.meta.name || "Personale"}</span>
        {offline ? <span class="badge warn">offline</span> : <span />}
      </header>
      <div class="content">
        <ErrBox error={err} />
        {!items ? (
          <p class="muted">Decifratura…</p>
        ) : items.length === 0 ? (
          <p class="empty">Nessun elemento.</p>
        ) : (
          <div class="card list">
            {[...items].sort((a, b) => a.data.name.localeCompare(b.data.name, "it", { sensitivity: "base" })).map((it) => (
              <button key={it.id} class="item-row" onClick={() => setOpen(it)}>
                <span class="kind">{it.type.slice(0, 4)}</span>
                <span class="grow" style="min-width:0">
                  <div class="name ellipsis">{it.data.name || "—"}</div>
                  {it.data.username && <div class="sub ellipsis">{it.data.username}</div>}
                </span>
                <span class="chev">›</span>
              </button>
            ))}
          </div>
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

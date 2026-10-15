import { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import {
  Api, completeRecovery, enableMfa, login, register, serverStatus, setupMfa, Vault, verifyMfa,
} from "@startcredentials/client";
import { api, ensureServerPermission, getSettings, saveSettings, saveToken, signOut, storeVault } from "../shared";
import { CopyButton, ErrorNote, Meter, Qr, strength, useAction, useLoad } from "./kit";

export function AuthFrame({ title, intro, children }: { title: string; intro?: ComponentChildren; children: ComponentChildren }) {
  return (
    <div class="auth-wrap">
      <div class="auth stack-lg">
        <div class="brand"><img src="icons/128.png" alt="" />StartCredentials</div>
        <div class="card pad stack-lg">
          <div class="stack" style="gap:6px">
            <h1 style="font-size:22px">{title}</h1>
            {intro && <p class="muted">{intro}</p>}
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}

export type Pending = { kind: "invite"; token: string } | { kind: "recover"; token: string } | null;

/** Riconosce un collegamento di invito/recupero o un indirizzo del server. */
export function parseLink(input: string): { serverUrl: string; pending: Pending } {
  const url = new URL(input.trim().includes("://") ? input.trim() : `https://${input.trim()}`);
  const hash = new URLSearchParams(url.hash.replace(/^#/, ""));
  const invite = hash.get("invite");
  const recover = hash.get("recover");
  return {
    serverUrl: url.origin,
    pending: invite ? { kind: "invite", token: invite } : recover ? { kind: "recover", token: recover } : null,
  };
}

export function Setup({ onDone }: { onDone: (p: Pending) => void }) {
  const [value, setValue] = useState("");
  const { busy, error, setError, run } = useAction();
  const submit = (e: Event) => {
    e.preventDefault();
    run(async () => {
      let parsed;
      try {
        parsed = parseLink(value);
      } catch {
        setError("Indirizzo non valido.");
        return;
      }
      if (!parsed.serverUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(parsed.serverUrl)) {
        setError("Il server deve usare HTTPS.");
        return;
      }
      if (!(await ensureServerPermission(parsed.serverUrl))) {
        setError("Serve il permesso di collegarsi al server per continuare.");
        return;
      }
      const v = await new Api({ baseUrl: parsed.serverUrl }).get<{ api: number }>("/version").catch(() => null);
      if (v?.api !== 1) {
        setError("A questo indirizzo non risponde un server StartCredentials.");
        return;
      }
      await saveSettings({ serverUrl: parsed.serverUrl });
      onDone(parsed.pending);
    });
  };
  return (
    <AuthFrame title="Collega il server" intro="Incolla il collegamento di invito che hai ricevuto, oppure l'indirizzo del server StartCredentials della tua azienda.">
      <form class="stack" onSubmit={submit}>
        <label class="field">Collegamento di invito o indirizzo
          <input class="input" autoFocus required value={value} onInput={(e) => setValue(e.currentTarget.value)} placeholder="https://credenziali.azienda.it/#invite=…" />
        </label>
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy}>{busy ? "Verifica in corso…" : "Continua"}</button>
      </form>
    </AuthFrame>
  );
}

function MasterPasswordFields({ pw, setPw, pw2, setPw2 }: { pw: string; setPw: (v: string) => void; pw2: string; setPw2: (v: string) => void }) {
  return (
    <>
      <label class="field">Master password
        <input class="input" type="password" autoComplete="new-password" required minLength={12} value={pw} onInput={(e) => setPw(e.currentTarget.value)} />
      </label>
      <Meter value={pw} />
      <label class="field">Ripeti la master password
        <input class="input" type="password" autoComplete="new-password" required value={pw2} onInput={(e) => setPw2(e.currentTarget.value)} />
      </label>
      <div class="notice warn">Nessuno può recuperarla al posto tuo, nemmeno l'amministratore del server: usa una frase lunga che ricordi facilmente.</div>
    </>
  );
}

/** Il codice può arrivare con virgolette, spazi o un punto finale copiati per errore. */
export function cleanToken(t: string): string {
  return t.trim().replace(/^["'“”‘’\s]+|["'“”‘’.,;:\s]+$/g, "");
}

function checkPw(pw: string, pw2: string): string | null {
  if ([...pw].length < 12) return "La master password deve avere almeno 12 caratteri.";
  if (pw !== pw2) return "Le due password non coincidono.";
  if (strength(pw).score < 0.45) return "Password troppo debole: allungala o aggiungi parole.";
  return null;
}

/** Registrazione da invito, oppure bootstrap del primo amministratore. */
export function Register({ token, bootstrap, onDone }: { token?: string; bootstrap?: boolean; onDone: (password: string) => void }) {
  const [tok, setTok] = useState(token ?? "");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const { busy, error, setError, run } = useAction();
  const submit = (e: Event) => {
    e.preventDefault();
    const bad = checkPw(pw, pw2);
    if (bad) return setError(bad);
    run(async () => {
      const a = await api();
      const r = await register(a, { token: cleanToken(tok), password: pw, email: bootstrap ? email : undefined, displayName: bootstrap ? name : undefined });
      await saveToken(r.token);
      if (bootstrap) await saveSettings({ email });
      onDone(pw);
    });
  };
  return (
    <AuthFrame
      title={bootstrap ? "Crea l'amministratore" : "Attiva il tuo account"}
      intro={bootstrap ? "Primo accesso al server: il codice di attivazione si trova nel pannello di NethServer, nella pagina del modulo StartCredentials." : "Scegli la master password: cifra le tue chiavi su questo dispositivo e non viene mai inviata al server."}
    >
      <form class="stack" onSubmit={submit}>
        {bootstrap && (
          <>
            <label class="field">Codice di attivazione
              <input class="input mono" required value={tok} onInput={(e) => setTok(e.currentTarget.value)} />
            </label>
            <label class="field">Nome e cognome
              <input class="input" required value={name} onInput={(e) => setName(e.currentTarget.value)} />
            </label>
            <label class="field">Email
              <input class="input" type="email" required value={email} onInput={(e) => setEmail(e.currentTarget.value)} />
            </label>
          </>
        )}
        <MasterPasswordFields pw={pw} setPw={setPw} pw2={pw2} setPw2={setPw2} />
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy}>{busy ? "Creazione delle chiavi…" : "Crea account"}</button>
      </form>
    </AuthFrame>
  );
}

export function Login({ onDone, onSetup }: { onDone: (password: string, state: string) => void; onSetup: () => void }) {
  const settings = useLoad(getSettings, []);
  const [email, setEmail] = useState<string | null>(null);
  const [pw, setPw] = useState("");
  const { busy, error, run } = useAction();
  const status = useLoad(async () => serverStatus(await api()), []);
  if (status.data && !status.data.bootstrapped) return <Register bootstrap onDone={(p) => onDone(p, "mfa_setup")} />;
  const em = email ?? settings.data?.email ?? "";
  const submit = (e: Event) => {
    e.preventDefault();
    run(async () => {
      const a = await api();
      const r = await login(a, em, pw);
      await saveToken(r.token);
      await saveSettings({ email: em });
      onDone(pw, r.state);
    });
  };
  return (
    <AuthFrame title="Accedi" intro={settings.data?.serverUrl ? <>Server <span class="mono">{new URL(settings.data.serverUrl).host}</span></> : undefined}>
      <form class="stack" onSubmit={submit}>
        <label class="field">Email
          <input class="input" type="email" autoComplete="username" required value={em} onInput={(e) => setEmail(e.currentTarget.value)} />
        </label>
        <label class="field">Master password
          <input class="input" type="password" autoComplete="current-password" autoFocus={!!em} required value={pw} onInput={(e) => setPw(e.currentTarget.value)} />
        </label>
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy}>{busy ? "Accesso…" : "Accedi"}</button>
        <div class="row between small">
          <button type="button" class="btn ghost sm" onClick={onSetup}>Ho un invito o cambio server</button>
        </div>
      </form>
    </AuthFrame>
  );
}

export function MfaSetup({ onDone }: { onDone: () => void }) {
  const setup = useLoad(async () => setupMfa(await api()), []);
  const [code, setCode] = useState("");
  const [backup, setBackup] = useState<string[] | null>(null);
  const { busy, error, run } = useAction();
  if (backup) {
    return (
      <AuthFrame title="Salva i codici di riserva" intro="Se perdi il telefono, ognuno di questi codici sostituisce una volta il codice dell'app. Stampali o salvali fuori da StartCredentials: non verranno mostrati di nuovo.">
        <BackupCodes codes={backup} />
        <button class="btn primary" onClick={onDone}>Ho salvato i codici</button>
      </AuthFrame>
    );
  }
  return (
    <AuthFrame title="Proteggi l'accesso con un secondo fattore" intro="Inquadra il codice con un'app di autenticazione (Microsoft Authenticator, Google Authenticator, 2FAS) e inserisci il codice a 6 cifre.">
      <ErrorNote error={setup.error} />
      {setup.data && (
        <div class="row" style="align-items:flex-start;gap:18px">
          <Qr text={setup.data.otpauthUri} />
          <div class="stack grow" style="min-width:180px">
            <span class="small muted">Oppure inserisci a mano questa chiave</span>
            <span class="mono" style="word-break:break-all">{setup.data.secret.match(/.{1,4}/g)!.join(" ")}</span>
          </div>
        </div>
      )}
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => setBackup(await enableMfa(await api(), code.trim()))); }}>
        <label class="field">Codice a 6 cifre
          <input class="input mono" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required value={code} onInput={(e) => setCode(e.currentTarget.value)} />
        </label>
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy || !setup.data}>Attiva</button>
      </form>
    </AuthFrame>
  );
}

export function BackupCodes({ codes }: { codes: string[] }) {
  return (
    <div class="stack">
      <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px">
        {codes.map((c) => <div class="share-box" style="text-align:center;font-size:15px">{c}</div>)}
      </div>
      <div class="row">
        <CopyButton value={codes.join("\n")} label="Copia tutti" />
        <button type="button" class="btn sm" onClick={() => window.print()}>Stampa</button>
      </div>
    </div>
  );
}

export function MfaVerify({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const { busy, error, run } = useAction();
  return (
    <AuthFrame title="Codice di verifica" intro="Inserisci il codice a 6 cifre generato dalla tua app di autenticazione. Se non hai il telefono, usa uno dei codici di riserva.">
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await verifyMfa(await api(), code.trim()); onDone(); }); }}>
        <input class="input mono" aria-label="Codice a 6 cifre" style="font-size:22px;letter-spacing:6px;text-align:center" autoComplete="one-time-code" autoFocus pattern="[0-9]{6}|[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}" required value={code} onInput={(e) => setCode(e.currentTarget.value)} />
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy}>Verifica</button>
        <button type="button" class="btn ghost sm" onClick={onCancel}>Esci</button>
      </form>
    </AuthFrame>
  );
}

/** Sblocco: la master password deriva in locale la chiave che apre le tue chiavi private. */
export async function unlockWith(password: string): Promise<Vault> {
  const settings = await getSettings();
  const v = await Vault.unlock(await api(), password, { pinnedOrgSignPublic: settings.pinnedOrgSignPublic });
  await storeVault(v);
  await v.ensureRecoveryCopy().catch(() => undefined);
  return v;
}

export function Unlock({ onDone }: { onDone: (v: Vault) => void }) {
  const [pw, setPw] = useState("");
  const settings = useLoad(getSettings, []);
  const { busy, error, run } = useAction();
  return (
    <AuthFrame title="Cassaforte bloccata" intro={settings.data?.email ? <>Inserisci la master password di <b>{settings.data.email}</b>.</> : "Inserisci la master password."}>
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => onDone(await unlockWith(pw))); }}>
        <input class="input" type="password" aria-label="Master password" autoComplete="current-password" autoFocus required value={pw} onInput={(e) => setPw(e.currentTarget.value)} />
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy}>{busy ? "Sblocco…" : "Sblocca"}</button>
        <button type="button" class="btn ghost sm" onClick={async () => { await signOut(); location.reload(); }}>Esci dall'account</button>
      </form>
    </AuthFrame>
  );
}

export function Recover({ token, onDone }: { token: string; onDone: () => void }) {
  const [code, setCode] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [ok, setOk] = useState(false);
  const { busy, error, setError, run } = useAction();
  if (ok) {
    return (
      <AuthFrame title="Account recuperato" intro="La nuova master password è attiva. Accedi con email, nuova password e codice di verifica.">
        <button class="btn primary" onClick={onDone}>Vai all'accesso</button>
      </AuthFrame>
    );
  }
  return (
    <AuthFrame title="Recupera l'account" intro="Inserisci il codice di recupero che l'amministratore ti ha comunicato a voce o per un canale diverso dall'email, poi scegli una nuova master password.">
      <form class="stack" onSubmit={(e) => {
        e.preventDefault();
        const bad = checkPw(pw, pw2);
        if (bad) return setError(bad);
        run(async () => { await completeRecovery(await api(), { token, code, newPassword: pw }); setOk(true); });
      }}>
        <label class="field">Codice di recupero
          <input class="input mono" required value={code} onInput={(e) => setCode(e.currentTarget.value)} placeholder="XXXX-XXXX-…" />
        </label>
        <MasterPasswordFields pw={pw} setPw={setPw} pw2={pw2} setPw2={setPw2} />
        <ErrorNote error={error} />
        <button class="btn primary" disabled={busy}>{busy ? "Recupero…" : "Imposta la nuova password"}</button>
      </form>
    </AuthFrame>
  );
}

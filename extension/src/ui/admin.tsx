import { useState } from "preact/hooks";
import {
  Container, generatePassword, import1Password, importBitwarden, importCsv, importInto, importKeePass, ImportResult, Vault,
} from "@startcredentials/client";
import { getSettings, initials, lock, saveSettings, signOut } from "../shared";
import { CopyButton, Dialog, ErrorNote, Meter, useAction, useLoad, useToast } from "./kit";
import { go } from "./vault";

type AdminUser = Awaited<ReturnType<Vault["users"]>>[number];

// ------------------------------------------------------------------ utenti

export function Users({ vault }: { vault: Vault }) {
  const users = useLoad(() => vault.users(), []);
  const [inviting, setInviting] = useState(false);
  const [certify, setCertify] = useState<AdminUser | null>(null);
  const [recover, setRecover] = useState<AdminUser | null>(null);
  const { error, run } = useAction();
  const toast = useToast();
  const orgReady = !!vault.me.org;
  return (
    <>
      <div class="row between">
        <div class="stack" style="gap:4px">
          <h1>Utenti</h1>
          <p class="muted">Un nuovo utente può ricevere condivisioni solo dopo che un amministratore ha certificato la sua chiave.</p>
        </div>
        <button class="btn primary" onClick={() => setInviting(true)}>Invita utente</button>
      </div>
      {!orgReady && <div class="notice warn">Prima di certificare le chiavi devi <a href="#/admin/org">inizializzare l'organizzazione</a>.</div>}
      <ErrorNote error={users.error ?? error} />
      <div class="card table-wrap">
        <table>
          <thead><tr><th>Nome</th><th>Ruolo</th><th>Stato</th><th>Chiave</th><th>Recupero</th><th></th></tr></thead>
          <tbody>
            {users.data?.map((u) => (
              <tr>
                <td>
                  <div class="row" style="flex-wrap:nowrap">
                    <div class="avatar">{initials(u.displayName)}</div>
                    <div><div style="font-weight:500">{u.displayName}</div><div class="small muted">{u.email}</div></div>
                  </div>
                </td>
                <td>{u.role === "admin" ? "Amministratore" : "Utente"}</td>
                <td>
                  {u.status === "invited" && <span class="badge warn">Invitato</span>}
                  {u.status === "active" && <span class="badge">Attivo{u.mfaEnabled ? "" : " · senza MFA"}</span>}
                  {u.status === "suspended" && <span class="badge warn">Sospeso</span>}
                </td>
                <td>{u.status === "invited" ? "—" : u.certified ? <span class="badge accent">Certificata</span> : <span class="badge warn">Da verificare</span>}</td>
                <td class="small">{u.recoveryPending ? "In corso" : u.hasRecovery ? "Disponibile" : "—"}</td>
                <td>
                  <div class="row" style="justify-content:flex-end;flex-wrap:nowrap">
                    {u.status === "active" && !u.certified && orgReady && <button class="btn sm primary" onClick={() => setCertify(u)}>Certifica</button>}
                    {u.id !== vault.me.id && u.status === "active" && u.hasRecovery && <button class="btn sm" onClick={() => setRecover(u)}>Recupera</button>}
                    {u.id !== vault.me.id && u.status !== "invited" && (
                      <button class="btn sm" onClick={() => run(async () => {
                        await vault.setUser(u.id, { status: u.status === "active" ? "suspended" : "active" });
                        users.reload();
                        toast(u.status === "active" ? "Utente sospeso: rimuovilo anche dai clienti condivisi" : "Utente riattivato");
                      })}>{u.status === "active" ? "Sospendi" : "Riattiva"}</button>
                    )}
                    {u.id !== vault.me.id && u.status === "active" && (
                      <button class="btn sm ghost" onClick={() => run(async () => {
                        if (u.role === "user") {
                          if (!u.certified) throw new Error("Certifica prima la chiave dell'utente");
                          await vault.setUser(u.id, { role: "admin" });
                          await vault.grantOrgAccess(u.id);
                        } else await vault.setUser(u.id, { role: "user" });
                        users.reload();
                      })}>{u.role === "user" ? "Rendi amministratore" : "Rendi utente"}</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {inviting && <InviteDialog vault={vault} onClose={() => { setInviting(false); users.reload(); }} />}
      {certify && <CertifyDialog vault={vault} user={certify} onClose={() => { setCertify(null); users.reload(); }} />}
      {recover && <RecoveryDialog vault={vault} user={recover} onClose={() => { setRecover(null); users.reload(); }} />}
    </>
  );
}

function InviteDialog({ vault, onClose }: { vault: Vault; onClose: () => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<"user" | "admin">("user");
  const [done, setDone] = useState<{ inviteUrl: string; emailed: boolean } | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Dialog title="Invita un utente" onClose={onClose}>
      {done ? (
        <div class="stack">
          <div class="notice ok">{done.emailed ? `Invito inviato a ${email}.` : "Invito creato. L'email non è configurata: invia tu il collegamento."}</div>
          <label class="field">Collegamento di invito (valido 72 ore)
            <div class="input-group"><input class="input mono" readOnly value={done.inviteUrl} /><CopyButton value={done.inviteUrl} /></div>
          </label>
          <p class="small muted">L'utente installa l'estensione e incolla il collegamento nella schermata iniziale.</p>
          <div class="row" style="justify-content:flex-end"><button class="btn primary" onClick={onClose}>Fatto</button></div>
        </div>
      ) : (
        <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => setDone(await vault.invite(email.trim(), name.trim(), role))); }}>
          <label class="field">Nome e cognome<input class="input" required autoFocus value={name} onInput={(e) => setName(e.currentTarget.value)} /></label>
          <label class="field">Email<input class="input" type="email" required value={email} onInput={(e) => setEmail(e.currentTarget.value)} /></label>
          <label class="field">Ruolo
            <select class="input" value={role} onChange={(e) => setRole(e.currentTarget.value as "user" | "admin")}>
              <option value="user">Utente</option><option value="admin">Amministratore</option>
            </select>
          </label>
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button type="button" class="btn" onClick={onClose}>Annulla</button>
            <button class="btn primary" disabled={busy}>Crea invito</button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function CertifyDialog({ vault, user, onClose }: { vault: Vault; user: AdminUser; onClose: () => void }) {
  const [fp, setFp] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Dialog title={`Certifica la chiave di ${user.displayName}`} onClose={onClose}>
      <p>Chiedi a {user.displayName} di aprire <b>Impostazioni</b> nell'estensione e di leggerti l'impronta della sua chiave, di persona o al telefono. Non usare email o chat: se il server fosse compromesso potrebbero essere alterate.</p>
      <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await vault.certifyUser(user.id, fp); onClose(); }); }}>
        <label class="field">Impronta comunicata dall'utente
          <input class="input mono" required autoFocus value={fp} onInput={(e) => setFp(e.currentTarget.value)} placeholder="XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX" />
        </label>
        <ErrorNote error={error} />
        <div class="row" style="justify-content:flex-end">
          <button type="button" class="btn" onClick={onClose}>Annulla</button>
          <button class="btn primary" disabled={busy}>Certifica</button>
        </div>
      </form>
    </Dialog>
  );
}

function RecoveryDialog({ vault, user, onClose }: { vault: Vault; user: AdminUser; onClose: () => void }) {
  const [shares, setShares] = useState("");
  const [res, setRes] = useState<{ recoveryUrl: string; code: string } | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Dialog title={`Recupero account di ${user.displayName}`} onClose={onClose}>
      {res ? (
        <div class="stack">
          <label class="field">Collegamento di recupero (valido 24 ore): invialo all'utente
            <div class="input-group"><input class="input mono" readOnly value={res.recoveryUrl} /><CopyButton value={res.recoveryUrl} /></div>
          </label>
          <label class="field">Codice di recupero: comunicalo a voce o per un canale diverso dal collegamento
            <div class="share-box" style="font-size:16px;letter-spacing:1px">{res.code}</div>
          </label>
          <div class="row" style="justify-content:flex-end"><button class="btn primary" onClick={onClose}>Fatto</button></div>
        </div>
      ) : (
        <form class="stack" onSubmit={(e) => { e.preventDefault(); run(async () => setRes(await vault.startRecovery(user.id, shares.split(/\s+/).filter(Boolean)))); }}>
          <p>Servono le quote di recupero stampate all'inizializzazione, almeno quante indicate nella pagina Organizzazione. Ogni custode incolla o digita la propria quota.</p>
          <label class="field">Quote di recupero (una per riga)
            <textarea class="input mono" required value={shares} onInput={(e) => setShares(e.currentTarget.value)} placeholder="SCR1-…" />
          </label>
          <ErrorNote error={error} />
          <div class="row" style="justify-content:flex-end">
            <button type="button" class="btn" onClick={onClose}>Annulla</button>
            <button class="btn primary" disabled={busy}>{busy ? "Verifica…" : "Avvia il recupero"}</button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

// ------------------------------------------------------------------ organizzazione

export function Org({ vault, onChanged }: { vault: Vault; onChanged: () => void }) {
  const info = useLoad(() => vault.api.get<{ initialized: boolean; recoveryThreshold?: number; recoveryShares?: number }>("/org"), []);
  const [shares, setShares] = useState(3);
  const [threshold, setThreshold] = useState(2);
  const [result, setResult] = useState<{ shares: string[]; fingerprint: string } | null>(null);
  const { busy, error, run } = useAction();
  if (result) {
    return (
      <div class="card pad stack-lg" style="max-width:760px">
        <h1>Stampa le quote di recupero</h1>
        <p>Consegna ogni quota a una persona diversa e conservala in un luogo sicuro, per esempio in cassaforte. Servono {threshold} quote su {result.shares.length} per recuperare un account. Non verranno mostrate di nuovo.</p>
        <div class="shares">
          {result.shares.map((s, i) => (
            <div class="stack" style="gap:4px"><span class="small muted">Quota {i + 1} di {result.shares.length}</span><div class="share-box">{s}</div></div>
          ))}
        </div>
        <div class="row">
          <button class="btn" onClick={() => window.print()}>Stampa</button>
          <button class="btn primary" onClick={() => { setResult(null); info.reload(); onChanged(); }}>Ho stampato e consegnato le quote</button>
        </div>
      </div>
    );
  }
  return (
    <>
      <div class="stack" style="gap:4px">
        <h1>Organizzazione</h1>
        <p class="muted">La chiave dell'organizzazione certifica le chiavi dei colleghi; la chiave di recupero permette di riaprire un account se qualcuno dimentica la master password.</p>
      </div>
      <ErrorNote error={info.error ?? error} />
      {info.data?.initialized ? (
        <div class="card pad stack" style="max-width:760px">
          <div class="notice ok">Organizzazione attiva.</div>
          <p>Recupero account: servono <b>{info.data.recoveryThreshold}</b> quote su <b>{info.data.recoveryShares}</b>.</p>
          <p class="small muted">Chiave di firma dell'organizzazione</p>
          <div class="share-box">{vault.me.org?.signPublic}</div>
          <p class="small muted">Questa chiave è fissata nell'estensione di ogni utente al primo accesso: se il server ne presentasse una diversa, l'estensione si rifiuterebbe di aprirsi.</p>
        </div>
      ) : info.data && (
        <div class="card pad stack" style="max-width:760px">
          <p>Va fatto una sola volta, dal primo amministratore. Verranno generate le quote di recupero da stampare.</p>
          <div class="row">
            <label class="field">Numero di quote
              <select class="input" value={shares} onChange={(e) => { const n = Number(e.currentTarget.value); setShares(n); setThreshold(Math.min(threshold, n)); }}>
                {[2, 3, 4, 5].map((n) => <option value={n}>{n}</option>)}
              </select>
            </label>
            <label class="field">Quote necessarie per un recupero
              <select class="input" value={threshold} onChange={(e) => setThreshold(Number(e.currentTarget.value))}>
                {[2, 3, 4, 5].filter((n) => n <= shares).map((n) => <option value={n}>{n}</option>)}
              </select>
            </label>
          </div>
          <button class="btn primary" style="align-self:flex-start" disabled={busy} onClick={() => run(async () => setResult(await vault.initOrg(shares, threshold)))}>Inizializza l'organizzazione</button>
        </div>
      )}
    </>
  );
}

// ------------------------------------------------------------------ registro attività

const ACTION_LABEL: Record<string, string> = {
  "auth.login": "Accesso", "auth.login_failed": "Accesso non riuscito", "auth.mfa_enabled": "MFA attivata", "auth.mfa_failed": "Codice MFA errato",
  "user.registered": "Registrazione", "user.invited": "Invito", "user.updated": "Utente modificato", "user.key_certified": "Chiave certificata",
  "user.recovery_started": "Recupero avviato", "user.recovery_completed": "Recupero completato", "org.initialized": "Organizzazione inizializzata",
  "container.created": "Cliente creato", "container.updated": "Cliente modificato", "container.deleted": "Cliente eliminato",
  "container.member_set": "Accesso concesso", "container.member_removed": "Accesso rimosso", "container.key_rotated": "Chiave ruotata",
  "container.imported": "Import", "container.export": "Export", "folder.created": "Cartella creata", "folder.deleted": "Cartella eliminata",
  "item.created": "Elemento creato", "item.updated": "Elemento modificato", "item.deleted": "Elemento nel cestino", "item.restored": "Elemento ripristinato",
  "item.reveal": "Password mostrata", "item.copy": "Password copiata", "item.fill": "Compilazione automatica", "item.totp_copy": "OTP copiato",
  "attachment.added": "Allegato aggiunto", "attachment.deleted": "Allegato eliminato",
};

export function Audit({ vault, containers }: { vault: Vault; containers: Container[] }) {
  const [containerId, setContainerId] = useState("");
  const [rows, setRows] = useState<Awaited<ReturnType<Vault["auditLog"]>>>([]);
  const [verify, setVerify] = useState<{ ok: boolean; rows: number; brokenAt?: number } | null>(null);
  const load = useLoad(async () => {
    const r = await vault.auditLog({ containerId: containerId || undefined });
    setRows(r);
    return r;
  }, [containerId]);
  const { busy, error, run } = useAction();
  const names = new Map(containers.map((c) => [c.id, c.meta.name]));
  return (
    <>
      <div class="row between">
        <div class="stack" style="gap:4px">
          <h1>Registro attività</h1>
          <p class="muted">Ogni riga è concatenata alla precedente con un hash: una modifica diretta al database rompe la catena.</p>
        </div>
        <button class="btn" disabled={busy} onClick={() => run(async () => setVerify(await vault.verifyAudit()))}>Verifica integrità</button>
      </div>
      {verify && (verify.ok
        ? <div class="notice ok">Catena integra: {verify.rows} eventi verificati.</div>
        : <div class="notice error">Catena interrotta all'evento {verify.brokenAt}: il registro è stato alterato.</div>)}
      <ErrorNote error={load.error ?? error} />
      <label class="field" style="max-width:340px">Cliente
        <select class="input" value={containerId} onChange={(e) => setContainerId(e.currentTarget.value)}>
          <option value="">Tutti gli eventi</option>
          {containers.filter((c) => c.kind === "client").map((c) => <option value={c.id}>{c.meta.name}</option>)}
        </select>
      </label>
      <div class="card table-wrap">
        <table>
          <thead><tr><th>Quando</th><th>Chi</th><th>Azione</th><th>Cliente</th><th>IP</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr>
                <td class="small" style="white-space:nowrap">{new Date(r.at).toLocaleString("it-IT")}</td>
                <td>{r.actorName ?? "—"}</td>
                <td>{ACTION_LABEL[r.action] ?? r.action}</td>
                <td class="small">{r.containerId ? names.get(r.containerId) ?? "—" : "—"}</td>
                <td class="small mono">{r.ip ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length >= 100 && (
        <button class="btn" style="align-self:center" onClick={() => run(async () => {
          const more = await vault.auditLog({ containerId: containerId || undefined, before: rows[rows.length - 1]!.id });
          setRows([...rows, ...more]);
        })}>Carica altri</button>
      )}
    </>
  );
}

// ------------------------------------------------------------------ import

const SOURCES = [
  { id: "passbolt", label: "Passbolt (KDBX o CSV)", accept: ".kdbx,.csv" },
  { id: "keepass", label: "KeePass / KeePassXC (.kdbx)", accept: ".kdbx" },
  { id: "bitwarden", label: "Bitwarden (JSON non cifrato o CSV)", accept: ".json,.csv" },
  { id: "1password", label: "1Password (.1pux)", accept: ".1pux" },
  { id: "lastpass", label: "LastPass (CSV)", accept: ".csv" },
  { id: "browser", label: "Chrome / Edge (CSV)", accept: ".csv" },
] as const;

export function Import({ vault, containers, onChanged }: { vault: Vault; containers: Container[]; onChanged: () => void }) {
  const writable = containers.filter((c) => c.permission !== "read" && c.kind !== "org");
  const [target, setTarget] = useState(writable[0]?.id ?? "");
  const [source, setSource] = useState<(typeof SOURCES)[number]["id"]>("passbolt");
  const [file, setFile] = useState<File | null>(null);
  const [kdbxPw, setKdbxPw] = useState("");
  const [preview, setPreview] = useState<ImportResult | null>(null);
  const [progress, setProgress] = useState<string | null>(null);
  const [done, setDone] = useState<number | null>(null);
  const { busy, error, run } = useAction();
  const isKdbx = file?.name.toLowerCase().endsWith(".kdbx");

  const analyse = () => run(async () => {
    if (!file) throw new Error("Scegli un file");
    const name = file.name.toLowerCase();
    let r: ImportResult;
    if (name.endsWith(".kdbx")) r = await importKeePass(await file.arrayBuffer(), kdbxPw);
    else if (name.endsWith(".1pux")) r = import1Password(new Uint8Array(await file.arrayBuffer()));
    else if (name.endsWith(".json")) r = importBitwarden(await file.text());
    else r = importCsv(await file.text(), source);
    r.source = source;
    setPreview(r);
  });

  if (done !== null) {
    return (
      <div class="card pad stack" style="max-width:640px">
        <h1>Import completato</h1>
        <p>{done} elementi cifrati e caricati. Elimina il file di export dal computer: contiene le password in chiaro.</p>
        <div class="row">
          <button class="btn primary" onClick={() => go(`/c/${target}`)}>Apri il cliente</button>
          <button class="btn" onClick={() => { setDone(null); setPreview(null); setFile(null); }}>Importa altro</button>
        </div>
      </div>
    );
  }

  return (
    <>
      <div class="stack" style="gap:4px">
        <h1>Importa</h1>
        <p class="muted">Il file viene letto e cifrato solo su questo computer: il server non lo riceve mai.</p>
      </div>
      <div class="card pad stack" style="max-width:640px">
        <label class="field">Provenienza
          <select class="input" value={source} onChange={(e) => { setSource(e.currentTarget.value as typeof source); setPreview(null); }}>
            {SOURCES.map((s) => <option value={s.id}>{s.label}</option>)}
          </select>
        </label>
        <label class="field">File di export
          <input class="input" type="file" accept={SOURCES.find((s) => s.id === source)!.accept} onChange={(e) => { setFile(e.currentTarget.files?.[0] ?? null); setPreview(null); }} />
        </label>
        {isKdbx && (
          <label class="field">Password del file KeePass
            <input class="input" type="password" value={kdbxPw} onInput={(e) => setKdbxPw(e.currentTarget.value)} />
          </label>
        )}
        <label class="field">Importa nel cliente
          <select class="input" value={target} onChange={(e) => setTarget(e.currentTarget.value)}>
            {writable.map((c) => <option value={c.id}>{c.kind === "personal" ? "Area personale" : c.meta.name}</option>)}
          </select>
        </label>
        {preview && (
          <div class="notice info">
            Trovati {preview.items.length} elementi e {preview.folders.length} cartelle
            {preview.items.filter((i) => i.data.totpUri).length ? `, di cui ${preview.items.filter((i) => i.data.totpUri).length} con OTP` : ""}.
            {preview.skipped.length > 0 && ` ${preview.skipped.length} avvisi: ${preview.skipped.slice(0, 3).map((s) => `${s.name} (${s.reason})`).join("; ")}.`}
          </div>
        )}
        <ErrorNote error={error} />
        <div class="row">
          {!preview && <button class="btn primary" disabled={busy || !file} onClick={analyse}>{busy ? "Lettura…" : "Analizza il file"}</button>}
          {preview && (
            <button class="btn primary" disabled={busy || !target} onClick={() => run(async () => {
              const n = await importInto(vault, target, preview, (d, t) => setProgress(`${d} di ${t}`));
              setProgress(null);
              onChanged();
              setDone(n);
            })}>{busy ? `Cifratura ${progress ?? ""}` : `Importa ${preview.items.length} elementi`}</button>
          )}
        </div>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ generatore

export function Generator() {
  const [len, setLen] = useState(24);
  const [opts, setOpts] = useState({ upper: true, lower: true, digits: true, symbols: true });
  const [n, setN] = useState(0);
  let value = "";
  try {
    value = generatePassword({ length: len, ...opts });
  } catch {
    value = "";
  }
  void n;
  return (
    <>
      <h1>Generatore di password</h1>
      <div class="card pad stack" style="max-width:640px">
        <div class="input-group">
          <input class="input mono" style="font-size:17px" readOnly value={value} aria-label="Password generata" />
          <button class="btn" onClick={() => setN(n + 1)}>Rigenera</button>
          <CopyButton value={value} small={false} />
        </div>
        <Meter value={value} />
        <label class="field">Lunghezza: {len} caratteri
          <input type="range" min="12" max="64" value={len} onInput={(e) => setLen(Number(e.currentTarget.value))} />
        </label>
        <div class="row">
          {([["upper", "Maiuscole"], ["lower", "Minuscole"], ["digits", "Numeri"], ["symbols", "Simboli"]] as const).map(([k, l]) => (
            <label class="check"><input type="checkbox" checked={opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.currentTarget.checked })} />{l}</label>
          ))}
        </div>
        <p class="small muted">Sono esclusi i caratteri facili da confondere, come 0 e O o 1 e l.</p>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ impostazioni

export function SettingsPage({ vault }: { vault: Vault }) {
  const s = useLoad(getSettings, []);
  const toast = useToast();
  if (!s.data) return null;
  return (
    <>
      <h1>Impostazioni</h1>
      <div class="card pad stack" style="max-width:640px">
        <h3>Impronta della tua chiave</h3>
        <p class="muted">Leggila all'amministratore quando deve certificare la tua chiave.</p>
        <div class="share-box" style="font-size:16px;letter-spacing:1px">{vault.myFingerprint}</div>
      </div>
      <div class="card pad stack" style="max-width:640px">
        <h3>Sicurezza</h3>
        <label class="field">Blocco automatico dopo
          <select class="input" value={s.data.autoLockMinutes} onChange={async (e) => { await saveSettings({ autoLockMinutes: Number(e.currentTarget.value) }); s.reload(); toast("Salvato"); }}>
            {[1, 5, 15, 30, 60, 240].map((m) => <option value={m}>{m < 60 ? `${m} minuti` : `${m / 60} ${m === 60 ? "ora" : "ore"}`} di inattività</option>)}
          </select>
        </label>
        <label class="field">Svuota gli appunti dopo
          <select class="input" value={s.data.clipboardSeconds} onChange={async (e) => { await saveSettings({ clipboardSeconds: Number(e.currentTarget.value) }); s.reload(); toast("Salvato"); }}>
            {[30, 60, 120].map((x) => <option value={x}>{x} secondi</option>)}
          </select>
        </label>
        <p class="small muted">Server: <span class="mono">{s.data.serverUrl}</span></p>
        <div class="row">
          <button class="btn" onClick={async () => { await lock(); location.reload(); }}>Blocca ora</button>
          <button class="btn danger" onClick={async () => { await signOut(); location.hash = ""; location.reload(); }}>Esci</button>
        </div>
      </div>
    </>
  );
}

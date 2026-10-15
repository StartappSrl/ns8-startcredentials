import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { ApiError, Container, ready, Vault } from "@startcredentials/client";
import { api, currentVault, getSettings, hasToken, saveToken } from "./shared";
import { AuthFrame, Login, MfaSetup, MfaVerify, parseLink, Pending, Recover, Register, Setup, Unlock, unlockWith } from "./ui/auth";
import { ErrorNote, ToastHost, useLoad } from "./ui/kit";
import { Clients, ContainerView, go, Shell, useRoute } from "./ui/vault";
import { Audit, Generator, Import, Org, SettingsPage, Users } from "./ui/admin";
import { Health, Search } from "./ui/tools";

type Phase =
  | { p: "loading" }
  | { p: "setup" }
  | { p: "register"; token: string }
  | { p: "recover"; token: string }
  | { p: "login" }
  | { p: "mfa_setup"; password?: string }
  | { p: "mfa_pending"; password?: string }
  | { p: "unlock" }
  | { p: "ready"; vault: Vault };

function pendingFromHash(): Pending {
  const h = new URLSearchParams(location.hash.replace(/^#/, ""));
  if (h.get("invite")) return { kind: "invite", token: h.get("invite")! };
  if (h.get("recover")) return { kind: "recover", token: h.get("recover")! };
  return null;
}

function App() {
  const [phase, setPhase] = useState<Phase>({ p: "loading" });
  const [fatal, setFatal] = useState<string | null>(null);

  const decide = async (password?: string) => {
    try {
      await ready();
      const settings = await getSettings();
      const pending = pendingFromHash();
      if (!settings.serverUrl) return setPhase({ p: "setup" });
      if (pending?.kind === "invite") return setPhase({ p: "register", token: pending.token });
      if (pending?.kind === "recover") return setPhase({ p: "recover", token: pending.token });
      if (!(await hasToken())) return setPhase({ p: "login" });
      let state: string;
      try {
        state = (await (await api()).get<{ state: string }>("/auth/session")).state;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {
          await saveToken(undefined);
          return setPhase({ p: "login" });
        }
        throw e;
      }
      if (state === "mfa_setup") return setPhase({ p: "mfa_setup", password });
      if (state === "mfa_pending") return setPhase({ p: "mfa_pending", password });
      const v = await currentVault();
      if (v) return setPhase({ p: "ready", vault: v });
      if (password) return setPhase({ p: "ready", vault: await unlockWith(password) });
      setPhase({ p: "unlock" });
    } catch (e) {
      setFatal((e as Error).message);
    }
  };

  useEffect(() => { void decide(); }, []);

  if (fatal) {
    return (
      <AuthFrame title="Impossibile aprire StartCredentials">
        <ErrorNote error={fatal} />
        <button class="btn primary" onClick={() => location.reload()}>Riprova</button>
      </AuthFrame>
    );
  }
  switch (phase.p) {
    case "loading": return null;
    case "setup": return <Setup onDone={(p) => { if (p) location.hash = p.kind === "invite" ? `invite=${p.token}` : `recover=${p.token}`; void decide(); }} />;
    case "register": return <Register token={phase.token} onDone={(pw) => { history.replaceState(null, "", location.pathname); void decide(pw); }} />;
    case "recover": return <Recover token={phase.token} onDone={() => { history.replaceState(null, "", location.pathname); void decide(); }} />;
    case "login": return <Login onDone={(pw) => void decide(pw)} onSetup={() => setPhase({ p: "setup" })} />;
    case "mfa_setup": return <MfaSetup onDone={() => void decide(phase.password)} />;
    case "mfa_pending": return <MfaVerify onDone={() => void decide(phase.password)} onCancel={async () => { await saveToken(undefined); setPhase({ p: "login" }); }} />;
    case "unlock": return <Unlock onDone={(v) => setPhase({ p: "ready", vault: v })} />;
    case "ready": return <Main vault={phase.vault} />;
  }
}

function Main({ vault }: { vault: Vault }) {
  const route = useRoute();
  const containers = useLoad(() => vault.containers(), []);
  const list: Container[] = containers.data ?? [];
  const personal = list.find((c) => c.kind === "personal");
  const counts = {
    clients: list.filter((c) => c.kind === "client").length,
    shared: list.filter((c) => c.kind === "client" && c.grantedBy !== vault.me.id).length,
  };

  useEffect(() => {
    if (containers.data && !personal) vault.ensurePersonal().then(containers.reload).catch(() => undefined);
  }, [containers.data]);

  // Rotazioni rimaste in sospeso (revoche interrotte, colleghi usciti): le completa il primo gestore.
  const [rotated, setRotated] = useState<string | null>(null);
  useEffect(() => {
    if (!containers.data?.some((c) => c.rotationRequired && c.permission === "manage")) return;
    vault.completePendingRotations().then((r) => {
      if (r.done.length) {
        setRotated(`Chiavi ruotate per ${r.done.length} ${r.done.length === 1 ? "cliente" : "clienti"} dopo la rimozione di un membro: ${r.done.join(", ")}.`);
        containers.reload();
      }
    }).catch(() => undefined);
  }, [containers.data]);

  let page;
  const m = route.match(/^\/c\/([0-9a-f-]{36})$/);
  if (containers.error) page = <ErrorNote error={containers.error} />;
  else if (!containers.data) page = <p class="muted">Decifratura dei clienti…</p>;
  else if (m) page = <ContainerView vault={vault} id={m[1]!} onChanged={containers.reload} />;
  else if (route === "/personale") page = personal ? <ContainerView vault={vault} id={personal.id} onChanged={containers.reload} /> : <p class="muted">Preparazione…</p>;
  else if (route === "/condivisi") page = <Clients vault={vault} containers={list} reload={containers.reload} shared />;
  else if (route === "/generatore") page = <Generator />;
  else if (route === "/cerca") page = <Search vault={vault} />;
  else if (route === "/salute") page = <Health vault={vault} />;
  else if (route === "/import") page = <Import vault={vault} containers={list} onChanged={containers.reload} />;
  else if (route === "/impostazioni") page = <SettingsPage vault={vault} />;
  else if (route === "/admin/utenti" && vault.me.role === "admin") page = <Users vault={vault} />;
  else if (route === "/admin/audit" && vault.me.role === "admin") page = <Audit vault={vault} containers={list} />;
  else if (route === "/admin/org" && vault.me.role === "admin") page = <Org vault={vault} onChanged={async () => { await vault.refreshMe(); containers.reload(); }} />;
  else page = <Clients vault={vault} containers={list} reload={containers.reload} />;

  return (
    <Shell vault={vault} route={route} counts={counts}>
      {vault.me.role === "admin" && !vault.me.org && route !== "/admin/org" && (
        <div class="notice warn">Primo passo: <a href="#/admin/org" onClick={() => go("/admin/org")}>inizializza l'organizzazione</a> per poter certificare i colleghi e abilitare il recupero degli account.</div>
      )}
      {rotated && <div class="notice info">{rotated}</div>}
      {page}
    </Shell>
  );
}

render(<ToastHost><App /></ToastHost>, document.getElementById("root")!);

export { parseLink };

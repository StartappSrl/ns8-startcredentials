import { useEffect, useState } from "react";
import { Alert, Linking, Pressable, ScrollView, Share, StyleSheet, Text, View } from "react-native";
import type { Item, ItemData, Me } from "@startcredentials/client";
import { accessCodeMessage, whatsappCodeLink, whatsappNumber } from "../ui/send";
import { useEngine } from "../engine/Engine";
import { errorText, useApp } from "../state/App";
import { Brand, Button, Card, CopyButton, Field, Notice } from "../ui/kit";
import { Header } from "./Vault";
import { color, mono } from "../theme";

type Perm = "read" | "write" | "manage";
const PERM: Record<Perm, string> = { read: "Lettura", write: "Modifica", manage: "Gestione" };
interface DirUser { id: string; displayName: string; email: string; status: string; verified: boolean }

function Choice<T extends string>({ value, options, onChange }: { value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <View style={{ flexDirection: "row", gap: 6, flexWrap: "wrap" }}>
      {options.map(([v, l]) => (
        <Button key={v} title={l} kind={value === v ? "primary" : "secondary"} onPress={() => onChange(v)} style={{ minHeight: 38, paddingHorizontal: 12 }} />
      ))}
    </View>
  );
}

// ------------------------------------------------------------------ cronologia

export function HistoryScreen({ item, where }: { item: Item; where: string }) {
  const engine = useEngine();
  const app = useApp();
  const [versions, setVersions] = useState<{ revision: number; createdAt: string; by: string; data: ItemData }[] | null>(null);
  const [shown, setShown] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { engine.call<typeof versions>("itemVersions", item.id).then(setVersions).catch((e) => setError(errorText(e))); }, [item.id]);
  return (
    <View style={{ flex: 1 }}>
      <Header title="Cronologia" subtitle={item.data.name} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
        {error && <Notice kind="error">{error}</Notice>}
        {versions?.length === 0 && <Text style={{ color: color.muted }}>Nessuna versione precedente.</Text>}
        {versions?.map((v) => (
          <Card key={v.revision}>
            <Text style={{ fontWeight: "700", color: color.ink }}>Versione {v.revision} · {new Date(v.createdAt).toLocaleString("it-IT")}</Text>
            <Text style={{ color: color.muted }}>Modificata da {v.by}</Text>
            {v.data.username ? <Text style={{ color: color.ink2 }}>Utente: {v.data.username}</Text> : null}
            {v.data.password ? <Text style={{ fontFamily: mono, color: color.ink }}>{shown === v.revision ? v.data.password : "••••••••••"}</Text> : null}
            <View style={{ flexDirection: "row", gap: 8 }}>
              {v.data.password ? <Button title={shown === v.revision ? "Nascondi" : "Mostra"} kind="secondary" onPress={() => setShown(shown === v.revision ? null : v.revision)} style={{ flex: 1 }} /> : null}
              {!engine.offline && (
                <Button title="Ripristina" style={{ flex: 1 }} onPress={() => Alert.alert("Ripristinare questa versione?", "La versione attuale resta nella cronologia.", [
                  { text: "Annulla", style: "cancel" },
                  { text: "Ripristina", onPress: async () => {
                    try { await engine.call("restoreVersion", item.id, v.revision); app.toast("Versione ripristinata"); app.back(3); } catch (e) { setError(errorText(e)); }
                  } },
                ])} />
              )}
            </View>
          </Card>
        ))}
        <Text style={{ color: color.muted, fontSize: 13 }}>{where}</Text>
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ condivisione di un cliente

export function ShareScreen({ containerId, title }: { containerId: string; title: string }) {
  const engine = useEngine();
  const app = useApp();
  const [members, setMembers] = useState<{ userId: string; displayName: string; email: string; permission: Perm }[]>([]);
  const [groups, setGroups] = useState<{ groupId: string; name: string; permission: Perm }[]>([]);
  const [dir, setDir] = useState<DirUser[]>([]);
  const [allGroups, setAllGroups] = useState<{ id: string; name: string; verified: boolean; rotationRequired: boolean }[]>([]);
  const [perm, setPerm] = useState<Perm>("read");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = async () => {
    try {
      const [m, g, d, ag] = await Promise.all([
        engine.call<typeof members>("members", containerId), engine.call<typeof groups>("containerGroups", containerId),
        engine.call<DirUser[]>("directory"), engine.call<typeof allGroups>("groups"),
      ]);
      setMembers(m); setGroups(g); setDir(d); setAllGroups(ag);
    } catch (e) {
      setError(errorText(e));
    }
  };
  useEffect(() => { void load(); }, [containerId]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setError(null);
    try { await fn(); app.toast(done); await load(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  };
  const candidates = dir.filter((u) => u.status === "active" && u.id !== app.me?.id && !members.some((m) => m.userId === u.id));
  const groupCandidates = allGroups.filter((g) => g.verified && !g.rotationRequired && !groups.some((x) => x.groupId === g.id));
  if (engine.offline) {
    return <View style={{ flex: 1 }}><Header title="Condividi" subtitle={title} back /><View style={{ padding: 16 }}><Notice kind="warn">Le condivisioni richiedono la rete.</Notice></View></View>;
  }
  return (
    <View style={{ flex: 1 }}>
      <Header title="Condividi" subtitle={title} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
        <Card>
          <Text style={st.h}>Con accesso</Text>
          {members.map((m) => (
            <View key={m.userId} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{m.displayName}{m.userId === app.me?.id ? " (tu)" : ""}</Text><Text style={st.sub}>{m.email} · {PERM[m.permission]}</Text></View>
              {m.userId !== app.me?.id && (
                <Button title="Rimuovi" kind="danger" disabled={busy} style={st.small} onPress={() => Alert.alert(`Togliere l'accesso a ${m.displayName}?`, "La chiave del cliente viene ruotata subito.", [
                  { text: "Annulla", style: "cancel" },
                  { text: "Rimuovi", style: "destructive", onPress: () => void act(() => engine.call("revoke", containerId, m.userId), "Accesso rimosso e chiave ruotata") },
                ])} />
              )}
            </View>
          ))}
          {groups.map((g) => (
            <View key={g.groupId} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>Gruppo {g.name}</Text><Text style={st.sub}>{PERM[g.permission]}</Text></View>
              <Button title="Rimuovi" kind="danger" disabled={busy} style={st.small} onPress={() => void act(() => engine.call("unshareGroup", containerId, g.groupId), "Gruppo rimosso e chiave ruotata")} />
            </View>
          ))}
        </Card>
        <Card>
          <Text style={st.h}>Aggiungi</Text>
          <Text style={st.sub}>Permesso</Text>
          <Choice value={perm} options={[["read", "Lettura"], ["write", "Modifica"], ["manage", "Gestione"]]} onChange={setPerm} />
          {candidates.map((u) => (
            <Pressable key={u.id} disabled={busy || !u.verified} onPress={() => void act(() => engine.call("share", containerId, u.id, perm), `Condiviso con ${u.displayName}`)} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{u.displayName}</Text><Text style={st.sub}>{u.email}{u.verified ? "" : " · chiave da certificare"}</Text></View>
              {u.verified && <Text style={{ color: color.accent, fontWeight: "700" }}>Aggiungi</Text>}
            </Pressable>
          ))}
          {groupCandidates.map((g) => (
            <Pressable key={g.id} disabled={busy} onPress={() => void act(() => engine.call("shareWithGroup", containerId, g.id, perm), `Condiviso con il gruppo ${g.name}`)} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>Gruppo {g.name}</Text></View>
              <Text style={{ color: color.accent, fontWeight: "700" }}>Aggiungi</Text>
            </Pressable>
          ))}
          {!candidates.length && !groupCandidates.length && <Text style={st.sub}>Nessun altro collega o gruppo da aggiungere.</Text>}
        </Card>
        {error && <Notice kind="error">{error}</Notice>}
        <Text style={st.sub}>La chiave del cliente viene cifrata sul telefono per la chiave certificata di ogni destinatario. Le chiavi si certificano dall'estensione.</Text>
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ condivisione di una singola password

export function ItemShareScreen({ item }: { item: Item }) {
  const engine = useEngine();
  const app = useApp();
  const [shares, setShares] = useState<{ userId: string; displayName: string; email: string }[]>([]);
  const [dir, setDir] = useState<DirUser[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = async () => {
    try {
      const [s, d] = await Promise.all([engine.call<typeof shares>("itemShares", item.id), engine.call<DirUser[]>("directory")]);
      setShares(s); setDir(d);
    } catch (e) { setError(errorText(e)); }
  };
  useEffect(() => { void load(); }, [item.id]);
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setError(null);
    try { await fn(); app.toast(done); await load(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  };
  const candidates = dir.filter((u) => u.status === "active" && u.verified && u.id !== app.me?.id && !shares.some((x) => x.userId === u.id));
  return (
    <View style={{ flex: 1 }}>
      <Header title="Condividi solo questa password" subtitle={item.data.name} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
        <Text style={st.sub}>Il collega la vede in sola lettura, anche senza accesso al cliente. Togliendola, la password viene ricifrata.</Text>
        <Card>
          <Text style={st.h}>Condivisa con</Text>
          {shares.length === 0 && <Text style={st.sub}>Nessuno.</Text>}
          {shares.map((x) => (
            <View key={x.userId} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{x.displayName}</Text><Text style={st.sub}>{x.email}</Text></View>
              <Button title="Rimuovi" kind="danger" disabled={busy} style={st.small} onPress={() => void act(() => engine.call("unshareItem", item.id, x.userId), "Condivisione rimossa e password ricifrata")} />
            </View>
          ))}
        </Card>
        <Card>
          <Text style={st.h}>Aggiungi</Text>
          {candidates.map((u) => (
            <Pressable key={u.id} disabled={busy} onPress={() => void act(() => engine.call("shareItem", item.id, u.id), `Condivisa con ${u.displayName}`)} style={st.row}>
              <View style={{ flex: 1 }}><Text style={st.name}>{u.displayName}</Text><Text style={st.sub}>{u.email}</Text></View>
              <Text style={{ color: color.accent, fontWeight: "700" }}>Aggiungi</Text>
            </Pressable>
          ))}
          {!candidates.length && <Text style={st.sub}>Nessun altro collega con chiave certificata.</Text>}
        </Card>
        {error && <Notice kind="error">{error}</Notice>}
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ salute delle password

type Ref = { itemId: string; name: string; where: string };
export function HealthScreen() {
  const engine = useEngine();
  const app = useApp();
  const [r, setR] = useState<{ checked: number; weak: Ref[]; reused: Ref[][]; old: Ref[]; missingOtp: Ref[] } | null>(null);
  useEffect(() => { engine.call<typeof r>("health").then(setR).catch(() => undefined); }, []);
  const open = async (x: Ref) => {
    const it = await engine.call<Item | null>("item", x.itemId);
    if (it) app.push({ name: "item", item: it, where: x.where, canWrite: true });
  };
  const list = (title: string, help: string, refs: Ref[]) => refs.length > 0 && (
    <Card>
      <Text style={st.h}>{title} ({refs.length})</Text>
      <Text style={st.sub}>{help}</Text>
      {refs.map((x, i) => (
        <Pressable key={`${x.itemId}-${i}`} onPress={() => void open(x)} style={st.row}>
          <View style={{ flex: 1 }}><Text style={st.name}>{x.name}</Text><Text style={st.sub}>{x.where}</Text></View>
        </Pressable>
      ))}
    </Card>
  );
  return (
    <View style={{ flex: 1 }}>
      <Header title="Salute password" subtitle={r ? `${r.checked} password analizzate sul telefono` : "Analisi…"} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
        {r && list("Usate in più punti", "Se una viene compromessa, lo sono anche le altre: cambiale per prime.", r.reused.flat())}
        {r && list("Deboli", "Brevi o prevedibili.", r.weak)}
        {r && list("Non cambiate da oltre un anno", "Valuta se cambiarle.", r.old)}
        {r && list("Pannelli senza OTP", "Se il servizio lo supporta, attiva il secondo fattore e aggancialo qui.", r.missingOtp)}
        {r && !r.reused.length && !r.weak.length && !r.old.length && <Notice kind="ok">Nessun problema trovato.</Notice>}
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ account

/** Lunghezza minima letta dal server (il motore la applica comunque). */
function useMinLength(): number {
  const engine = useEngine();
  const [n, setN] = useState(12);
  useEffect(() => { engine.call<{ minPasswordLength: number }>("passwordPolicy").then((p) => setN(p.minPasswordLength)).catch(() => undefined); }, []);
  return n;
}

export function ChangePasswordScreen() {
  const engine = useEngine();
  const app = useApp();
  const minLen = useMinLength();
  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if ([...pw].length < minLen) return setError(`La nuova master password deve avere almeno ${minLen} caratteri.`);
    if (pw !== pw2) return setError("Le due password non coincidono.");
    setBusy(true);
    setError(null);
    try {
      await engine.call("changePassword", cur, pw, code.trim());
      app.toast("Master password cambiata: le altre sessioni sono state chiuse");
      app.pop();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <View style={{ flex: 1 }}>
      <Header title="Cambia la master password" back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }} keyboardShouldPersistTaps="handled">
        <Field label="Master password attuale" value={cur} onChangeText={setCur} secureTextEntry />
        <Field label={`Nuova master password (almeno ${minLen} caratteri)`} value={pw} onChangeText={setPw} secureTextEntry />
        <Field label="Ripeti la nuova master password" value={pw2} onChangeText={setPw2} secureTextEntry />
        <Field label="Codice MFA o di riserva" value={code} onChangeText={setCode} autoComplete="one-time-code" />
        {error && <Notice kind="error">{error}</Notice>}
        <Button title={busy ? "Cifratura delle chiavi…" : "Cambia password"} onPress={submit} busy={busy} disabled={!cur || !pw || !code || engine.offline} />
        <Text style={st.sub}>Cambiandola vengono revocati anche i dispositivi attendibili.</Text>
      </ScrollView>
    </View>
  );
}

export function BackupCodesScreen() {
  const engine = useEngine();
  const [code, setCode] = useState("");
  const [left, setLeft] = useState<number | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { engine.call<{ backupCodesRemaining: number }>("mfaStatus").then((r) => setLeft(r.backupCodesRemaining)).catch(() => undefined); }, []);
  return (
    <View style={{ flex: 1 }}>
      <Header title="Codici di riserva" subtitle={left === null ? undefined : `${left} ancora disponibili`} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
        {codes ? (
          <>
            <Notice kind="warn">I codici precedenti non valgono più. Salva questi fuori da StartCredentials: non verranno mostrati di nuovo.</Notice>
            <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
              {codes.map((c) => <Text key={c} selectable style={st.code}>{c}</Text>)}
            </View>
          </>
        ) : (
          <>
            <Field label="Codice dall'app di autenticazione" value={code} onChangeText={setCode} keyboardType="number-pad" />
            {error && <Notice kind="error">{error}</Notice>}
            <Button title="Genera nuovi codici" busy={busy} disabled={!code.trim() || engine.offline} onPress={async () => {
              setBusy(true);
              setError(null);
              try { setCodes(await engine.call<string[]>("regenerateBackupCodes", code.trim())); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
            }} />
          </>
        )}
      </ScrollView>
    </View>
  );
}

// ------------------------------------------------------------------ registrazione da invito

export function RegisterScreen() {
  const engine = useEngine();
  const app = useApp();
  const minLen = useMinLength();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if ([...pw].length < minLen) return setError(`La master password deve avere almeno ${minLen} caratteri: meglio una frase lunga.`);
    if (pw !== pw2) return setError("Le due password non coincidono.");
    setBusy(true);
    setError(null);
    try {
      await engine.call("init", app.settings.serverUrl!, "");
      await engine.call("register", app.inviteToken.current, pw);
      app.inviteToken.current = null;
      app.pendingPassword.current = pw;
      app.setPhase("mfaSetup");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <ScrollView contentContainerStyle={{ padding: 20, gap: 20, paddingTop: 48, backgroundColor: color.ground, flexGrow: 1 }} keyboardShouldPersistTaps="handled">
      <Brand />
      <Card>
        <Text style={{ fontSize: 22, fontWeight: "700", color: color.ink }}>Attiva il tuo account</Text>
        <Text style={{ color: color.muted }}>Scegli la master password: la conosci solo tu, nessuno può recuperarla al posto tuo senza la procedura con gli amministratori.</Text>
        <Field label={`Master password (almeno ${minLen} caratteri)`} value={pw} onChangeText={setPw} secureTextEntry />
        <Field label="Ripeti la master password" value={pw2} onChangeText={setPw2} secureTextEntry />
        {error && <Notice kind="error">{error}</Notice>}
        <Button title={busy ? "Creazione delle chiavi…" : "Crea l'account"} onPress={submit} busy={busy} disabled={!pw || !pw2} />
        <Button title="Annulla" kind="ghost" onPress={() => { app.inviteToken.current = null; app.setPhase("login"); }} />
      </Card>
    </ScrollView>
  );
}

// ------------------------------------------------------------------ invio sicuro

type SendInfo = { supported: boolean; enabled: boolean; maxHours: number; domains: string[] };
const DURATIONS: [number, string][] = [[1, "1 ora"], [24, "1 giorno"], [72, "3 giorni"], [168, "7 giorni"], [336, "14 giorni"], [720, "30 giorni"]];

/** Invio sicuro a un destinatario anche esterno: cifrato sul telefono, codice da comunicare a parte. */
export function SecureSendScreen({ item }: { item: Item }) {
  const engine = useEngine();
  const app = useApp();
  const d = item.data;
  const [info, setInfo] = useState<SendInfo | null>(null);
  const [hasOtp, setHasOtp] = useState(false);
  const [to, setTo] = useState("");
  // Cellulare per il codice su WhatsApp: resta su questa schermata, non va al server.
  const [phone, setPhone] = useState("");
  const wa = whatsappNumber(phone);
  const [hours, setHours] = useState(24);
  const [views, setViews] = useState(1);
  const [fields, setFields] = useState({ username: !!d.username, password: !!d.password, urls: !!d.urls?.length, notes: false, otp: false });
  const [res, setRes] = useState<{ code: string; link: string; emailed: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    engine.call<SendInfo>("secureSendInfo").then((i) => {
      setInfo(i);
      const allowed = DURATIONS.filter(([h]) => h <= i.maxHours);
      if (!allowed.some(([h]) => h === 24)) setHours(allowed[0]?.[0] ?? 1);
    }).catch((e) => setError(errorText(e)));
    engine.call<string | null>("effectiveTotp", item.id).then((u) => setHasOtp(!!u)).catch(() => undefined);
  }, [item.id]);
  const opts: [keyof typeof fields, string, boolean][] = [
    ["username", "Nome utente", !!d.username], ["password", "Password", !!d.password], ["urls", "Indirizzi dei siti", !!d.urls?.length],
    ["notes", "Note", !!d.notes], ["otp", "Chiave OTP", hasOtp],
  ];
  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setRes(await engine.call<{ code: string; link: string; emailed: boolean }>("createSecureSend", item.id,
        { recipientEmail: to.trim(), expiresInHours: hours, maxViews: views, fields }));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (res) {
    return (
      <View style={{ flex: 1 }}>
        <Header title="Invio sicuro creato" subtitle={d.name} />
        <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
          <Notice kind={res.emailed ? "ok" : "warn"}>
            {res.emailed ? `Collegamento inviato per email a ${to.trim().toLowerCase()}.` : "Email non inviata: manda tu il collegamento qui sotto."}
          </Notice>
          <Card>
            <Text style={st.h}>Codice di accesso</Text>
            <Text style={st.sub}>Comunicalo per un canale diverso dall'email. Non viene salvato: annotalo ora se serve.</Text>
            <Text selectable style={{ fontFamily: mono, fontSize: 22, letterSpacing: 2, color: color.ink }}>{res.code}</Text>
            <View style={{ flexDirection: "row", gap: 8 }}>
              <CopyButton value={res.code} toast={app.toast} />
              <Button kind="secondary" title="Condividi il codice" style={st.small}
                onPress={() => void Share.share({ message: accessCodeMessage(res.code) })} />
            </View>
            <Button title={wa ? `Invia il codice su WhatsApp a +${wa}` : "Invia il codice su WhatsApp"}
              onPress={() => void Linking.openURL(whatsappCodeLink(res.code, wa || "")).catch(() => app.toast("WhatsApp non è installato"))} />
            <Text style={st.sub}>Nel messaggio c'è solo il codice, non il collegamento: chi intercetta uno solo dei due canali non apre l'invio.</Text>
          </Card>
          {!res.emailed && (
            <Card>
              <Text style={st.h}>Collegamento</Text>
              <Text selectable style={[st.sub, { fontFamily: mono }]}>{res.link}</Text>
              <CopyButton value={res.link} toast={app.toast} />
            </Card>
          )}
          <Text style={st.sub}>Riceverai un'email a ogni apertura. Puoi revocare l'invio dall'estensione, in Impostazioni → Invii sicuri.</Text>
          <Button title="Fatto" onPress={() => app.pop()} />
        </ScrollView>
      </View>
    );
  }

  return (
    <View style={{ flex: 1 }}>
      <Header title="Invia in modo sicuro" subtitle={d.name} back />
      <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }} keyboardShouldPersistTaps="handled">
        {!info && !error && <Text style={st.sub}>Caricamento…</Text>}
        {info && !info.enabled && <Notice kind="warn">L'invio sicuro è disattivato dall'amministratore.</Notice>}
        {info && !info.supported && <Notice kind="warn">Questo telefono non supporta la cifratura dell'invio sicuro: usa l'estensione sul computer.</Notice>}
        {info?.enabled && info.supported && (
          <>
            <Text style={st.sub}>I dati scelti vengono cifrati sul telefono. Il destinatario riceve per email un collegamento; per aprirlo serve un codice che gli comunicherai tu per un altro canale.</Text>
            <Field label="Email del destinatario" value={to} onChangeText={setTo} keyboardType="email-address" placeholder="referente@cliente.it" />
            {info.domains.length > 0 && <Text style={st.sub}>Domini ammessi: {info.domains.join(", ")}</Text>}
            <Field label="Cellulare per il codice su WhatsApp (facoltativo)" value={phone} onChangeText={setPhone} keyboardType="phone-pad" placeholder="+39 333 1234567" />
            {wa === null
              ? <Text style={{ color: color.danger, fontSize: 13 }}>Numero non valido: usa il prefisso internazionale, per esempio +39 333 1234567.</Text>
              : <Text style={st.sub}>Serve solo ad aprire WhatsApp sul contatto giusto: non viene salvato.</Text>}
            <Card>
              <Text style={st.h}>Cosa inviare</Text>
              {opts.filter(([, , has]) => has).map(([k, label]) => (
                <Pressable key={k} accessibilityRole="checkbox" accessibilityState={{ checked: fields[k] }} onPress={() => setFields({ ...fields, [k]: !fields[k] })} style={st.row}>
                  <Text style={{ fontSize: 18, color: fields[k] ? color.accent : color.muted }}>{fields[k] ? "☑" : "☐"}</Text>
                  <Text style={[st.name, { flex: 1 }]}>{label}</Text>
                </Pressable>
              ))}
              {fields.otp && <Notice kind="warn">Con la chiave OTP il destinatario potrà generare codici anche in futuro, finché non la cambi alla fonte.</Notice>}
            </Card>
            <Card>
              <Text style={st.h}>Scadenza</Text>
              <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
                {DURATIONS.filter(([h]) => h <= info.maxHours).map(([h, l]) => (
                  <Button key={h} title={l} kind={hours === h ? "primary" : "secondary"} style={st.small} onPress={() => setHours(h)} />
                ))}
              </View>
              <Text style={st.h}>Aperture consentite</Text>
              <View style={{ flexDirection: "row", gap: 8 }}>
                {[1, 2, 3, 5].map((n) => (
                  <Button key={n} title={n === 1 ? "Una sola" : String(n)} kind={views === n ? "primary" : "secondary"} style={st.small} onPress={() => setViews(n)} />
                ))}
              </View>
            </Card>
            <Button title={busy ? "Cifratura…" : "Crea l'invio"} busy={busy} disabled={!to.trim() || wa === null || !Object.values(fields).some(Boolean)} onPress={() => void create()} />
          </>
        )}
        {error && <Notice kind="error">{error}</Notice>}
      </ScrollView>
    </View>
  );
}

const st = StyleSheet.create({
  h: { fontWeight: "700", color: color.ink },
  row: { flexDirection: "row", alignItems: "center", gap: 10, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: color.line },
  name: { fontSize: 15, fontWeight: "600", color: color.ink },
  sub: { fontSize: 13, color: color.muted },
  small: { minHeight: 38, paddingHorizontal: 12 },
  code: { fontFamily: mono, fontSize: 16, padding: 8, borderWidth: 1, borderColor: color.line, borderRadius: 8, width: "47%", textAlign: "center", color: color.ink },
});

export type { Me };

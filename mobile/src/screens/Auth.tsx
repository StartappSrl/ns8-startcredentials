import { ReactNode, useEffect, useState } from "react";
import { Alert, KeyboardAvoidingView, Linking, Platform, ScrollView, Switch, Text, View } from "react-native";
import type { Me } from "@startcredentials/client";
import { useEngine } from "../engine/Engine";
import { errorText, useApp } from "../state/App";
import { biometricAvailable, loadDeviceTrust, saveBiometricSession, saveDeviceTrust, saveSettings } from "../state/storage";
import { Brand, Button, Card, Field, Notice } from "../ui/kit";
import { color, mono } from "../theme";

function Frame({ title, intro, children }: { title: string; intro?: string; children: ReactNode }) {
  return (
    <KeyboardAvoidingView style={{ flex: 1, backgroundColor: color.ground }} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <ScrollView contentContainerStyle={{ padding: 20, gap: 20, paddingTop: 48 }} keyboardShouldPersistTaps="handled">
        <Brand />
        <Card>
          <Text style={{ fontSize: 22, fontWeight: "700", color: color.ink }} accessibilityRole="header">{title}</Text>
          {intro && <Text style={{ color: color.muted, fontSize: 15, lineHeight: 21 }}>{intro}</Text>}
          {children}
        </Card>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

export function SetupScreen() {
  const engine = useEngine();
  const app = useApp();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setError(null);
    let origin: string;
    try {
      const t = value.trim();
      origin = new URL(t.includes("://") ? t : `https://${t}`).origin;
    } catch {
      return setError("Indirizzo non valido.");
    }
    if (!origin.startsWith("https://")) return setError("Il server deve usare HTTPS.");
    setBusy(true);
    try {
      engine.setAllowedOrigin(origin);
      await engine.call("init", origin, "");
      await engine.call("status");
      await app.updateSettings({ serverUrl: origin });
      app.setPhase("login");
    } catch {
      setError("A questo indirizzo non risponde un server StartCredentials.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Collega il server" intro="Inserisci l'indirizzo del server StartCredentials della tua azienda, per esempio secures.startappitalia.it.">
      <Field label="Indirizzo del server" value={value} onChangeText={setValue} keyboardType="url" placeholder="secures.startappitalia.it" onSubmitEditing={submit} />
      {error && <Notice kind="error">{error}</Notice>}
      <Button title={busy ? "Verifica…" : "Continua"} onPress={submit} busy={busy} disabled={!value.trim()} />
      <Text style={{ color: color.muted, fontSize: 13 }}>L'account si crea dall'estensione per Chrome o Edge: sul telefono si accede con le stesse credenziali.</Text>
    </Frame>
  );
}

const deviceLabel = () => `Android ${Platform.Version}`;

export function LoginScreen() {
  const engine = useEngine();
  const app = useApp();
  const [email, setEmail] = useState(app.settings.email ?? "");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [canOffline, setCanOffline] = useState(false);

  const bio = app.settings.biometric && biometricAvailable();
  /** Senza rete: sblocco dai dati cifrati salvati sul telefono, in sola lettura. */
  const unlockOffline = async () => {
    setBusy(true);
    setError(null);
    try {
      await engine.call("init", app.settings.serverUrl!, app.settings.pinnedOrg ?? "");
      const r = await engine.call<{ me: Me; fingerprint: string }>("unlock", pw);
      if (email && r.me.email.toLowerCase() !== email.trim().toLowerCase()) throw new Error("I dati offline appartengono a un altro account.");
      await app.afterUnlock(r);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const tryBio = async () => {
    setBusy(true);
    setError(null);
    const err = await app.biometricUnlock();
    if (err) setError(err);
    setBusy(false);
  };
  useEffect(() => { if (bio) void tryBio(); }, []);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await engine.call("init", app.settings.serverUrl!, app.settings.pinnedOrg ?? "");
      const trust = await loadDeviceTrust(email, app.settings.serverUrl!);
      const r = await engine.call<{ state: string }>("login", email.trim(), pw, trust?.token);
      await app.updateSettings({ email: email.trim() });
      app.pendingPassword.current = pw;
      if (r.state === "mfa_pending") return app.setPhase("mfa");
      if (r.state === "mfa_setup") return app.setPhase("mfaSetup");
      await unlockAndFinish(engine, app, pw);
    } catch (e) {
      // Server non raggiungibile: si propone lo sblocco offline, se ci sono dati salvati.
      if (!(e as { code?: string }).code && (await engine.hasOfflineData())) {
        setCanOffline(true);
        setError("Server non raggiungibile. Puoi aprire in sola lettura i dati salvati sul telefono.");
      } else setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Frame title={app.settings.email ? "Sblocca" : "Accedi"} intro={new URL(app.settings.serverUrl!).host}>
      {bio && <Button title="Sblocca con l'impronta" onPress={tryBio} busy={busy} />}
      <Field label="Email" value={email} onChangeText={setEmail} keyboardType="email-address" autoComplete="email" textContentType="username" />
      <Field label="Master password" value={pw} onChangeText={setPw} secureTextEntry autoComplete="password" textContentType="password" onSubmitEditing={submit} />
      {error && <Notice kind="error">{error}</Notice>}
      <Button title={busy ? "Accesso…" : "Accedi"} kind={bio ? "secondary" : "primary"} onPress={submit} busy={busy} disabled={!email || !pw} />
      {canOffline && <Button title="Sblocca offline" kind="secondary" onPress={unlockOffline} busy={busy} disabled={!pw} />}
      <Button title="Cambia server" kind="ghost" onPress={async () => { engine.wipeOffline(); await saveSettings({ serverUrl: undefined, pinnedOrg: undefined }); app.setPhase("setup"); }} />
    </Frame>
  );
}

/** Sblocco con la password appena usata; propone l'impronta al primo accesso. */
async function unlockAndFinish(engine: ReturnType<typeof useEngine>, app: ReturnType<typeof useApp>, password: string) {
  const r = await engine.call<{ me: Me; fingerprint: string }>("unlock", password);
  if (app.settings.biometric === undefined && biometricAvailable()) {
    await new Promise<void>((done) => Alert.alert(
      "Sblocco con l'impronta",
      "Vuoi riaprire StartCredentials con l'impronta digitale? La sessione resta nell'archivio protetto del telefono.",
      [
        { text: "No", style: "cancel", onPress: () => { void app.updateSettings({ biometric: false }); done(); } },
        { text: "Sì", onPress: async () => {
          try {
            await saveBiometricSession(await engine.call("serialize"));
            await app.updateSettings({ biometric: true });
          } catch {
            /* impronta annullata */
          }
          done();
        } },
      ],
    ));
  }
  await app.afterUnlock(r);
}

export function MfaScreen() {
  const engine = useEngine();
  const app = useApp();
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await engine.call("verifyMfa", code.trim());
      if (trust) {
        try {
          const t = await engine.call<{ deviceToken: string; deviceId: string; expiresAt: string }>("trustDevice", deviceLabel());
          await saveDeviceTrust({ token: t.deviceToken, deviceId: t.deviceId, expiresAt: t.expiresAt, email: app.settings.email!, serverUrl: app.settings.serverUrl! });
        } catch {
          /* funzione disattivata sul server */
        }
      }
      await unlockAndFinish(engine, app, app.pendingPassword.current ?? "");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Codice di verifica" intro="Inserisci il codice a 6 cifre dell'app di autenticazione, oppure un codice di riserva.">
      <Field label="Codice" value={code} onChangeText={setCode} keyboardType="number-pad" autoComplete="one-time-code" textContentType="oneTimeCode" style={{ fontSize: 22, letterSpacing: 6, textAlign: "center", fontFamily: mono }} onSubmitEditing={submit} />
      <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
        <Switch value={trust} onValueChange={setTrust} trackColor={{ true: color.accent }} accessibilityLabel="Dispositivo attendibile" />
        <Text style={{ flex: 1, color: color.ink2 }}>Considera attendibile questo telefono per 30 giorni (poi basterà la master password)</Text>
      </View>
      {error && <Notice kind="error">{error}</Notice>}
      <Button title="Verifica" onPress={submit} busy={busy} disabled={code.trim().length < 6} />
      <Button title="Annulla" kind="ghost" onPress={() => app.setPhase("login")} />
    </Frame>
  );
}

export function MfaSetupScreen() {
  const engine = useEngine();
  const app = useApp();
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { engine.call<{ secret: string; otpauthUri: string }>("setupMfa").then(setSetup).catch((e) => setError(errorText(e))); }, []);
  if (codes) {
    return (
      <Frame title="Salva i codici di riserva" intro="Ognuno sostituisce una volta il codice dell'app se perdi il telefono. Salvali fuori da StartCredentials: non verranno mostrati di nuovo.">
        <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
          {codes.map((c) => <Text key={c} style={{ fontFamily: mono, fontSize: 16, padding: 8, borderWidth: 1, borderColor: color.line, borderRadius: 8, width: "47%", textAlign: "center" }} selectable>{c}</Text>)}
        </View>
        <Button title="Ho salvato i codici" onPress={async () => {
          setBusy(true);
          try { await unlockAndFinish(engine, app, app.pendingPassword.current ?? ""); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
        }} busy={busy} />
      </Frame>
    );
  }
  return (
    <Frame title="Attiva il secondo fattore" intro="Aggiungi StartCredentials alla tua app di autenticazione, poi inserisci il codice a 6 cifre.">
      {setup && (
        <>
          <Button title="Apri nell'app di autenticazione" kind="secondary" onPress={() => Linking.openURL(setup.otpauthUri).catch(() => Alert.alert("Nessuna app di autenticazione trovata", "Inserisci a mano la chiave qui sotto."))} />
          <Text style={{ color: color.muted }}>Oppure inserisci a mano questa chiave:</Text>
          <Text style={{ fontFamily: mono, fontSize: 16 }} selectable>{setup.secret.match(/.{1,4}/g)!.join(" ")}</Text>
        </>
      )}
      <Field label="Codice a 6 cifre" value={code} onChangeText={setCode} keyboardType="number-pad" autoComplete="one-time-code" />
      {error && <Notice kind="error">{error}</Notice>}
      <Button title="Attiva" busy={busy} disabled={!setup || code.trim().length !== 6} onPress={async () => {
        setBusy(true);
        setError(null);
        try { setCodes(await engine.call<string[]>("enableMfa", code.trim())); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
      }} />
    </Frame>
  );
}

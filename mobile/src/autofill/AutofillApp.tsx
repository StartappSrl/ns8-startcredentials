/**
 * Componente "autofill": la schermata che Android apre quando si tocca
 * "Compila con StartCredentials". Ha un proprio motore (WebView) e si chiude
 * restituendo i valori scelti, oppure annullando.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { Alert, FlatList, Pressable, Text, TextInput, View } from "react-native";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";
import { usePreventScreenCapture } from "expo-screen-capture";
import type { Item, Me } from "@startcredentials/client";
import { Autofill, AutofillRequest } from "../../modules/sc-autofill";
import { EngineError, EngineProvider, useEngine } from "../engine/Engine";
import { biometricAvailable, loadBiometricSession, loadDeviceTrust, loadSettings, Settings } from "../state/storage";
import { Brand, Button, Field, Notice } from "../ui/kit";
import { color, mono } from "../theme";

type Row = { item: Item; where: string; canWrite: boolean };

const msg = (e: unknown) => {
  const err = e as EngineError;
  if (err.code === "invalid_credentials") return "Email o master password non corretti.";
  if (err.code === "invalid_code") return "Codice non valido.";
  return err.message || "Errore imprevisto.";
};

function Flow() {
  usePreventScreenCapture();
  const engine = useEngine();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [req] = useState<AutofillRequest>(() => Autofill.getRequest());
  const [stage, setStage] = useState<"start" | "password" | "mfa" | "pick" | "save">("start");
  const [save] = useState(() => (req.mode === "save" ? Autofill.getSave() : null));
  const [saveName, setSaveName] = useState(req.webDomain?.replace(/^www\./, "") ?? req.appLabel ?? req.packageName ?? "");
  const [saveTarget, setSaveTarget] = useState<string | null>(null);
  const [writable, setWritable] = useState<{ id: string; name: string }[]>([]);
  const [existing, setExisting] = useState<Row | null>(null);
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [matches, setMatches] = useState<Row[]>([]);
  const [all, setAll] = useState<Row[] | null>(null);
  const [q, setQ] = useState("");
  const pwRef = useRef("");

  const target = req.webDomain ?? req.appLabel ?? req.packageName ?? "";

  useEffect(() => {
    (async () => {
      const st = await loadSettings();
      setSettings(st);
      if (!req.active || !st.serverUrl) return;
      engine.setOfflineEnabled(st.offline !== false);
      engine.setAllowedOrigin(new URL(st.serverUrl).origin);
      await engine.call("init", st.serverUrl, st.pinnedOrg ?? "");
      if (st.biometric && biometricAvailable()) await unlockBiometric();
      else setStage("password");
    })().catch((e) => { setError(msg(e)); setStage("password"); });
  }, []);

  const loadMatches = async () => {
    if (req.mode === "save") return prepareSave();
    const found = req.webDomain
      ? await engine.call<Row[]>("lookup", `https://${req.webDomain}`)
      : req.packageName ? await engine.call<Row[]>("lookupApp", req.packageName) : [];
    setMatches(found);
    setStage("pick");
    if (!found.length) setAll(await engine.call<Row[]>("allItems"));
  };

  /** Proposta di salvataggio: stesso utente già presente → aggiornamento, altrimenti nuovo elemento. */
  const prepareSave = async () => {
    const found = req.webDomain
      ? await engine.call<Row[]>("lookup", `https://${req.webDomain}`)
      : req.packageName ? await engine.call<Row[]>("lookupApp", req.packageName) : [];
    setExisting(found.find((r) => r.canWrite && (r.item.data.username ?? "") === (save?.username ?? "")) ?? null);
    const cs = await engine.call<{ id: string; kind: string; permission: string; meta: { name: string } }[]>("containers");
    const w = cs.filter((c) => c.kind !== "org" && c.permission !== "read").map((c) => ({ id: c.id, name: c.kind === "personal" ? "Area personale" : c.meta.name }));
    setWritable(w);
    setSaveTarget(w.find((c) => c.name === "Area personale")?.id ?? w[0]?.id ?? null);
    setStage("save");
  };

  const doSave = async () => {
    if (!save) return;
    setBusy(true);
    setError(null);
    try {
      if (existing) {
        await engine.call("updateItem", existing.item.id, { ...existing.item.data, password: save.password });
      } else {
        if (!saveTarget) throw new Error("Nessun cliente in cui puoi salvare.");
        const url = req.webDomain ? `https://${req.webDomain}` : `androidapp://${req.packageName}`;
        await engine.call("createItem", saveTarget, { type: "login", name: saveName.trim() || target, username: save.username || undefined, password: save.password, urls: [url] }, null);
      }
      Autofill.finish();
    } catch (e) {
      setError(msg(e));
    } finally {
      setBusy(false);
    }
  };

  const unlockBiometric = async () => {
    setBusy(true);
    setError(null);
    try {
      const session = await loadBiometricSession<{ token: string; vault: unknown }>();
      if (!session) throw new Error("Nessuna sessione salvata.");
      await engine.call<{ me: Me }>("restore", session);
      await loadMatches();
    } catch (e) {
      setError(msg(e));
      setStage("password");
    } finally {
      setBusy(false);
    }
  };

  const unlockPassword = async () => {
    if (!settings?.serverUrl || !settings.email) return setError("Accedi prima dall'app StartCredentials.");
    setBusy(true);
    setError(null);
    pwRef.current = pw;
    try {
      const trust = await loadDeviceTrust(settings.email, settings.serverUrl);
      let state = "active";
      try {
        state = (await engine.call<{ state: string }>("login", settings.email, pw, trust?.token)).state;
      } catch (e) {
        // Senza rete: dati salvati, in sola lettura.
        if ((e as EngineError).code) throw e;
      }
      if (state === "mfa_pending") return setStage("mfa");
      if (state === "mfa_setup") throw new Error("Completa prima la configurazione dall'app StartCredentials.");
      await engine.call("unlock", pw);
      await loadMatches();
    } catch (e) {
      setError(msg(e));
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    setBusy(true);
    setError(null);
    try {
      await engine.call("verifyMfa", code.trim());
      await engine.call("unlock", pwRef.current);
      await loadMatches();
    } catch (e) {
      setError(msg(e));
    } finally {
      setBusy(false);
    }
  };

  const fill = async (r: Row, associate: boolean) => {
    try {
      if (associate && req.packageName) {
        await engine.call("updateItem", r.item.id, { ...r.item.data, urls: [...(r.item.data.urls ?? []), `androidapp://${req.packageName}`] });
      }
      let otp: string | undefined;
      if (req.kinds?.includes("otp")) {
        const uri = await engine.call<string | null>("effectiveTotp", r.item.id);
        if (uri) otp = (await engine.call<{ code: string }>("totp", uri)).code;
      }
      await engine.call("report", "item.fill", r.item.containerId, r.item.id).catch(() => undefined);
      Autofill.complete({ username: r.item.data.username, password: r.item.data.password, otp }, r.item.data.name);
    } catch (e) {
      setError(msg(e));
    }
  };

  /** Scelta manuale: avvisa se il sito non corrisponde, propone l'associazione per le app. */
  const pickManual = (r: Row) => {
    if (req.webDomain) {
      Alert.alert("Il sito non corrisponde", `«${r.item.data.name}» non è salvata per ${req.webDomain}. Compilare comunque? Fallo solo se sei sicuro che il sito sia quello giusto.`, [
        { text: "Annulla", style: "cancel" },
        { text: "Compila", style: "destructive", onPress: () => void fill(r, false) },
      ]);
    } else if (r.canWrite && !engine.offline) {
      Alert.alert("Ricordare per questa app?", `La prossima volta «${r.item.data.name}» comparirà subito per ${req.appLabel ?? req.packageName}.`, [
        { text: "Solo ora", onPress: () => void fill(r, false) },
        { text: "Ricorda", onPress: () => void fill(r, true) },
      ]);
    } else void fill(r, false);
  };

  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (all ?? []).filter((r) => !s || [r.item.data.name, r.item.data.username, r.where, ...(r.item.data.urls ?? [])].some((v) => v?.toLowerCase().includes(s))).slice(0, 80);
  }, [all, q]);

  if (!req.active) {
    return <View style={{ padding: 20, gap: 12 }}><Notice kind="warn">Nessuna richiesta di compilazione.</Notice><Button title="Chiudi" onPress={() => Autofill.cancel()} /></View>;
  }

  const rowView = (r: Row, onPress: () => void) => (
    <Pressable onPress={onPress} accessibilityRole="button" style={({ pressed }) => [{ padding: 14, borderBottomWidth: 1, borderBottomColor: color.line, backgroundColor: color.surface }, pressed && { backgroundColor: color.accentSoft }]}>
      <Text style={{ fontSize: 16, fontWeight: "600", color: color.ink }} numberOfLines={1}>{r.item.data.name}</Text>
      <Text style={{ fontSize: 13, color: color.muted }} numberOfLines={1}>{r.item.data.username || "senza utente"} · {r.where}</Text>
    </Pressable>
  );

  return (
    <View style={{ flex: 1, backgroundColor: color.ground }}>
      <View style={{ padding: 16, gap: 10, backgroundColor: color.surface, borderBottomWidth: 1, borderBottomColor: color.line }}>
        <Brand small />
        <Text style={{ fontSize: 18, fontWeight: "700", color: color.ink }}>{req.mode === "save" ? "Salva in StartCredentials" : `Compila ${target ? `su ${target}` : ""}`}</Text>
        {engine.offline && <Text style={{ color: color.warnInk }}>Offline: dati dell'ultima sincronizzazione.</Text>}
      </View>
      {error && <View style={{ padding: 12 }}><Notice kind="error">{error}</Notice></View>}

      {stage === "start" && <View style={{ padding: 20 }}><Text style={{ color: color.muted }}>Sblocco…</Text></View>}

      {stage === "password" && (
        <View style={{ padding: 16, gap: 12 }}>
          {settings?.biometric && biometricAvailable() && <Button title="Sblocca con l'impronta" onPress={unlockBiometric} busy={busy} />}
          <Field label="Master password" value={pw} onChangeText={setPw} secureTextEntry onSubmitEditing={unlockPassword} />
          <Button title="Sblocca" kind={settings?.biometric ? "secondary" : "primary"} onPress={unlockPassword} busy={busy} disabled={!pw} />
          <Button title="Annulla" kind="ghost" onPress={() => Autofill.cancel()} />
        </View>
      )}

      {stage === "mfa" && (
        <View style={{ padding: 16, gap: 12 }}>
          <Field label="Codice dell'app di autenticazione" value={code} onChangeText={setCode} keyboardType="number-pad" style={{ fontFamily: mono, fontSize: 22, letterSpacing: 6, textAlign: "center" }} />
          <Button title="Verifica" onPress={verify} busy={busy} disabled={code.trim().length < 6} />
          <Button title="Annulla" kind="ghost" onPress={() => Autofill.cancel()} />
        </View>
      )}

      {stage === "save" && save && (
        <View style={{ padding: 16, gap: 12 }}>
          {engine.offline ? <Notice kind="warn">Senza rete non si può salvare: riprova quando sei connesso.</Notice> : existing ? (
            <>
              <Text style={{ color: color.ink, fontSize: 16 }}>Aggiornare la password di «{existing.item.data.name}» ({save.username || "senza utente"}) in {existing.where}?</Text>
              <Button title="Aggiorna" onPress={doSave} busy={busy} />
            </>
          ) : (
            <>
              <Text style={{ color: color.muted }}>Nuovo accesso {save.username ? `per ${save.username}` : ""}</Text>
              <Field label="Nome" value={saveName} onChangeText={setSaveName} autoCapitalize="sentences" />
              <Text style={{ color: color.muted }}>Dove salvarlo</Text>
              {writable.map((c) => (
                <Pressable key={c.id} accessibilityRole="radio" accessibilityState={{ checked: saveTarget === c.id }} onPress={() => setSaveTarget(c.id)}
                  style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
                  <View style={{ width: 18, height: 18, borderRadius: 9, borderWidth: 2, borderColor: saveTarget === c.id ? color.accent : color.line, backgroundColor: saveTarget === c.id ? color.accent : "transparent" }} />
                  <Text style={{ color: color.ink }}>{c.name}</Text>
                </Pressable>
              ))}
              <Button title="Salva" onPress={doSave} busy={busy} disabled={!saveTarget} />
            </>
          )}
          <Button title="Non ora" kind="ghost" onPress={() => Autofill.finish()} />
        </View>
      )}

      {stage === "pick" && (
        <View style={{ flex: 1 }}>
          {matches.length > 0 && (
            <>
              <Text style={{ padding: 12, color: color.muted }}>Salvate per {target}</Text>
              {matches.map((r) => <View key={r.item.id}>{rowView(r, () => void fill(r, false))}</View>)}
            </>
          )}
          {all === null && matches.length > 0 && (
            <Button title="Scegli un'altra credenziale" kind="ghost" onPress={async () => setAll(await engine.call<Row[]>("allItems"))} />
          )}
          {all !== null && (
            <View style={{ flex: 1 }}>
              <Text style={{ padding: 12, color: color.muted }}>{matches.length ? "Tutte le credenziali" : `Nessuna credenziale salvata per ${target}: scegline una`}</Text>
              <TextInput value={q} onChangeText={setQ} placeholder="Cerca…" placeholderTextColor={color.muted} autoCapitalize="none" autoCorrect={false}
                style={{ marginHorizontal: 12, marginBottom: 8, minHeight: 44, borderWidth: 1, borderColor: color.line, borderRadius: 10, paddingHorizontal: 12, backgroundColor: color.surface, color: color.ink }} />
              <FlatList data={shown} keyExtractor={(r) => r.item.id} renderItem={({ item: r }) => rowView(r, () => pickManual(r))} />
            </View>
          )}
          <Button title="Annulla" kind="ghost" onPress={() => Autofill.cancel()} />
        </View>
      )}
    </View>
  );
}

export function AutofillApp() {
  return (
    <SafeAreaProvider>
      <SafeAreaView style={{ flex: 1, backgroundColor: color.surface }} edges={["top", "bottom"]}>
        <EngineProvider>
          <Flow />
        </EngineProvider>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

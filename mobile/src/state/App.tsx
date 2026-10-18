import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { AppState, BackHandler, Text, View } from "react-native";
import type { Item, Me } from "@startcredentials/client";
import { useEngine, EngineError } from "../engine/Engine";
import {
  biometricAvailable, clearBiometricSession, loadBiometricSession, loadSettings, saveBiometricSession, saveSettings, Settings,
} from "./storage";
import { color } from "../theme";

export type Phase = "boot" | "setup" | "login" | "mfa" | "mfaSetup" | "ready";
export type Route =
  | { name: "clients" } | { name: "search" } | { name: "shared" } | { name: "settings" }
  | { name: "container"; id: string; title: string }
  | { name: "item"; item: Item; where: string };

interface Ctx {
  phase: Phase;
  setPhase(p: Phase): void;
  settings: Settings;
  updateSettings(p: Partial<Settings>): Promise<void>;
  me: Me | null;
  fingerprint: string;
  /** Password tenuta in memoria solo tra accesso e sblocco. */
  pendingPassword: React.MutableRefObject<string | null>;
  afterUnlock(r: { me: Me; fingerprint: string }): Promise<void>;
  biometricUnlock(): Promise<string | null>;
  lock(): Promise<void>;
  logout(): Promise<void>;
  route: Route;
  push(r: Route): void;
  pop(): void;
  tab(r: Route): void;
  toast(msg: string): void;
}

const AppCtx = createContext<Ctx | null>(null);
export const useApp = (): Ctx => {
  const c = useContext(AppCtx);
  if (!c) throw new Error("AppProvider mancante");
  return c;
};

export function errorText(e: unknown): string {
  const err = e as EngineError;
  const map: Record<string, string> = {
    invalid_credentials: "Email o master password non corretti.",
    invalid_code: "Codice non valido o già usato.",
    rate_limited: "Troppi tentativi: attendi un minuto.",
    unauthorized: "Sessione scaduta: accedi di nuovo.",
    security: err.message,
  };
  return (err.code && map[err.code]) || err.message || "Errore imprevisto.";
}

export function AppProvider({ children }: { children: ReactNode }) {
  const engine = useEngine();
  const [phase, setPhase] = useState<Phase>("boot");
  const [settings, setSettings] = useState<Settings>({ autoLockMinutes: 1 });
  const [me, setMe] = useState<Me | null>(null);
  const [fingerprint, setFingerprint] = useState("");
  const [stack, setStack] = useState<Route[]>([{ name: "clients" }]);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const pendingPassword = useRef<string | null>(null);
  const backgroundAt = useRef<number | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const toast = useCallback((m: string) => {
    setToastMsg(m);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToastMsg(null), 2600);
  }, []);

  const updateSettings = async (p: Partial<Settings>) => setSettings(await saveSettings(p));

  // Avvio: server configurato? Allora si inizializza il motore.
  useEffect(() => {
    (async () => {
      const st = await loadSettings();
      setSettings(st);
      if (!st.serverUrl) return setPhase("setup");
      engine.setOfflineEnabled(st.offline !== false);
      engine.setAllowedOrigin(new URL(st.serverUrl).origin);
      await engine.call("init", st.serverUrl, st.pinnedOrg ?? "");
      setPhase("login");
    })().catch(() => setPhase("setup"));
  }, []);

  /** Dopo lo sblocco: fissa la chiave dell'organizzazione e aggiorna la sessione biometrica. */
  const afterUnlock = async (r: { me: Me; fingerprint: string }) => {
    pendingPassword.current = null;
    setMe(r.me);
    setFingerprint(r.fingerprint);
    const patch: Partial<Settings> = {};
    // Primo accesso (TOFU) o rotazione già verificata dal motore con la catena firmata.
    if (r.me.org && settings.pinnedOrg !== r.me.org.signPublic) patch.pinnedOrg = r.me.org.signPublic;
    if (Object.keys(patch).length) await updateSettings(patch);
    if (settings.biometric && biometricAvailable()) {
      await saveBiometricSession(await engine.call("serialize")).catch(() => undefined);
    }
    setStack([{ name: "clients" }]);
    setPhase("ready");
    // Con la rete: copia completa per l'uso offline, in sottofondo.
    if (settings.offline !== false) void engine.syncForOffline();
  };

  /** Sblocco con l'impronta: legge la sessione dall'archivio protetto e la riprende. */
  const biometricUnlock = async (): Promise<string | null> => {
    try {
      const session = await loadBiometricSession<{ token: string; vault: unknown }>();
      if (!session) return "Nessuna sessione salvata: accedi con la password.";
      await engine.call("init", settings.serverUrl!, settings.pinnedOrg ?? "");
      const r = await engine.call<{ me: Me; fingerprint: string }>("restore", session);
      // Con la rete il token deve essere ancora valido; senza rete si procede in sola lettura.
      try {
        await engine.call("session");
      } catch (e) {
        if ((e as EngineError).code === "unauthorized") throw e;
      }
      await afterUnlock(r);
      return null;
    } catch (e) {
      const code = (e as EngineError).code;
      if (code === "unauthorized") {
        await clearBiometricSession();
        return "Sessione scaduta: accedi con la master password.";
      }
      return errorText(e);
    }
  };

  const lock = async () => {
    await engine.call("lock").catch(() => undefined);
    setMe(null);
    setPhase("login");
  };

  const logout = async () => {
    await engine.call("logout").catch(() => undefined);
    await clearBiometricSession().catch(() => undefined);
    engine.wipeOffline();
    setMe(null);
    setPhase("login");
  };

  // Auto-blocco: oltre il tempo scelto in secondo piano, la cassaforte si richiude.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (s) => {
      if (s === "background") {
        backgroundAt.current = Date.now();
        if (settings.autoLockMinutes === 0 && phase === "ready") void lock();
      } else if (s === "active" && backgroundAt.current && phase === "ready") {
        if (Date.now() - backgroundAt.current >= settings.autoLockMinutes * 60_000) void lock();
        backgroundAt.current = null;
      }
    });
    return () => sub.remove();
  }, [settings.autoLockMinutes, phase]);

  // Tasto Indietro di Android.
  useEffect(() => {
    const sub = BackHandler.addEventListener("hardwareBackPress", () => {
      if (phase === "ready" && stack.length > 1) {
        setStack((st) => st.slice(0, -1));
        return true;
      }
      return false;
    });
    return () => sub.remove();
  }, [phase, stack.length]);

  const value: Ctx = {
    phase, setPhase, settings, updateSettings, me, fingerprint, pendingPassword, afterUnlock, biometricUnlock, lock, logout,
    route: stack[stack.length - 1]!,
    push: (r) => setStack((st) => [...st, r]),
    pop: () => setStack((st) => (st.length > 1 ? st.slice(0, -1) : st)),
    tab: (r) => setStack([r]),
    toast,
  };
  return (
    <AppCtx.Provider value={value}>
      {children}
      {toastMsg && (
        <View style={{ position: "absolute", left: 16, right: 16, bottom: 90, backgroundColor: color.ink, borderRadius: 10, padding: 12 }} accessibilityLiveRegion="polite">
          <Text style={{ color: "#fff", fontSize: 14, textAlign: "center" }}>{toastMsg}</Text>
        </View>
      )}
    </AppCtx.Provider>
  );
}

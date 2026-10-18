/**
 * Archiviazione sul telefono, tutta su Android Keystore (expo-secure-store):
 * - impostazioni non segrete (server, email, chiave dell'organizzazione fissata);
 * - token del dispositivo attendibile;
 * - sessione sbloccata solo se l'utente attiva l'impronta: protetta da
 *   autenticazione biometrica a ogni lettura.
 */
import * as SecureStore from "expo-secure-store";

export interface Settings {
  serverUrl?: string;
  email?: string;
  pinnedOrg?: string;
  biometric?: boolean;
  autoLockMinutes: number;
  /** Conserva i dati cifrati sul telefono per l'uso senza rete (predefinito: sì). */
  offline?: boolean;
}
export interface DeviceTrust { token: string; deviceId: string; expiresAt: string; email: string; serverUrl: string }

const OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

export async function loadSettings(): Promise<Settings> {
  const raw = await SecureStore.getItemAsync("settings", OPTS);
  return { autoLockMinutes: 1, ...(raw ? JSON.parse(raw) : {}) };
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await loadSettings()), ...patch };
  await SecureStore.setItemAsync("settings", JSON.stringify(next), OPTS);
  return next;
}

export async function loadDeviceTrust(email: string, serverUrl: string): Promise<DeviceTrust | null> {
  const raw = await SecureStore.getItemAsync("deviceTrust", OPTS);
  const t = raw ? (JSON.parse(raw) as DeviceTrust) : null;
  if (!t || t.serverUrl !== serverUrl || t.email.toLowerCase() !== email.toLowerCase() || new Date(t.expiresAt) < new Date()) return null;
  return t;
}

export async function saveDeviceTrust(t: DeviceTrust): Promise<void> {
  await SecureStore.setItemAsync("deviceTrust", JSON.stringify(t), OPTS);
}

export async function clearDeviceTrust(): Promise<void> {
  await SecureStore.deleteItemAsync("deviceTrust", OPTS);
}

const BIO: SecureStore.SecureStoreOptions = {
  ...OPTS,
  requireAuthentication: true,
  authenticationPrompt: "Sblocca StartCredentials",
};

export function biometricAvailable(): boolean {
  try {
    return SecureStore.canUseBiometricAuthentication();
  } catch {
    return false;
  }
}

/** Sessione sbloccata, leggibile solo dopo l'autenticazione biometrica. */
export async function saveBiometricSession(session: unknown): Promise<void> {
  await SecureStore.setItemAsync("session", JSON.stringify(session), BIO);
}

export async function loadBiometricSession<T>(): Promise<T | null> {
  const raw = await SecureStore.getItemAsync("session", BIO);
  return raw ? (JSON.parse(raw) as T) : null;
}

export async function clearBiometricSession(): Promise<void> {
  await SecureStore.deleteItemAsync("session", OPTS);
}

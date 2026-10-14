import { ComponentChildren, createContext } from "preact";
import { useContext, useEffect, useRef, useState } from "preact/hooks";
import qrcode from "qrcode-generator";
import { Vault } from "@startcredentials/client";
import { copySecret, errorText, touch } from "../shared";

// ------------------------------------------------------------------ notifiche

const ToastCtx = createContext<(msg: string) => void>(() => undefined);
export const useToast = () => useContext(ToastCtx);

export function ToastHost({ children }: { children: ComponentChildren }) {
  const [msg, setMsg] = useState<string | null>(null);
  const timer = useRef<number>();
  const show = (m: string) => {
    setMsg(m);
    clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setMsg(null), 2600);
  };
  useEffect(() => {
    const t = () => void touch();
    window.addEventListener("pointerdown", t);
    window.addEventListener("keydown", t);
    return () => {
      window.removeEventListener("pointerdown", t);
      window.removeEventListener("keydown", t);
    };
  }, []);
  return (
    <ToastCtx.Provider value={show}>
      {children}
      {msg && <div class="toast" role="status">{msg}</div>}
    </ToastCtx.Provider>
  );
}

// ------------------------------------------------------------------ azioni asincrone

export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(errorText(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): { data: T | undefined; error: string | null; reload: () => void; loading: boolean } {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [n, setN] = useState(0);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    fn().then((d) => { if (alive) { setData(d); setError(null); } })
      .catch((e) => { if (alive) setError(errorText(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [...deps, n]);
  return { data, error, loading, reload: () => setN((x) => x + 1) };
}

// ------------------------------------------------------------------ elementi

export function ErrorNote({ error }: { error: string | null }) {
  return error ? <div class="notice error" role="alert">{error}</div> : null;
}

export function Dialog({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ComponentChildren; wide?: boolean }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  return (
    <div class="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div class={`dialog${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <div class="row between">
          <h2>{title}</h2>
          <button class="btn icon-btn ghost" aria-label="Chiudi" onClick={onClose}>
            <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18" /></svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function CopyButton({ value, label = "Copia", onCopied, small = true }: { value: string; label?: string; onCopied?: () => void; small?: boolean }) {
  const toast = useToast();
  return (
    <button class={`btn${small ? " sm" : ""}`} type="button" onClick={async () => {
      await copySecret(value);
      onCopied?.();
      toast("Copiato: gli appunti si svuoteranno a breve");
    }}>{label}</button>
  );
}

export function Secret({ value, onReveal, onCopy }: { value: string; onReveal?: () => void; onCopy?: () => void }) {
  const [shown, setShown] = useState(false);
  return (
    <div class="input-group">
      <input class="input mono" readOnly type={shown ? "text" : "password"} value={value} aria-label="Valore riservato" />
      <button class="btn sm" type="button" onClick={() => { if (!shown) onReveal?.(); setShown(!shown); }}>{shown ? "Nascondi" : "Mostra"}</button>
      <CopyButton value={value} onCopied={onCopy} />
    </div>
  );
}

/** Codice OTP aggiornato in tempo reale con l'anello del tempo residuo. */
export function OtpCode({ uri, onCopy, compact }: { uri: string; onCopy?: () => void; compact?: boolean }) {
  const [st, setSt] = useState<{ code: string; secondsLeft: number; period: number } | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    let alive = true;
    const tick = () => Vault.totp(uri).then((r) => alive && setSt(r)).catch(() => alive && setErr(true));
    tick();
    const t = setInterval(tick, 1000);
    return () => { alive = false; clearInterval(t); };
  }, [uri]);
  if (err) return <div class="notice warn">Configurazione OTP non valida</div>;
  if (!st) return null;
  const low = st.secondsLeft <= 5;
  const C = 2 * Math.PI * 18;
  const code = `${st.code.slice(0, Math.ceil(st.code.length / 2))} ${st.code.slice(Math.ceil(st.code.length / 2))}`;
  if (compact) {
    return (
      <div class="pop-otp">
        <span class="muted small">OTP</span>
        <span class={`grow mono${low ? " otp-code low" : ""}`} style="font-size:18px;letter-spacing:2px">{code}</span>
        <span class="mono small muted">{st.secondsLeft} s</span>
        <CopyButton value={st.code} onCopied={onCopy} />
      </div>
    );
  }
  return (
    <div class="otp">
      <svg class="ring" viewBox="0 0 44 44" role="img" aria-label={`${st.secondsLeft} secondi rimanenti`}>
        <circle cx="22" cy="22" r="18" fill="none" stroke="var(--accent-line)" stroke-width="4" />
        <circle cx="22" cy="22" r="18" fill="none" stroke={low ? "var(--danger)" : "var(--accent)"} stroke-width="4" stroke-linecap="round"
          stroke-dasharray={`${(C * st.secondsLeft) / st.period} ${C}`} transform="rotate(-90 22 22)" />
        <text x="22" y="26.5" text-anchor="middle" font-size="12" font-family="var(--mono)" fill="currentColor">{st.secondsLeft}</text>
      </svg>
      <div class="grow">
        <div class="small muted">Codice OTP</div>
        <div class={`otp-code${low ? " low" : ""}`}>{code}</div>
      </div>
      <CopyButton value={st.code} onCopied={onCopy} />
    </div>
  );
}

export function Qr({ text }: { text: string }) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  return <div class="qr" dangerouslySetInnerHTML={{ __html: qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true }) }} aria-label="Codice QR" role="img" />;
}

/** Stima della robustezza basata sull'entropia (indicativa, senza dizionari). */
export function strength(pw: string): { score: number; label: string; color: string } {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const unique = new Set(pw).size;
  const bits = Math.log2(Math.max(pool, 1)) * Math.min(pw.length, unique * 2);
  if (bits < 40) return { score: 0.2, label: "Debole", color: "var(--danger)" };
  if (bits < 60) return { score: 0.45, label: "Discreta", color: "#B54708" };
  if (bits < 80) return { score: 0.7, label: "Buona", color: "var(--accent)" };
  return { score: 1, label: "Robusta", color: "var(--ok)" };
}

export function Meter({ value }: { value: string }) {
  const s = strength(value);
  if (!value) return null;
  return (
    <div class="row small" style="gap:8px">
      <div class="meter grow"><div style={`width:${s.score * 100}%;background:${s.color}`} /></div>
      <span class="muted">{s.label}</span>
    </div>
  );
}

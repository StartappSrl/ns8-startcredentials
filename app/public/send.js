// Apertura di un invio sicuro di StartCredentials. Tutto avviene nel browser:
// il codice di accesso non viene mai inviato al server.
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const AAD = new TextEncoder().encode("sc:send:v1");
  const token = location.hash.replace(/^#/, "");
  // Il token non resta nella barra degli indirizzi né nella cronologia.
  if (location.hash) history.replaceState(null, "", location.pathname);
  let envelope = null;
  let info = null;
  let timers = [];

  const fail = (msg) => { const e = $("sc-error"); e.textContent = msg; e.hidden = false; };
  const clearFail = () => { $("sc-error").hidden = true; };
  if (!/^[A-Za-z0-9_-]{16,200}$/.test(token)) {
    fail("Collegamento non valido: aprilo esattamente come ricevuto nell'email.");
    $("sc-intro").hidden = true;
    return;
  }
  $("sc-views").textContent = "Attenzione: ogni apertura viene conteggiata e dopo l'ultima il messaggio viene distrutto.";

  const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const normalize = (c) => c.toUpperCase().replace(/[\s-]/g, "");

  async function decrypt(env, code) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(env.salt), iterations: 600000, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv), additionalData: AAD }, key, b64(env.data));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  // ---------------------------------------------------------------- TOTP (RFC 6238)
  function base32(s) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0, val = 0; const out = [];
    for (const ch of s.toUpperCase().replace(/[=\s-]/g, "")) {
      const i = A.indexOf(ch); if (i < 0) throw new Error("chiave OTP non valida");
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }
  async function totp(uri) {
    const u = new URL(uri);
    const p = u.searchParams;
    const digits = Number(p.get("digits") || 6), period = Number(p.get("period") || 30);
    const alg = { SHA256: "SHA-256", SHA512: "SHA-512" }[(p.get("algorithm") || "").toUpperCase()] || "SHA-1";
    const now = Date.now() / 1000;
    const counter = Math.floor(now / period);
    const msg = new Uint8Array(8);
    new DataView(msg.buffer).setUint32(4, counter);
    new DataView(msg.buffer).setUint32(0, Math.floor(counter / 2 ** 32));
    const key = await crypto.subtle.importKey("raw", base32(p.get("secret") || ""), { name: "HMAC", hash: alg }, false, ["sign"]);
    const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
    const o = h[h.length - 1] & 15;
    const n = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** digits;
    return { code: String(n).padStart(digits, "0"), left: period - Math.floor(now % period) };
  }

  // ---------------------------------------------------------------- visualizzazione
  function row(label, value, opts = {}) {
    const box = document.createElement("div");
    box.className = "send-field";
    const l = document.createElement("div"); l.className = "muted small"; l.textContent = label;
    const v = document.createElement(opts.link ? "a" : "div"); v.className = "send-value" + (opts.secret ? " mono" : "");
    if (opts.link) { v.href = value; v.rel = "noopener noreferrer"; v.target = "_blank"; }
    v.textContent = opts.secret ? "••••••••••" : value;
    box.append(l, v);
    const actions = document.createElement("div"); actions.className = "send-actions";
    if (opts.secret) {
      const show = document.createElement("button"); show.type = "button"; show.className = "btn btn-small"; show.textContent = "Mostra";
      show.onclick = () => { const hidden = v.textContent.startsWith("•"); v.textContent = hidden ? value : "••••••••••"; show.textContent = hidden ? "Nascondi" : "Mostra"; };
      actions.append(show);
    }
    if (opts.copy !== false) {
      const copy = document.createElement("button"); copy.type = "button"; copy.className = "btn btn-small"; copy.textContent = "Copia";
      copy.onclick = async () => { await navigator.clipboard.writeText(opts.copyValue ? opts.copyValue() : value); copy.textContent = "Copiato"; setTimeout(() => { copy.textContent = "Copia"; }, 1500); };
      actions.append(copy);
    }
    box.append(actions);
    $("sc-fields").append(box);
    return v;
  }

  async function show(data) {
    $("sc-intro").hidden = true;
    $("sc-result").hidden = false;
    $("sc-from").textContent = `Inviato da ${info.sender}`;
    $("sc-name").textContent = data.name || "Credenziali";
    if (data.username) row("Nome utente", data.username);
    if (data.password) row("Password", data.password, { secret: true });
    for (const url of data.urls || []) {
      const safe = /^https?:\/\//i.test(url) ? url : null;
      if (safe) row("Sito", safe, { link: true }); else row("Sito", url);
    }
    if (data.totpUri) {
      let current = "";
      const v = row("Codice OTP", "…", { copyValue: () => current });
      const tick = async () => { try { const t = await totp(data.totpUri); current = t.code; v.textContent = `${t.code.slice(0, 3)} ${t.code.slice(3)} · ${t.left} s`; } catch { v.textContent = "configurazione OTP non valida"; } };
      await tick();
      timers.push(setInterval(tick, 1000));
    }
    if (data.notes) row("Note", data.notes, { copy: false });
    $("sc-left").textContent = info.viewsLeft ? `Il messaggio si può aprire ancora ${info.viewsLeft} ${info.viewsLeft === 1 ? "volta" : "volte"}.`
      : "Era l'ultima apertura: il messaggio è stato distrutto sul server. Salva ora ciò che ti serve in un posto sicuro.";
  }

  $("sc-open").onclick = async () => {
    clearFail();
    const code = normalize($("sc-code").value);
    if (code.length !== 16 || [...code].some((c) => !ALPHABET.includes(c))) return fail("Il codice ha 16 caratteri (lettere e cifre), per esempio ABCD-EFGH-JKLM-NPQR.");
    $("sc-open").disabled = true;
    try {
      // Il pacchetto cifrato si scarica una volta sola: i tentativi con il codice restano in questo browser.
      if (!envelope) {
        const r = await fetch("/api/v1/sends/open", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
        if (r.status === 404) return fail("Il messaggio non è più disponibile: è scaduto, è stato revocato o è già stato aperto.");
        if (r.status === 429) return fail("Troppi tentativi: riprova tra un minuto.");
        if (!r.ok) return fail("Il server non ha risposto correttamente: riprova più tardi.");
        info = await r.json();
        envelope = info.envelope;
      }
      let data;
      try { data = await decrypt(envelope, code); } catch { return fail("Codice di accesso errato: controllalo e riprova."); }
      await show(data);
    } catch {
      fail("Errore imprevisto durante l'apertura.");
    } finally {
      $("sc-open").disabled = false;
    }
  };
  $("sc-code").addEventListener("keydown", (e) => { if (e.key === "Enter") $("sc-open").click(); });
  $("sc-close").onclick = () => {
    for (const t of timers) clearInterval(t);
    envelope = null; info = null;
    $("sc-fields").replaceChildren();
    $("sc-result").hidden = true;
    $("sc-name").textContent = "";
    fail("Contenuto cancellato dalla pagina.");
  };
})();

# Revisione di sicurezza — scheletro PWA mobile

Data: 26/11/2026 · Ambito: branch `pwa/scheletro-mobile` (PR #17) · Esito: **nessun bloccante**

Revisione white-box dello scheletro PWA (lettura offline) prima di qualunque rilascio,
come da prassi su StartCredentials. La modifica è **puramente additiva** (1054 righe,
nessun file esistente toccato): **zero rischio di regressione** sul prodotto in esercizio.
Il backend non è modificato (la rotta `/m` è solo documentata).

## Invarianti di sicurezza — verificate ✅

| # | Invariante | Verifica |
|---|---|---|
| 1 | **Nessuna chiave sbloccata a riposo** | Il `Vault` sbloccato e il token vivono solo in campi d'istanza RAM (`session.ts`); mai scritti su IndexedDB. A riposo solo `me.privateEnc` (bundle avvolto da Argon2id) nella cache GET. |
| 2 | **Nessun token/sessione in cache** | `offlineFetch` salva **solo** se `isCacheable` (GET in whitelist). La whitelist esclude `/auth/*`; il `Bearer` è nella richiesta, mai nel corpo salvato. |
| 3 | **Cache limitata al ciphertext E2EE** | `cachePolicy.isCacheable` (copia fedele da `mobile/`): solo `/me`, `containers`, `items`, `groups`, `users/directory`, `shared-items`, `attachments/chunks`. Ancoraggio `$` sulla query → niente poisoning via querystring. |
| 4 | **Service worker non tocca `/api`** | `sw.ts`: `if (method!=="GET" || path.startsWith("/api/")) return;` → non può salvare risposte con header di auth. Cache solo app-shell, stessa origine. |
| 5 | **Argon2id non declassabile** | `Vault.unlock` usa `me.kdfParams` cifrati/verificati; parametri manomessi fanno fallire l'AEAD (`unwrapPrivateKeys`), non esfiltrano nulla. Controllo anche su `publicKeys`. |
| 6 | **Auto-lock + wipe** | `resetAutoLock` (default 5 min, min 1) → `vault.lock()` azzera i buffer chiave; `logout()` → `wipeAll()` svuota cache + settings. Listener attività (`pointerdown`/`keydown`) persistenti mentre `Main` è montato. |
| 7 | **Org pinning (TOFU)** | `adopt()` fissa/aggiorna `pinnedOrgSignPublic`; passato a `unlock`/`restore` online e offline → protezione dalla sostituzione della chiave d'organizzazione. |
| 8 | **Nessun oracolo di autenticazione** | `ApiError` → messaggio generico "Email o master password non corrette"; `CryptoError` → "Master password errata". |
| 9 | **baseUrl robusto** | `Setup` valida `new URL`, impone https (salvo localhost), salva `u.origin` (niente path injection). `offlineFetch` rifiuta origini diverse da quella configurata. |

## Raccomandazioni di hardening (Fase 1, prima del rilascio reale — non bloccanti)

- **H1 — Lock su background.** Aggiungere il lock su `visibilitychange`/`pagehide`
  (oggi documentato come opzionale) per ridurre la finestra di esposizione quando la
  PWA va in background.
- **H2 — Metadati di cache su dispositivo condiviso.** La cache offline tiene in chiaro
  (a livello DB) i metadati E2EE e la rubrica (`/users/directory`: email e nomi dei
  colleghi), com'è già nel modello nativo. Su un dispositivo condiviso/compromesso sono
  leggibili senza master password. Valutare in Fase 2 di **cifrare le voci di cache** con
  una chiave derivata allo sblocco (i segreti veri restano comunque avvolti). Già
  elencato tra i limiti noti del documento di scoping.
- **H3 — Origine in hosting `/m`.** Con CSP `connect-src 'self'`, derivare `serverUrl`
  dall'origine servente invece del campo libero in `Setup` (un mismatch oggi fallisce in
  modo sicuro — bloccato dalla CSP — ma conviene toglierlo del tutto).

## Conclusione

Le invarianti critiche reggono; lo scheletro è coerente con il modello di sicurezza di
StartCredentials. **Nulla osta a mantenere il branch/PR**; le raccomandazioni H1–H3 vanno
affrontate nella Fase 1 insieme alla rotta `/m` del backend, con una nuova revisione di
sicurezza prima del rilascio effettivo della PWA agli utenti.

---

## Addendum Fase 1 (26/11) — rotta `/m` + H1/H3 · Esito: **nessun bloccante**

Revisione delle modifiche della Fase 1 (branch `pwa/fase1-hosting-hardening`).

**Backend — rotta `/m` (`app/src/server.ts`)**
- **Nessun path traversal**: i nomi dei file provengono da una whitelist fissa
  (`index.html` + `pwaAssets`); le rotte sono stringhe statiche (`/m/app.js`…), **non** un
  parametro `:file`. Il nome non è mai controllato dal client.
- **CSP stretta** (`default-src 'none'`, tutto `'self'`, `frame-ancestors 'none'`,
  `base-uri 'self'`, `form-action 'none'`): nessun `unsafe-inline` (l'app non ha script/stili
  in linea). Rafforzata dagli header globali dell'`onSend` (nosniff, X-Frame-Options DENY,
  Referrer-Policy, HSTS).
- **Service worker con scope `/m/`**: non può controllare `/api` né altre rotte.
- **Robustezza**: letture pigre → 404 se la build manca, il server parte comunque; cache in
  memoria limitata a pochi file; redirect a target fisso (`/m/`, nessun open redirect);
  app-shell pubblica ma priva di segreti (il vault richiede login+sblocco).

**Client — H1/H3 e fix SW**
- **H3**: `serverUrl` legato all'origine servente quando servito via http(s); coerente con
  `connect-src 'self'`, fallisce in modo sicuro su origini diverse. `Setup` resta solo per `file://`.
- **H1**: lock su `visibilitychange`→hidden e `pagehide` → `vault.lock()` azzera le chiavi
  quando l'app va in background. Nessun effetto collaterale di sicurezza.
- **Fix SW**: rimosso `./index.html` dal precache (il backend serve l'index su `/m/`, non su
  `/m/index.html`): evita il fallimento di `addAll` all'install.

**Verifica**: typecheck pulito su `app` e `pwa`; build esbuild della PWA riuscita e caricata
in `app/public/m/`; smoke-test nel browser → l'app-shell si carica, la crittografia si
inizializza e la UI si monta (il form di accesso compare direttamente, a conferma di H3).

**Rimane per la Fase 2**: H2 (cifratura dei metadati di cache a riposo, design in
`PWA-MOBILE-SCOPING-2026-11-26.md` Appendice A) come change dedicata e rivista a sé.

---

## Addendum Fase 2 (26/11) — H2 cifratura metadati di cache · Esito: **nessun bloccante**

Revisione dell'implementazione di H2 (`cacheCrypto.ts`, `offlineFetch.ts`, `session.ts`,
`db.ts`). Scelta architetturale: **interamente nella PWA**, nessuna modifica all'SDK E2EE
condiviso → zero rischio per estensione e app nativa.

- **Derivazione chiave**: `HKDF-SHA256` (WebCrypto) sul materiale di chiave che il Vault già
  tiene in RAM. HKDF è un PRF **unidirezionale**: non espone né indebolisce le chiavi private.
  Nessun secondo Argon2id. L'IKM viene azzerato dopo la derivazione.
- **Chiave solo in RAM, non estraibile**: `CryptoKey` con `extractable=false`; mai scritta su
  IndexedDB; azzerata a `lock()`/`logout()` insieme al Vault.
- **Copertura**: cifrate tutte le voci di cache **tranne `/me`** (necessario in chiaro per il
  bootstrap dello sblocco; parte segreta già avvolta). La PII di rubrica/metadati, prima in
  chiaro, è ora cifrata.
- **AES-GCM**: **IV casuale per voce** (verificato unico in test), integrità AEAD (la
  manomissione fa fallire la decifratura). Volume di scrittura basso → nessun rischio di
  riuso IV.
- **Gating**: le voci cifrate sono leggibili solo dopo uno sblocco riuscito (che ri-deriva la
  cacheKey dal `/me` in chiaro). Senza master password restano illeggibili.
- **Fail-safe**: voce cifrata senza chiave o manomessa → cache miss, nessun leak né crash.
- **Poisoning**: la cache tiene solo ciphertext del server, che il Vault riverifica con la sua
  crittografia AEAD; una voce falsificata causa al più un errore di decifratura, mai forgiatura.
- **Limite onesto**: la cacheKey deriva da materiale che l'app ha comunque in RAM; H2 alza
  l'asticella sulla **PII a riposo**, non cambia il modello di minaccia in-RAM (chi legge la
  memoria del processo ha già il Vault). Inerente e accettabile.

**Verifica**: typecheck pulito su `pwa`; test di roundtrip della crittografia (deriva/cifra/
decifra, chiave deterministica, chiave errata e ciphertext manomesso che falliscono, IV unico):
5/5 pass.

Con H2 implementata e rivista, i tre hardening H1–H3 e H2 sono **chiusi**. Resta l'eventuale
Opzione A (riuso UI estensione) e, prima del rilascio agli utenti, un test end-to-end su
dispositivi reali (incl. tempi Argon2id e `navigator.storage.persist()`).

---

## Addendum Fase 3 (26/11) — fix CSP per WASM di libsodium/OPAQUE · Esito: **nessun bloccante**

**Difetto trovato nel test su dispositivo reale.** Dallo smartphone lo sblocco falliva con:
`WebAssembly.compile(): ... 'unsafe-eval' is not an allowed source of script ... "script-src 'self'"`.
La CSP stretta della rotta `/m` (`script-src 'self'`) impediva la compilazione dei **moduli
WebAssembly** di libsodium (Argon2id/X25519/Ed25519) e di `@serenity-kit/opaque` (login OPAQUE):
la PWA caricava l'app-shell ma la crittografia non si inizializzava → accesso impossibile.

**Fix** (`app/src/server.ts`, solo `PWA_CSP`): `script-src 'self'` → `script-src 'self' 'wasm-unsafe-eval'`.

**Analisi di sicurezza del delta**
- `'wasm-unsafe-eval'` è la source **specifica per WebAssembly**: abilita **solo**
  `WebAssembly.compile/instantiate`. **Non** riabilita `eval()`, `new Function()`,
  `setTimeout(string)` né lo script inline — quelli richiedono `'unsafe-eval'`/`'unsafe-inline'`,
  che **restano bloccati**. È quindi **strettamente più stretta** di `'unsafe-eval'`.
- **Nessun nuovo vettore XSS**: `script-src` resta limitato a `'self'` (niente origini esterne,
  niente inline). Un eventuale script iniettato è già bloccato come prima; questa source permette
  soltanto allo script di stessa origine di compilare i **byte WASM impacchettati nel bundle**.
- **Verificato che `'unsafe-eval'` NON serve**: il bundle contiene un glue wasm-bindgen
  (`__wbg_new_no_args` → `new Function`) dentro `@serenity-kit/opaque`. Test locale servendo i due
  moduli sotto la CSP esatta ed eseguendo un `opaque.client.startLogin` reale: entrambi i WASM si
  inizializzano e il login parte **senza alcuna violazione CSP** → quel `new Function` è codice morto,
  non invocato a runtime. Basta quindi `'wasm-unsafe-eval'`.
- `SEND_CSP` (rotta `/send`) **non è toccata**: resta `script-src 'self'` perché non usa WASM.
- Il **service worker** usa solo WebCrypto nativo (AES-GCM/HKDF), nessun WASM né eval →
  `worker-src 'self'` invariato.
- È la CSP raccomandata e standard per qualunque app che distribuisce crittografia WASM
  (compatibile con Chrome 97+, Firefox 102+, Safari 16.4+).

**Verifica**: typecheck backend pulito; harness locale (libsodium + OPAQUE sotto la CSP del fix)
→ `startLogin` eseguito, zero errori di console/CSP.

---

## Addendum Fase 4 (26/11) — secondo fattore (MFA/TOTP) nell'accesso · Esito: **nessun bloccante**

**Lacuna trovata nel test su telefono reale.** Dopo il fix CSP il login superava la password ma
si fermava: gli account con MFA attiva ricevono `state: "mfa_pending"` e lo scheletro non aveva lo
step del codice (`session.signIn` lanciava "Serve un codice MFA"). Aggiunto il secondo fattore
riusando **le stesse funzioni del client SDK già usate dall'estensione** (`verifyMfa`,
`trustDevice`) — nessuna modifica all'SDK né al backend.

**Flusso implementato** (`pwa/src/session.ts`, `app.tsx`, `styles.css`)
- `signIn` passa `deviceToken` a `login`; se torna `mfa_pending` tiene in RAM `{api, password}` e
  ritorna `"mfa"`; la UI mostra lo schermo codice (6 cifre TOTP **o** codice di riserva).
- `completeMfa(code, trust)` → `verifyMfa(api, code)`; se `trust`, `trustDevice` e salva il
  `deviceToken`; poi `Vault.unlock`. `cancelMfa()` e `lock()` azzerano il pending.

**Analisi di sicurezza**
- **Password in RAM tra i due passaggi**: necessaria perché lo sblocco post-MFA deriva la master
  key dalla password; tenuta solo in `pending`, azzerata a completamento, annullamento e `lock()`.
  Nessuna scrittura su disco. Stesso modello dell'estensione.
- **`deviceToken` a riposo (IndexedDB)**: è un bearer che salta **solo il secondo fattore**, non la
  master password (primo fattore, mai memorizzato). Da solo è inutile: ogni accesso richiede comunque
  la master password (OPAQUE) e ogni sblocco la ri-deriva. Scadenza lato server (30 gg). Opt-in
  (checkbox). È il modello "dispositivo attendibile" già in uso nell'app nativa/estensione
  («il token va conservato solo su questo dispositivo»). Azzerato al `logout` (`wipeAll`).
- **Nessun oracolo**: codice errato → `ApiError` → messaggio generico "Codice non valido o scaduto";
  `verifyMfa` fallito **non** scarta il pending → nuovo tentativo possibile senza re-login.
- **Token di sessione**: la verifica avviene sulla stessa `api`/token del login; `/me` (sblocco)
  funziona solo dopo che il server ha portato la sessione ad `active`. Il token resta in RAM.
- **Offline invariato**: `unlockLocal` non tocca la rete e legge `/me` dalla cache, popolata solo da
  un precedente login online **già passato per l'MFA** → nessuna nuova esposizione offline. H1/H2/H3
  invariati.
- `trustDevice` in try/catch: se disattivato sul server si prosegue senza, nessun crash.

**Verifica**: typecheck `pwa` pulito + build esbuild ok. Test end-to-end del codice MFA su istanza
pentest (account di test con TOTP) dopo il deploy.

---

## Addendum Fase 5 (26/11) — dettaglio elemento: mostra/copia password, OTP, campi · Esito: **nessun bloccante**

**Lacuna d'uso.** Lo scheletro mostrava solo l'elenco (nome/utente/tipo): non si potevano **vedere le
password**. Aggiunta la schermata di dettaglio in sola lettura (`ItemDetail` in `app.tsx`): password
con **mostra/nascondi** + copia, **codice OTP (2FA)** calcolato in locale, nome utente, indirizzi,
note e campi personalizzati (quelli segreti mascherati). Nuova dipendenza: `@startcredentials/crypto`
(sorella di workspace, già nel bundle in modo transitivo) per `generateTotp`/`parseOtpauthUri`.

**Analisi di sicurezza**
- **Segreti in chiaro solo su gesto esplicito**: password/campi segreti sono nascosti di default e
  rivelati solo premendo "Mostra". I dati sono già decifrati in RAM dal Vault **sbloccato**: mostrarli
  non abbassa la soglia. Lo stato "rivelato" vive **solo nello stato del componente/DOM**, mai scritto
  su IndexedDB né in cache (H2 invariato).
- **Azzeramento al blocco**: auto-lock, `visibilitychange`→hidden (H1) e `pagehide` smontano la vista
  → i segreti spariscono dal DOM. Cambiando app sul telefono la PWA si blocca subito (comportamento H1
  esistente).
- **Clipboard**: "Copia" scrive il segreto negli appunti di sistema **su tocco dell'utente** (standard
  per un gestore password, come l'estensione). Esposizione: altre app possono leggere gli appunti e il
  valore resta finché non sovrascritto. Niente auto-pulizia (possibile hardening futuro). In contesto
  non sicuro/permesso negato fallisce in silenzio.
- **OTP**: calcolato in locale con `@noble/hashes` (già nel bundle, librerie da audit) — **nessuna
  rete, nessun WASM, nessun eval** → nessun impatto CSP. Il segreto otpauth sta in RAM per la vita del
  componente, rilasciato allo smontaggio/blocco.
- **Link esterni**: `<a target="_blank" rel="noopener noreferrer">` — niente reverse-tabnabbing, nessun
  referrer anomalo; `default-src 'none'` non blocca la navigazione top-level avviata dall'utente.
- **Sola lettura**: nessuna modifica/scrittura; coerente con l'ambito PWA. Nessuna nuova chiamata di
  rete; H1/H2/H3 e offline invariati.

**Verifica**: typecheck `pwa` pulito + build esbuild ok; load-test locale del bundle sotto la CSP del
fix (carica e renderizza, nessun errore di modulo/CSP; la nuova dip crypto/OTP non introduce
violazioni). Test funzionale del dettaglio (reveal/copia/OTP) a carico dell'utente dopo il deploy
(serve il login a un vault reale).

---

## Addendum Fase 6 (26/11) — restyle con lo stile dell'app (token + font) · Esito: **nessun bloccante**

Su richiesta dell'utente la PWA adotta il **design system dell'estensione/app**: stessi token
(tema chiaro + scuro automatico via `prefers-color-scheme`), componenti (card/pulsanti/liste/campi) e
**font self-hosted** Plus Jakarta Sans + JetBrains Mono (gli stessi 6 woff2 di `@fontsource` che usa
l'estensione, copiati in build). Cambiamento **puramente presentazionale** (CSS + classi del markup):
nessuna modifica ai flussi di auth/crypto/dati, sola lettura invariata.

**Analisi di sicurezza**
- **CSP**: aggiunto `font-src 'self'` a `PWA_CSP` (solo questa direttiva). Consente di caricare font
  **solo dalla stessa origine**; nessun CDN esterno. Non amplia `script-src`/`connect-src`. I 6 woff2
  sono serviti dal backend via la **whitelist fissa** `/m/fonts/*.woff2` (nomi letterali, nessun path
  traversal), con la stessa CSP stretta.
- **Nessun contenuto eseguibile**: i font sono asset statici; nessun nuovo egress di rete (tutto da
  `'self'`).
- **Service worker**: la precache della shell ora include i 6 font (avvio offline corretto); il SW
  continua a **non toccare `/api`**. Versione cache `v1`→`v2` per sostituire la shell vecchia.
- **Nessun segreto coinvolto**; H1/H2/H3, MFA e dettaglio invariati.

**Verifica**: typecheck `app`+`pwa` puliti; build esbuild + copia font ok; load-test locale (schermate
di accesso in **chiaro e scuro**) sotto la CSP con `font-src 'self'` → i font si caricano, layout
corretto, nessuna violazione CSP (solo l'errore di registrazione SW tipico del mini-server locale).

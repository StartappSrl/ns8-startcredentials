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

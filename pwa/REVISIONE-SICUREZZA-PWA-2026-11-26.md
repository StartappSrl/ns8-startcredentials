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

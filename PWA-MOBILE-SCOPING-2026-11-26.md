# StartCredentials — Web-app mobile (PWA) con lettura offline

Documento di scoping e architettura — 26/11/2026

## 1. Obiettivo

Offrire una **web-app responsive installabile** (PWA) usabile dal telefono al posto
dell'app nativa Expo/React Native (`mobile/`), mantenendo la **lettura offline** del
vault. La web-app è servita dal backend Fastify esistente (`app/`) e riusa l'SDK E2EE
isomorfico `packages/client` — lo stesso che già gira nel browser dentro l'estensione
Chrome. **La cifratura non si reinventa.**

La fattibilità è alta: i pezzi grossi esistono già e sono testati.

| Pezzo | Dove | Riuso per la PWA |
|---|---|---|
| SDK E2EE (OPAQUE, X25519/Ed25519, Argon2id, libsodium/wasm) | `packages/client` | **Diretto** — già browser-ready |
| UI vault completa (Preact) | `extension/src/ui` | Adattabile (vedi §3) |
| Backend + ~90 endpoint `/api/v1` | `app/` | Diretto + 1 rotta statica nuova |
| Whitelist cache offline | `mobile/src/engine/cachePolicy.ts` | **Diretto** (`isCacheable`) |
| Modello sblocco/cache offline | `mobile/src/engine/` | Riadattato da SecureStore/file a IndexedDB |

Il nodo non è la crittografia (risolta), ma **il modello offline/unlock locale** e i
**limiti strutturali di una PWA** rispetto a un'app nativa (§7).

## 2. Perché è già quasi tutto pronto: il bundle chiavi è già avvolto

La scoperta che rende semplice lo sblocco offline: il bundle delle chiavi private
dell'utente è **già** avvolto da `Argon2id(master password)` e disponibile in lettura
in `/me`.

```ts
// packages/client/src/vault.ts
export interface Me {
  id: string; …; publicKeys: PublicKeys;
  privateEnc: string;   // ← bundle chiavi private sigillato con la master key
  kdfParams: KdfParams; // ← parametri Argon2id per ri-derivare la master key
  …
}

static async unlock(api, password, opts): Promise<Vault> {
  const me = await api.get<Me>("/me");          // ← serve offline dalla cache
  const mk = deriveMasterKey(password, me.kdfParams);
  const keys = unwrapPrivateKeys(mk, me.privateEnc, me.id, me.keyVersion);
  …
}
```

Quindi **non serve re-inventare né re-avvolgere nulla**: lo sblocco offline è lo stesso
`Vault.unlock`, con l'unica differenza che `/me` viene servito dalla cache locale invece
che dalla rete. `deriveMasterKey` (Argon2id) e `unwrapPrivateKeys` sono puro
calcolo client-side → funzionano senza rete. È esattamente il modello del motore nativo
(`mobile/src/engine/Engine.tsx`, `doFetch`): wrap del `fetch`, su errore di rete le GET
in whitelist vengono servite dalla copia salvata (ciphertext).

`Api` accetta un `fetch` iniettabile (`packages/client/src/api.ts`), quindi l'aggancio è
pulito: `new Api({ baseUrl, token, fetch: offlineFetch })`.

## 3. UI: due opzioni

### Opzione A — Riuso dell'intera UI Preact dell'estensione (consigliata a regime)
`extension/src/app.tsx` + `extension/src/ui/*` sono già una web-app vault completa in
Preact (lista clienti, elementi, generatore, ricerca, salute, admin…). L'unico
accoppiamento alla piattaforma è `extension/src/shared.ts`, che usa `chrome.storage.*`.

**Piano**: estrarre da `shared.ts` un'interfaccia `Platform` (storage settings, storage
sessione, clipboard) con due implementazioni — `chrome.*` per l'estensione, IndexedDB +
RAM per la PWA. L'albero UI resta identico. Costo medio, massimo riuso, un'unica UI da
mantenere. Da fare dopo lo scheletro.

### Opzione B — UI minimale sopra `packages/client` (per lo scheletro / questa fase)
Una PWA standalone snella (setup → login → unlock → lista read-only), costruita
direttamente sull'SDK, con un proprio layer di storage. È ciò che implementa lo scheletro
in `pwa/` (§6): dimostra end-to-end hosting, manifest, service worker, cache offline e
sblocco locale senza trascinare tutta la UI admin.

**Raccomandazione**: B ora (scheletro di validazione), A come evoluzione (parità di
funzioni di lettura con l'estensione), riusando il layer `Platform`.

> ⚠️ Non confondere con `ui/` (UI admin del modulo NS8 in Vue/Carbon): non è per
> l'utente finale e non c'entra con questa web-app.

## 4. Architettura

```
┌─────────────────────── telefono (browser / PWA installata) ───────────────────────┐
│  App shell (HTML/JS/CSS)  ──precache──►  Service Worker  (solo shell, mai /api)     │
│                                                                                     │
│  Preact UI  ─►  @startcredentials/client (Vault)  ─►  Api({ fetch: offlineFetch })  │
│                      │                                        │                      │
│                      │ unlock/lock (chiavi SOLO in RAM)       │ GET in whitelist     │
│                      ▼                                        ▼                      │
│            master password (Argon2id)              IndexedDB: ciphertext E2EE        │
│                                                    + `me` avvolto + settings         │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                        │ online: fetch reale
                                        ▼
                         Fastify `app/`  ──►  /api/v1/*  +  /m (app shell, CSP stretta)
```

Due archivi locali, con responsabilità separate (scelta di sicurezza, §8):

- **Service Worker + Cache API** → *solo* app-shell (HTML/JS/CSS/manifest/icone).
  Garantisce installabilità e avvio offline. **Non intercetta né cacha mai `/api/v1/*`**:
  così non può salvare per errore una risposta con header di autenticazione.
- **IndexedDB (gestita dal fetch-wrapper in pagina)** → dati E2EE:
  - risposte **GET in whitelist** (`isCacheable`, §5) — ciphertext, identico al server;
  - `me` (bundle `privateEnc` avvolto + `kdfParams` + `publicKeys`) per lo sblocco offline;
  - settings **non segreti** (serverUrl, email, `pinnedOrgSignPublic`, autoLockMinutes).

Il **Vault sbloccato (chiavi in chiaro) vive solo in una variabile JS (RAM)**, mai
persistito. Ad ogni refresh/riapertura serve un nuovo unlock. Più restrittivo del nativo
(che può tenere una sessione sbloccata in Keystore dietro biometria).

## 5. Lettura offline — cache

La whitelist è **riusata tale e quale** da `mobile/src/engine/cachePolicy.ts`:

```ts
const CACHEABLE = /^\/api\/v1\/(me|me\/devices|containers|containers\/<uuid>|
  containers\/<uuid>\/items(\?trash=1)?|users\/directory|shared-items|groups|
  items\/<uuid>\/versions|attachments\/<uuid>\/chunks\/\d+)$/;
export const isCacheable = (method, pathAndQuery) => method === "GET" && CACHEABLE.test(…);
```

Sono **solo GET che restituiscono ciphertext E2EE**: nessun endpoint `/auth/*`, nessun
token, nessuno stato di sessione. Il `fetch` iniettato nell'`Api`:

1. online → `fetch` reale; se la risposta è OK **e** `isCacheable` → salva il body in IndexedDB;
2. errore di rete → se `isCacheable` e c'è una copia salvata, la restituisce; altrimenti errore.

Identico a `Engine.doFetch` nativo. La decifratura è client-side → la lista vault e gli
elementi sono leggibili offline una volta sbloccato.

> Nota: per evitare di dipendere da due copie della regex, nello scheletro `cachePolicy.ts`
> è duplicato in `pwa/src/`. A regime conviene **spostare `cachePolicy.ts` in
> `packages/client`** ed importarlo sia da `mobile/` sia da `pwa/` (fonte unica).

## 6. Sblocco offline — dettaglio e ciclo di vita della chiave

**Primo accesso (online):** setup serverUrl → `login` OPAQUE (online-only) → eventuale
MFA → `Vault.unlock(password)`. Durante l'uso online, ogni GET in whitelist popola la
cache; al termine `/me` è in IndexedDB.

**Riapertura offline:** l'utente inserisce la master password → `Vault.unlock` gira con
l'`offlineFetch`, che serve `/me` dalla cache → `deriveMasterKey` (Argon2id) +
`unwrapPrivateKeys` in locale → Vault in RAM. Password errata → `CryptoError` →
"Master password errata" (nessun oracolo lato server, com'è giusto in E2EE).

**A riposo** non c'è mai: né la master key derivata, né le chiavi sbloccate. Solo il
bundle `privateEnc` **avvolto** (inutile senza la master password) e ciphertext.

**Auto-lock:** timer sull'ultima attività (default conservativo, es. 5 min); allo scadere
`vault.lock()` (azzera le chiavi in RAM, come già fa il metodo) + si abbandona il
riferimento. Lock anche su `visibilitychange`/`pagehide` opzionale.

**Logout / cambio server / disattivazione offline:** `vault.lock()` + **wipe IndexedDB**
(ciphertext + `me`) + rimozione token. Equivalente a `wipeOffline()` nativo.

**Org pinning (TOFU):** `pinnedOrgSignPublic` nei settings, passato a `unlock`/`restore`
come fa l'estensione — protegge dalla sostituzione della chiave d'organizzazione.

## 7. Scritture — fase 1 online-only, fase 2 outbox

In **v1 le scritture sono online-only**. Motivo: l'audit a catena di hash e la
rotazione/condivisione delle chiavi sono **server-authoritative** (richiedono risposta
del server per numero di revisione, concatenamento audit, versioni chiave). Offline si
mostra un banner "sola lettura — nessuna rete".

**Fase 2 (documentata, non implementata):** coda di sincronizzazione (*outbox*) in
IndexedDB per le operazioni semplici e idempotenti (es. modifica dati di un elemento su
cui si ha permesso `manage`), con:
- conflict detection sul `revision` dell'elemento (rifiuto + merge manuale se cambiato);
- rigiocata in ordine alla riconnessione;
- esclusione esplicita delle operazioni che toccano chiavi/condivisioni/audit (restano
  online-only).
Da valutare solo dopo aver misurato il reale bisogno: aggiunge superficie e complessità.

## 8. Limiti noti (da comunicare all'utente)

| Limite | Dettaglio | Mitigazione |
|---|---|---|
| **Niente autofill** | Una PWA non può registrarsi come Android Autofill Service né iOS Credential Provider. | Copia/incolla e share-sheet (Web Share). Autofill resta appannaggio dell'estensione (desktop) o di un'app nativa. |
| **Storage evictabile** | IndexedDB può essere sfrattata dal SO. iOS: eviction ~7 gg per PWA **non installate**. | Richiedere `navigator.storage.persist()` (concesso di norma dopo l'installazione su Android); invitare l'utente a **installare** la PWA; i dati offline sono comunque ri-scaricabili online. |
| **Chiave a riposo meno protetta** | Niente Secure Enclave/Keystore/StrongBox: a riposo c'è solo il bundle avvolto da Argon2id, non una chiave hardware-protetta. | A riposo **nessuna chiave sbloccata**; unlock con master password ad ogni apertura. Fase 2: **WebAuthn/passkey** per gating biometrico di una sessione avvolta (sblocco "comodo" senza ridigitare la master password, protetto dall'autenticatore del dispositivo). |
| **Nessun background nativo** | Niente sync in background affidabile, niente notifiche push senza setup. | Non necessario per sola lettura. |
| **iOS: PWA limitata** | Storage e install più fragili su iOS/Safari. | Documentare; su iOS l'esperienza migliore resta Safari "Aggiungi a Home". |

## 9. Hosting nel backend

Si riusa il pattern delle pagine statiche di `app/src/server.ts` (vedi la pagina `/s`
degli invii sicuri): file serviti con **CSP stretta per-rotta**.

- Nuova rotta `GET /m` (+ asset `/_m/*`) che serve l'app-shell della PWA.
- CSP proposta: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
  connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none';
  base-uri 'none'; form-action 'none'`.
- `connect-src 'self'` presuppone PWA e API **sulla stessa origine** del modulo NS8
  (è il caso: Fastify serve entrambe). Niente CORS, niente origini esterne.
- `manifest.webmanifest`, `sw.js` serviti da `'self'`; il SW ha scope `/m`.
- Build esbuild come l'estensione (`extension/build.mjs`: bundle ESM, `node-stubs` per
  libsodium/kdbxweb, font woff2), output in `pwa/dist/`, copiato/servito da Fastify.

## 10. Piano a fasi

**Fase 0 — Scheletro (questa consegna, in `pwa/`)**
Build esbuild · manifest installabile · service worker (solo shell) · fetch-wrapper +
IndexedDB (whitelist cache) · pagina di unlock locale · lista vault read-only · auto-lock
· wipe su logout. Serve a validare hosting, offline e sblocco end-to-end. *Non rilasciato.*

**Fase 1 — PWA di lettura completa**
Rotta `/m` nel backend con CSP · `navigator.storage.persist()` · gestione MFA/trust
device nel login · dettaglio elemento read-only con copia negli appunti a scadenza ·
estrazione del layer `Platform` da `extension/src/shared.ts` e **riuso dell'UI Preact**
dell'estensione (Opzione A) · icone/splash.

**Fase 2 — Comodità e scrittura**
WebAuthn/passkey per sblocco biometrico (sessione avvolta) · outbox di scrittura
idempotente con conflict detection · Web Share / copia rapida.

**Prima di qualunque rilascio — revisione di sicurezza (obbligatoria).** Focus:
1. bundle avvolto in IndexedDB: a riposo solo ciphertext, mai chiavi sbloccate né mk;
2. parametri Argon2id = quelli del server (`me.kdfParams`), nessun downgrade;
3. auto-lock effettivo + `vault.lock()` che azzera la RAM + wipe IndexedDB su logout;
4. **nessun** dato di auth/sessione in cache (solo `isCacheable`); SW non tocca `/api`;
5. CSP stretta, stessa origine, `connect-src 'self'`;
6. org pinning (TOFU) rispettato anche offline.

## 11. Rischi / aperti

- **Argon2id su telefoni lenti**: 256 MiB possono richiedere secondi (il nativo usa timeout
  120 s). In PWA il calcolo è nel main thread/wasm → spostarlo in un **Web Worker** per non
  bloccare la UI. Da verificare su dispositivi reali.
- **Fonte unica della whitelist**: spostare `cachePolicy.ts` in `packages/client` (evita
  divergenze tra `mobile/` e `pwa/`).
- **iOS eviction**: accettare che offline su iOS sia "best effort"; i dati sono comunque
  rigenerabili online.
- **Parità UI**: decidere presto se puntare all'Opzione A (riuso UI estensione) per non
  mantenere due interfacce.

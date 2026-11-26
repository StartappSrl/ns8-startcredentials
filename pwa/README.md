# @startcredentials/pwa — scheletro web-app mobile (lettura offline)

Scheletro di validazione della PWA mobile descritta in
[`../PWA-MOBILE-SCOPING-2026-11-26.md`](../PWA-MOBILE-SCOPING-2026-11-26.md).
Dimostra end-to-end: hosting, manifest installabile, service worker (solo app-shell),
cache offline E2EE in IndexedDB, **sblocco locale** con la master password e **lista
vault in sola lettura**, sopra `@startcredentials/client`. **Non è un prodotto rilasciabile**
(manca MFA/trust device, dettaglio elemento, icone definitive; serve la revisione di
sicurezza prima di qualunque rilascio).

## Struttura

| File | Ruolo |
|---|---|
| `src/app.tsx` | UI Preact: setup → accesso → sblocco → lista (read-only) + auto-lock |
| `src/session.ts` | Vault sbloccato **solo in RAM**; login OPAQUE, unlock online/offline, lock, logout+wipe |
| `src/offlineFetch.ts` | `fetch` iniettato nell'Api: cache delle GET in whitelist, fallback offline |
| `src/cachePolicy.ts` | whitelist `isCacheable` (copia da `mobile/`; a regime spostarla in `packages/client`) |
| `src/db.ts` | IndexedDB: solo ciphertext + bundle avvolto + settings non segreti |
| `src/sw.ts` | service worker: solo shell, **non tocca `/api`** |
| `static/` | `index.html`, `manifest.webmanifest`, `styles.css`, `icon.svg` |

## Comandi

```sh
npm run typecheck   # tsc --noEmit
npm run build       # typecheck + bundle in dist/
```

Lo scheletro non è ancora nei `workspaces` della root. Per compilarlo/pacchettizzarlo
aggiungere `"pwa"` ai workspaces e lanciare `npm install` una volta (risolve `esbuild`).
Il **typecheck** gira già con i pacchetti hoistati (`preact`, `@startcredentials/client`).

## Collegamento al backend — rotta `/m` (implementata)

Il backend serve l'app-shell sotto **`/m/`** con CSP stretta, stessa origine dell'API
(niente CORS). Vedi `app/src/server.ts` (`PWA_CSP`, rotte `/m`, `/m/`, `/m/<asset>`):

- `/m` → redirect 301 a `/m/` (base con slash finale: le risorse relative si risolvono sotto `/m/`);
- `/m/` → `index.html`; `/m/app.js`, `/m/sw.js`, `/m/styles.css`, `/m/manifest.webmanifest`, `/m/icon.svg`;
- lettura pigra da `app/public/m/` con cache in memoria e **404 se la build manca** (il server parte comunque);
- il service worker servito a `/m/sw.js` ha scope `/m/`.

`npm run build` (in `pwa/`) genera `dist/` **e** lo copia in `app/public/m/`, da dove il
backend lo serve — stesso schema con cui l'estensione scrive il suo zip in `app/public`.
I file in `app/public/m/` sono **artefatti di build** (non versionati): vanno rigenerati
con `npm run build -w pwa` nel pipeline di deploy.

## Note di sicurezza (vedi §6/§10 del documento)

- A riposo c'è **solo** ciphertext: cache GET in whitelist + `me.privateEnc` (bundle avvolto
  da Argon2id). Mai chiavi sbloccate, mai master key, mai token.
- `offlineFetch` salva **solo** GET che superano `isCacheable`: niente `/auth/*`, niente sessioni.
- Il service worker **non intercetta `/api`**: non può salvare risposte con header di auth.
- Auto-lock (default 5 min) → `vault.lock()` azzera la RAM. Logout → `wipeAll()` svuota IndexedDB.
- Argon2id con `me.kdfParams` (gli stessi del server): nessun downgrade dei parametri.

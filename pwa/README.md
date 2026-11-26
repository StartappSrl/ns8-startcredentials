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

## Collegamento al backend (da aggiungere a `app/src/server.ts`)

Serve l'app-shell su `/m` con CSP stretta, stessa origine dell'API (niente CORS):

```ts
const PWA_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
  "connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const pwaDir = join(APP_ROOT, "..", "pwa", "dist");
const file = (n: string, type: string) =>
  app.get(`/m/${n}`, async (_r, reply) => reply.type(type).header("Content-Security-Policy", PWA_CSP).send(readFileSync(join(pwaDir, n))));
app.get("/m", async (_r, reply) => reply.type("text/html; charset=utf-8").header("Content-Security-Policy", PWA_CSP).send(readFileSync(join(pwaDir, "index.html"))));
file("app.js", "text/javascript; charset=utf-8");
file("sw.js", "text/javascript; charset=utf-8");          // scope "./": servilo sotto /m
file("styles.css", "text/css; charset=utf-8");
file("manifest.webmanifest", "application/manifest+json");
file("icon.svg", "image/svg+xml");
```

> Il backend è lasciato **intatto**: lo snippet va applicato e rivisto insieme alla
> revisione di sicurezza, non prima.

## Note di sicurezza (vedi §6/§10 del documento)

- A riposo c'è **solo** ciphertext: cache GET in whitelist + `me.privateEnc` (bundle avvolto
  da Argon2id). Mai chiavi sbloccate, mai master key, mai token.
- `offlineFetch` salva **solo** GET che superano `isCacheable`: niente `/auth/*`, niente sessioni.
- Il service worker **non intercetta `/api`**: non può salvare risposte con header di auth.
- Auto-lock (default 5 min) → `vault.lock()` azzera la RAM. Logout → `wipeAll()` svuota IndexedDB.
- Argon2id con `me.kdfParams` (gli stessi del server): nessun downgrade dei parametri.

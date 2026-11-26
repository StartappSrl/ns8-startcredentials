/**
 * Service worker: SOLO app-shell (HTML/JS/CSS/manifest/icona) per installabilità e
 * avvio offline. NON intercetta né mette mai in cache `/api/v1/*`: le risposte E2EE
 * e lo stato offline sono gestiti in pagina (IndexedDB, vedi offlineFetch.ts), così
 * il service worker non può salvare per errore una risposta con header di autenticazione.
 */
const sw = self as unknown as ServiceWorkerGlobalScope;

const CACHE = "sc-pwa-shell-v2";
// "./" è il documento (il backend serve l'index su /m/, non su /m/index.html).
const SHELL = [
  "./", "./app.js", "./styles.css", "./manifest.webmanifest", "./icon.svg",
  "./fonts/jakarta-400.woff2", "./fonts/jakarta-500.woff2", "./fonts/jakarta-600.woff2",
  "./fonts/jakarta-700.woff2", "./fonts/mono-400.woff2", "./fonts/mono-500.woff2",
];

sw.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => sw.skipWaiting()));
});

sw.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => sw.clients.claim()),
  );
});

sw.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  // Mai toccare l'API: lasciala passare direttamente alla rete (la gestisce offlineFetch).
  if (req.method !== "GET" || url.pathname.startsWith("/api/")) return;
  // Solo shell della stessa origine: cache-first con aggiornamento in background.
  if (url.origin !== sw.location.origin) return;
  e.respondWith(
    caches.match(req).then((hit) => {
      const net = fetch(req)
        .then((res) => {
          if (res.ok) void caches.open(CACHE).then((c) => c.put(req, res.clone()));
          return res;
        })
        .catch(() => hit ?? Response.error());
      return hit ?? net;
    }),
  );
});

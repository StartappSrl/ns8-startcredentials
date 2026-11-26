/**
 * Letture conservabili per l'uso offline: mai autenticazione né sessioni.
 *
 * Copia fedele di `mobile/src/engine/cachePolicy.ts`. A regime conviene spostare
 * questo file in `packages/client` e importarlo sia da `mobile/` sia da `pwa/`
 * per avere un'unica fonte di verità (vedi PWA-MOBILE-SCOPING-2026-11-26.md §5).
 */
const CACHEABLE = new RegExp(
  "^/api/v1/(me|me/devices|containers|containers/[0-9a-f-]{36}|containers/[0-9a-f-]{36}/items(\\?trash=1)?|" +
  "users/directory|shared-items|groups|items/[0-9a-f-]{36}/versions|attachments/[0-9a-f-]{36}/chunks/\\d+)$",
);
export const isCacheable = (method: string, pathAndQuery: string): boolean =>
  method === "GET" && CACHEABLE.test(pathAndQuery);

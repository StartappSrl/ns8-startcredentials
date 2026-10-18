/** Letture conservabili per l'uso offline: mai autenticazione né sessioni. */
const CACHEABLE = new RegExp(
  "^/api/v1/(me|me/devices|containers|containers/[0-9a-f-]{36}|containers/[0-9a-f-]{36}/items(\\?trash=1)?|" +
  "users/directory|shared-items|groups|items/[0-9a-f-]{36}/versions|attachments/[0-9a-f-]{36}/chunks/\\d+)$",
);
export const isCacheable = (method: string, pathAndQuery: string): boolean => method === "GET" && CACHEABLE.test(pathAndQuery);

// Ri-base UNA TANTUM della catena del registro, da eseguire all'aggiornamento
// da una versione che firmava il registro con SHA-256 non firmato alla nuova
// (HMAC). Senza, su un database esistente `audit/verify` segnalerebbe una
// manomissione sulle righe vecchie. Su una nuova installazione NON serve.
//
// Uso (sul nodo, con le stesse variabili d'ambiente del servizio):
//   npm run build && node scripts/rebase-audit.mjs
//
// IMPORTANTE: eseguire in una finestra fidata, NON dopo una sospetta
// manomissione (ri-baserebbe anche le modifiche di un attaccante).
import { loadConfig, createPool, rebaseAuditChain, verifyAuditChain } from "../dist/src/core.js";

const cfg = loadConfig();
const db = createPool(cfg.databaseUrl);
try {
  const before = await verifyAuditChain(db);
  const n = await rebaseAuditChain(db);
  const after = await verifyAuditChain(db);
  console.log(`Ri-base completata: ${n} righe. Verifica prima=${before.ok} dopo=${after.ok}`);
  if (!after.ok) {
    console.error("La verifica dopo la ri-base NON è ok: non proseguire con il rilascio.");
    process.exit(1);
  }
} finally {
  await db.end();
}

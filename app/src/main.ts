import { join } from "node:path";
import { createPool, loadConfig, migrate } from "./core.js";
import { APP_ROOT, buildApp } from "./server.js";

const cfg = loadConfig();
const db = createPool(cfg.databaseUrl);

// Il database può avviarsi dopo l'applicazione: riprova per 60 secondi.
for (let i = 0; ; i++) {
  try {
    await db.query("SELECT 1");
    break;
  } catch (e) {
    if (i >= 30) throw e;
    await new Promise((r) => setTimeout(r, 2000));
  }
}
await migrate(db, join(APP_ROOT, "migrations"));
const app = await buildApp(cfg, db);

// Pulizia periodica: sessioni scadute, cestino oltre 30 giorni, upload abbandonati.
const cleanup = async () => {
  try {
    await db.query("DELETE FROM sessions WHERE expires_at < now()");
    await db.query("DELETE FROM items WHERE deleted_at < now() - interval '30 days'");
    await db.query("DELETE FROM attachments WHERE status = 'uploading' AND created_at < now() - interval '1 day'");
    await db.query("UPDATE users SET invite_token_hash = NULL WHERE invite_expires_at < now() - interval '30 days'");
  } catch (e) {
    app.log.error(e);
  }
};
setInterval(cleanup, 3600_000).unref();
void cleanup();

const shutdown = async () => {
  await app.close();
  await db.end();
  process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

await app.listen({ host: "0.0.0.0", port: cfg.port });

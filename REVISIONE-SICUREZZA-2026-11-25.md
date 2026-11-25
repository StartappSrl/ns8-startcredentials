# StartCredentials 0.7.15 — Revisione di sicurezza white-box

**Data:** 25/11/2026 · **Versione analizzata:** 0.7.15 (repo `StartappSrl/ns8-startcredentials`, app 0.7.15, app Android 0.8.6) · **Tipo:** revisione white-box del codice sorgente, in sola lettura.

---

## Riepilogo per la direzione

La promessa centrale del prodotto — *«senza la chiave di un utente autorizzato nessuno legge le credenziali, nemmeno chi controlla il server»* — **regge**. Non abbiamo trovato nessun modo per leggere credenziali o chiavi senza averne diritto, né per aggirare la cifratura end-to-end. Le parti più delicate e scritte su misura (autorizzazioni sui ~90 endpoint, firme sulle consegne di chiave e catena di certificazione dell'organizzazione, rotazioni, accesso d'emergenza con attese, recupero 2-di-3, corse sull'invio sicuro, riuso TOTP, invalidazione delle sessioni, estensione Chrome) sono risultate solide e, nei punti verificati, corrette.

Abbiamo trovato **5 problemi** da correggere, nessuno dei quali espone di per sé una credenziale in chiaro a chi non la poteva già vedere:

| # | Gravità | Componente | In sintesi |
|---|---------|-----------|-----------|
| H1 | **Alta** | App Android (autofill) | Un'app malevola sul telefono si fa compilare le credenziali di un altro sito/app: nessun controllo della firma dell'app né allowlist dei browser. |
| M1 | **Media** | Server — rotazione | Un gestore può duplicare una consegna di chiave e ometterne un'altra: toglie l'accesso a un collega **senza traccia nel registro** e può lasciare un cliente **senza gestori**. |
| M2 | **Media** | Server — registro attività | La catena di hash usa SHA-256 "nudo", non un HMAC: chi scrive sul database può riscrivere o troncare il registro e `audit/verify` dice comunque «ok». |
| B1 | **Bassa-media** | Server — rimozione membri | Togliere un utente da un cliente non cancella le condivisioni di singoli elementi già fatte con lui. |
| B2–B5 | **Bassa** | Varie | Controllo `deleted_at` mancante su un percorso allegati; `import` non valida la cartella padre; `trustProxy` da fissare; la sospensione non revoca i dispositivi attendibili. |

**Metodo e limite importante:** questa è stata un'analisi **statica** del codice (quattro revisori indipendenti sulle aree prioritarie del brief, più una verifica indipendente dei problemi seri rileggendo il codice). **Non** è stato eseguito nessun test dinamico contro l'istanza `pentest-secures.startappitalia.it`, perché l'istanza di test non è ancora allestita. Le classi di problemi che si confermano solo a runtime (tempi di risposta reali, comportamento TLS/CSP del server in esecuzione, finestre di corsa sotto carico, la build Android vera sul dispositivo) restano da verificare sull'istanza di test. Siamo disponibili a una verifica delle correzioni.

---

## Problemi

### H1 — Alta — L'autofill Android si fida del dominio/pacchetto dichiarato dall'app richiedente (phishing di credenziali)

- **Componente / punto nel codice:**
  - `mobile/modules/sc-autofill/android/.../AutofillParser.kt:32` — il dominio web è preso da un nodo qualsiasi della struttura fornita dall'app richiedente: `n.webDomain?.takeIf { it.isNotBlank() }`, senza verifiche.
  - `AutofillParser.kt:51`, `ScAutofillService.kt:51-52` — `webDomain` e `packageName` sono inoltrati così come sono.
  - `mobile/src/autofill/AutofillApp.tsx:63-65` — `req.webDomain ? lookup("https://"+webDomain) : lookupApp(packageName)`.
  - `AutofillApp.tsx` (stage `pick`) — le voci corrispondenti (`matches`) si compilano con un tocco tramite `fill(r, false)`, **senza** l'avviso «Il sito non corrisponde»; quell'avviso (`pickManual`, righe 177-189) scatta solo per le voci scelte dalla lista completa, mai per una corrispondenza diretta falsificata.
  - Nessuna verifica della firma dell'app in tutto il modulo di autofill (nessun `getPackageInfo(GET_SIGNING_CERTIFICATES)`, nessun Digital Asset Links). L'associazione app è un confronto di sole stringhe.
- **Riproduzione:** un'app malevola installata sul telefono mostra una finta schermata di login e, in `onProvideAutofillStructure`, chiama `ViewStructure.setWebDomain("google.com")` sul proprio campo (API pubblica, non verificata dal sistema). StartCredentials legge `webDomain="google.com"`, esegue `lookup("https://google.com")` e offre la voce Google reale dell'utente come corrispondenza diretta, etichettata «Salvate per google.com». Un tocco invia username, password e OTP correnti nel campo dell'app malevola. Variante app native: un'app che dichiara il package di una vittima (es. `com.foo.bank`, possibile se l'app vera non è installata) combacia con l'associazione `androidapp://com.foo.bank` salvata — il confronto è solo sul nome del pacchetto, nessuna verifica della firma.
- **Impatto (modello di minaccia — app malevola sul dispositivo):** divulgazione, con un solo tocco, delle credenziali e dell'OTP di qualsiasi origine salvata. È esattamente il caso «compilazione automatica verso app con nome di pacchetto falsificato» del brief.
- **Gravità:** Alta. Attaccante locale (app sul dispositivo), un tocco dell'utente, divulgazione di credenziali + OTP. L'app Android è priorità secondaria nel brief, ma è l'unica vulnerabilità nuova con impatto diretto sulla riservatezza.
- **Correzione:**
  1. Accettare `webDomain` **solo** quando il `packageName` richiedente è un browser verificato (mantenere un'allowlist pacchetto-browser → firma, come fanno Bitwarden/1Password); altrimenti combaciare solo sul pacchetto.
  2. Per le app native, verificare la firma del chiamante (`PackageManager.getPackageInfo(..., GET_SIGNING_CERTIFICATES)`) contro una firma legata all'associazione salvata (salvare `androidapp://<pkg>@<hashFirma>` o usare Digital Asset Links), non il solo nome del pacchetto.
  3. `RecentFill.match` (`RecentFill.kt:30-37`) usa lo stesso `domain` non verificato come chiave della cache di 60 s (username/password in chiaro): una falsificazione nella finestra ottiene i valori anche senza sblocco. Correggere insieme.

### M1 — Media — La rotazione controlla il numero delle consegne, non chi sono: rimozione silenziosa di un membro e "orfanamento" del cliente

- **Componente / punto nel codice:** `app/src/routes/containers.ts:419-435` (`POST /api/v1/containers/:id/rotate`); stesso schema per i gruppi a `:428-435`. `insertGrant` è un `INSERT … ON CONFLICT (container_id,key_version,user_id) DO UPDATE` (`containers.ts:64-71`).
- **Causa:** il controllo è `if (body.grants.length !== expected.size)` più, per ogni consegna, `expected.get(g.recipientId) !== g.permission`. Nulla rifiuta `recipientId` **duplicati**. Un destinatario ripetuto aggiorna la stessa riga (ON CONFLICT), quindi il test sulla lunghezza è soddisfatto anche duplicando un membro e omettendone un altro. La `rotate` **non ha** il controllo `last_manager` che invece `DELETE /members/:userId` ha.
- **Riproduzione:** attore = membro M con permesso `manage`; cliente con M:manage e X:read, `key_version=1`.
  1. M esegue una rotazione normale ma invia `grants = [grantValidoPer(X,read,v2), grantValidoPer(X,read,v2)]` (due consegne corrette e firmate per X) e **omette** la propria consegna — oppure, per orfanare il cliente, omette tutti i gestori.
  2. `length (2) === expected.size (2)` passa; `expected.get(X) === "read"` passa per entrambe; entrambi gli `insertGrant` riescono.
  3. La chiave passa a `v2` e `DELETE FROM container_keys WHERE key_version < 2` cancella la chiave di M (e di ogni membro omesso).
  4. Risultato: solo il destinatario duplicato ha la chiave `v2`. Il membro omesso perde l'accesso **senza nessun record `container.member_removed`**: l'unico evento è `container.key_rotated` con `details.members = 2`, che sembra una rotazione normale a piena membership.
- **Impatto (modello di minaccia):**
  - **Evasione del registro / integrità:** l'accesso di un membro (una «consegna di chiave / permesso») viene revocato senza evento mirato, e il registro riporta un conteggio membri falso. Contraddice la garanzia «nessuno deve poter alterare un permesso o una consegna di chiave senza essere scoperto».
  - **Aggiramento della protezione `last_manager` / cliente orfano:** omettendo tutti i gestori e riempiendo con duplicati di un membro in lettura, un gestore può lasciare il cliente **con zero gestori** — non più rotabile, condivisibile o gestibile (perdita di disponibilità del vault di un cliente).
  - Lo stesso trucco toglie un **gruppo** da `groupGrants`, revocando l'accesso di un intero gruppo con il solo record di rotazione.
  - *Non* è una falla di riservatezza: ogni consegna deve comunque combaciare con un membro/permesso esistente, quindi non si può aggiungere un utente rimosso o alzare un permesso. Per questo è Media, non Alta.
- **Correzione:** richiedere l'uguaglianza degli **insiemi**, non delle lunghezze — rifiutare i duplicati e verificare che ogni membro atteso sia coperto:
  ```ts
  const seen = new Set<string>();
  for (const g of body.grants) {
    if (seen.has(g.recipientId)) throw badRequest("duplicate_grant");
    seen.add(g.recipientId);
    if (expected.get(g.recipientId) !== g.permission || g.containerId !== id || g.keyVersion !== body.newKeyVersion) throw badRequest("grants_must_match_members");
    await insertGrant(c, g, a.id);
  }
  if (seen.size !== expected.size) throw badRequest("grants_must_match_members");
  ```
  Stessa modifica per `groupGrants`. Aggiungere inoltre un controllo «≥1 gestore» alla `rotate`, per chiudere l'orfanamento anche contro altri bug futuri.

### M2 — Media — Il registro attività usa SHA-256 non keyed: manomissione e troncamento falsificabili da chi scrive sul database

- **Componente / punto nel codice:** `app/src/core.ts:273-278` (`auditHash` usa `createHash("sha256")`), `audit()` `:282`, `pruneAudit()` `:300`, `verifyAuditChain()` `:312`. Esposto da `GET /api/v1/audit/verify` (`app/src/routes/users.ts:516`). Per contrasto, `tokenHash` (`core.ts:152-153`) usa correttamente `createHmac("sha256", cfg.serverSecret)`.
- **Causa:** l'hash di ogni riga è `SHA256(canonical([prev_hash, at, actorId, action, …, details]))`. Tutti gli input sono colonne della stessa riga e la canonicalizzazione è pubblica (open source). L'hash **non è keyed**: non serve nessun segreto per ricalcolarlo.
- **Riproduzione (avversario con scrittura sul database — operatore malevolo, SQLi altrove, o restore manomesso):**
  1. Modificare/cancellare righe di `audit_log` (es. cancellare un `item.reveal`, un `send.created`, un `user.offboarded`, o troncare le più vecchie).
  2. Ricalcolare `prev_hash`/`hash` di quella riga e di tutte le successive con la formula pubblica `auditHash` (nessun segreto richiesto).
  3. Per il troncamento in testa, riscrivere anche l'impostazione `audit_anchor` con un `{id,hash}` calcolato.
  4. `GET /api/v1/audit/verify` risponde `{ ok: true }`.
- **Impatto (modello di minaccia):** il registro è il controllo di prova-di-manomissione del prodotto, e nel modello il server/database è esplicitamente non affidabile. Chi raggiunge il database può riscrivere silenziosamente la storia (nascondere un'esfiltrazione di credenziali, un invio sicuro, un'uscita, una concessione di permesso) e la verifica passa comunque. Il controllo non protegge proprio contro l'avversario per cui esiste.
- **Gravità:** Media — impatto alto sull'integrità del controllo, condizionato alla scrittura sul database.
- **Correzione:** in `auditHash` usare `createHmac("sha256", cfg.serverSecret)` al posto di `createHash("sha256")` (passare il segreto a `audit`/`pruneAudit`/`verifyAuditChain`). In più, pubblicare periodicamente l'ultimo `hash` della catena fuori banda (es. nella mail di avviso all'admin), così la catena resta verificabile anche contro chi possiede `SERVER_SECRET`.

### B1 — Bassa-media — Le condivisioni di singoli elementi sopravvivono alla rimozione dell'utente dal cliente

- **Componente / punto nel codice:** `app/src/routes/containers.ts:385-391` (`DELETE /containers/:id/members/:userId`): cancella `container_keys` e `emergency_access` dell'utente e segna la rotazione, ma **non** cancella `item_shares`. La rotazione re-incarta la chiave dell'elemento (`ik_key_version`) ma non cambia `ik_version`, e `GET /shared-items` combacia su `sh.ik_version = i.ik_version`, quindi la condivisione resta valida anche dopo la rotazione (la chiave dell'elemento è sigillata direttamente al destinatario, non tramite la chiave del cliente).
- **Riproduzione:** il gestore M condivide l'elemento X (sola lettura) con il collega U (`POST /items/X/shares`). M rimuove U dal cliente (`DELETE /containers/C/members/U`) e ruota. U — ancora dipendente attivo — continua a leggere X e i suoi allegati via `GET /shared-items`.
- **Impatto:** un admin che toglie un utente da un cliente si aspetta che finisca ogni suo accesso a quel cliente; le condivisioni di singoli elementi restano. Limite che riduce la gravità: l'uscita completa usa `POST /users/:id/offboard` (`users.ts:246`), che sospende l'account → la sessione è rifiutata globalmente. Il problema morde solo quando un utente **ancora attivo** viene rimosso da un singolo cliente. È recuperabile (`DELETE /items/:id/shares/:userId`). Nessuna chiave esposta oltre a ciò che la condivisione aveva già concesso.
- **Correzione:** alla rimozione di un membro, cancellare anche le sue `item_shares` sugli elementi del cliente (e segnare `rekey_required` su quegli elementi), come già si fa per `emergency_access` nello stesso handler.

### B2 — Bassa — Il download dei blocchi di un allegato ignora il soft-delete del cliente per chi ha una condivisione

- **Punto nel codice:** `app/src/routes/items.ts:405-412` (`GET /attachments/:id/chunks/:n`), helper `sharedWith` (`items.ts:33-38`). I clienti sono cancellati "soft" (`deleted_at`), quindi il `CASCADE` non scatta. Il controllo qui è `permissionOf(...) || sharedWith(...)`: `permissionOf` filtra `c.deleted_at IS NULL`, ma `sharedWith` fa join solo su `items`, non su `containers`. Dopo la cancellazione soft di un cliente, un destinatario di condivisione può ancora scaricare i blocchi dell'allegato, mentre `GET /shared-items` (che fa join con `containers … deleted_at IS NULL`) smette correttamente di elencarlo.
- **Impatto:** basso — il destinatario aveva già la chiave dell'elemento e l'accesso in lettura prima della cancellazione; i byte restano cifrati sotto la stessa chiave. È un'incoerenza tra i due percorsi di lettura.
- **Correzione:** aggiungere `AND c.deleted_at IS NULL` a `sharedWith` (join con `containers`), come in `/shared-items`.

### B3 — Bassa — `import` inserisce cartelle senza validare che `parentId` appartenga al cliente

- **Punto nel codice:** `app/src/routes/items.ts:455-457` (`POST /containers/:id/import`), ciclo cartelle. Il percorso singola-cartella (`containers.ts:516-519`) valida il padre con `checkFolder`; l'import no.
- **Impatto:** nessuno sulla riservatezza — `parentId` è metadato strutturale opaco, restituito solo dentro l'elenco cartelle dello stesso cliente; non raggiunge dati di altri clienti e id in conflitto abortiscono la transazione. Solo integrità dell'albero.
- **Correzione:** validare ogni `parentId` importato contro {cartelle esistenti nel cliente} ∪ {cartelle dello stesso import} prima dell'inserimento.

### B4 — Bassa — `trustProxy: "127.0.0.1"` rende i limiti per-IP dipendenti dal deploy

- **Punto nel codice:** `server.ts:76` e i limitatori per-IP. Se il reverse proxy non raggiunge Fastify da loopback, `req.ip` diventa l'IP del proxy (i bucket per-IP diventano uno globale — più restrittivo, ma rompe l'attribuzione). Lo spoofing di X-Forwarded-For per ruotare `req.ip` funziona solo se l'app è raggiungibile direttamente o il proxy inoltra un XFF non fidato; un singolo hop Traefik corretto lo previene.
- **Nota che limita l'impatto:** i limiti anti-forza-bruta che contano sono su **email/userId** (`auth-key:<email>`, `mfa:<userId>`, `pw:<userId>`), non per-IP — quindi il tentativo online su master password e TOTP resta limitato anche se i limiti per-IP vengono aggirati.
- **Correzione:** fissare `trustProxy` all'hop/CIDR reale del proxy del deploy NS8 e verificare che `req.ip` rifletta il vero client in produzione.

### B5 — Bassa/Info — La sospensione cancella le sessioni ma non revoca i dispositivi attendibili

- **Punto nel codice:** `users.ts:191` (`PATCH /users/:id`) cancella le sessioni su sospensione/declassamento ma, a differenza di `offboard` (`:280`) e `mfa-reset` (`:234`), non revoca i `trusted_devices`.
- **Non sfruttabile ora:** il login richiede `status='active'` e la query di caricamento sessione filtra `status='active'`; un utente sospeso non può comunque agire. Rischio solo alla **riattivazione**: i dispositivi attendibili preesistenti salterebbero di nuovo l'MFA. Da revocare alla sospensione per coerenza.

---

## Cosa è stato provato senza esito (copertura)

Aree verificate e risultate corrette (non si sono trovati problemi oltre a quelli sopra):

- **Identità e sessioni:** risoluzione sessione→utente unica e filtrata su `status='active'` (`server.ts:96-112`) — un utente sospeso/uscito/cancellato è rifiutato globalmente su ogni endpoint, non solo al login. Cambio password, recupero, mfa-reset, offboard revocano sessioni e dispositivi attendibili.
- **Autorizzazioni server (IDOR, escalation):** ogni operazione su elementi/allegati/cartelle risolve il cliente **dalla riga salvata** e poi controlla il permesso; ogni `containerId`/`keyVersion`/`recipientId` dal corpo è ricontrollato; nessun IDOR, nessuna escalation verticale (lettura/scrittura→gestione, non-admin→admin) o orizzontale verso un altro cliente; nessun mass-assignment di ruolo/permesso/proprietario; operazioni in blocco (`items/bulk`, `import`) verificano l'appartenenza di ogni id.
- **Consegne di chiave e rotazioni:** ogni consegna (diretta, di gruppo, condivisione elemento) lega nella firma cliente+versione+destinatario+permesso+concedente+hash della chiave sigillata; server e client ri-verificano. Il client rifiuta consegne non firmate da un utente certificato dall'organizzazione (`signerKey`/`verifyUserCertification`). La sostituzione della chiave dell'organizzazione è bloccata da pinning TOFU + catena di rotazione firmata. Una vecchia consegna rigiocata non apre i blocchi correnti (AAD legato alla versione di chiave).
- **Accesso d'emergenza e a tempo:** nessun accesso senza l'attesa; dopo un rifiuto niente ri-richiesta ogni 24 h; `activate` ri-verifica che il designante sia ancora attivo e `manage`, il destinatario attivo e certificato, e la firma della consegna; gli accessi a tempo mantengono la scadenza anche dopo la rotazione (non diventano permanenti). La chiave sigillata trattenuta non è mai restituita prima dell'attivazione. Tutte le transizioni sono sotto lock (`FOR UPDATE`).
- **Recupero 2-di-3:** soglia imposta da Shamir; la ricostruzione è validata contro la chiave pubblica di recupero dell'organizzazione; vecchie quote invalide dopo la rotazione. Nessuna ricostruzione con meno quote.
- **Accesso e invio sicuro:** enumerazione account mitigata (risposta OPAQUE fittizia per email sconosciute, log/avvisi identici, limite per-email simmetrico); TOTP con contatore monotòno (passo usato rifiutato); codici di riserva monouso e solo in HMAC; token dispositivi attendibili legati all'utente e revocabili. Invio sicuro: conteggio aperture protetto da `SELECT … FOR UPDATE` (nessuna corsa oltre `max_views`); aperture dopo scadenza/revoca bloccate nella stessa transazione; token da 32 byte, codice ~80 bit mai inviato al server (resta nel frammento URL); pagina `/s` con CSP stretta (`default-src 'none'`), `X-Frame-Options: DENY`, `no-referrer`.
- **Estensione Chrome:** niente `externally_connectable`/`onMessageExternal`; `runtime.onMessage` controlla `sender.id`. Compilazione automatica con corrispondenza host esatta, triplo controllo, solo sul frame principale e dietro un click; nessuna confusione sottodominio/suffisso/IDN. Icona nei campi in uno shadow root chiuso; menu in iframe con URL dinamico non indovinabile (anti-clickjacking). Nessuna injection HTML via nomi di clienti/elementi (Preact auto-escape; report con encoder completo; QR genera solo `<rect>`). Appunti svuotati dopo la copia; il blocco automatico cancella le chiavi.
- **Android (oltre H1):** WebView del motore ben isolata (`default-src 'none'`, `about:blank`, nessun contenuto remoto, nessuna rete propria: le richieste passano dall'app e sono limitate all'origine del server). Segreti a riposo solo in `expo-secure-store` con autenticazione richiesta; cache offline solo cifrata lato server; nessun log di segreti; cattura schermo bloccata nel flusso di autofill.
- **Registro attività:** append e prune sotto advisory lock; manomissione di una riga intermedia rompe `prev_hash` ed è colta dalla verifica (l'unico aggiramento è l'hash non-keyed di M2); avvisi email limitati a 1/ora per `azione:utente` (nessuna inondazione).

Problemi già corretti prima del rilascio (elencati nel brief) confermati corretti e non ri-segnalati. Limiti noti/accettati (il server può anticipare attese/scadenze; eventi inviati dal client sopprimibili; dati già scaricati conservati fino alla rotazione; HIBP a k-anonimato; avviso basso Vue 2 nel pannello) esclusi come da brief.

---

## Metodo, limiti e disponibilità

- **Metodo:** revisione statica del codice 0.7.15, quattro revisori indipendenti sulle aree prioritarie del brief, più una verifica indipendente dei problemi H1, M1, M2, B1 rileggendo direttamente il codice citato.
- **Non coperto (richiede l'istanza di test in esecuzione):** test dinamici contro `pentest-secures.startappitalia.it` (non ancora allestita) — tempi di risposta reali, comportamento TLS/certificato e header/CSP del server in esecuzione, finestre di corsa reali sotto carico, la build Android vera su dispositivo, fuzzing delle API. Questi confermerebbero/escluderebbero sul campo le classi solo-runtime.
- **Disponibilità a verifica delle correzioni:** sì. Ordine suggerito: **H1** (Android, l'unico con impatto diretto sulla riservatezza), poi **M1** e **M2** (integrità/registro, correzioni piccole), poi **B1** (revoca incompleta); B2–B5 come indurimento.

*Revisione svolta con assistente AI (Claude), come i controlli automatici precedenti citati nel brief. Non sostituisce una verifica umana indipendente, che il brief stesso indica come primo obiettivo.*

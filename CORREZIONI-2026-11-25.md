# StartCredentials — Correzioni dalla revisione di sicurezza del 25/11/2026

Tutti i problemi della revisione ([REVISIONE-SICUREZZA-2026-11-25.md](REVISIONE-SICUREZZA-2026-11-25.md)) sono stati corretti nel repository locale. **Niente è stato rilasciato:** il tag e il deploy restano al flusso abituale su gestsec, con i due passaggi obbligatori qui sotto.

## Cosa è stato corretto

| # | File | Correzione |
|---|------|-----------|
| **H1** | `mobile/.../CallerVerifier.kt` (nuovo), `ScAutofillService.kt`, `RecentFill.kt`, `AutofillResult.kt`, `engine/engine.ts`, `src/autofill/AutofillApp.tsx` | L'autofill accetta il dominio dichiarato **solo** da browser verificati per firma del certificato; le altre app ricadono sul match per solo pacchetto. Le associazioni app sono legate alla firma (`androidapp://pkg@sha256`), compatibili con quelle vecchie. |
| **M1** | `app/src/routes/containers.ts` (rotate) | La rotazione richiede l'uguaglianza degli **insiemi** (niente consegne duplicate, ogni membro coperto) + almeno un gestore: non si può più togliere accesso a un collega senza traccia, né orfanare il cliente. |
| **M2** | `app/src/core.ts` | Catena del registro con **HMAC** e chiave del server (prima SHA-256 nudo). Aggiunta `rebaseAuditChain` + script eseguibile. |
| **B1** | `app/src/routes/containers.ts` (rimozione membro) | Alla rimozione si cancellano le condivisioni di singoli elementi dell'utente e si forza la ri-cifratura (`rekey_required`) di quegli elementi. |
| **B2** | `app/src/routes/items.ts` (`sharedWith`) | Controlla il soft-delete del cliente, come `/shared-items`. |
| **B3** | `app/src/routes/items.ts` (import) | Valida che la cartella padre appartenga al cliente (o allo stesso import). |
| **B4** | `app/src/server.ts`, `core.ts` | `trustProxy` da variabile d'ambiente `TRUST_PROXY`. |
| **B5** | `app/src/routes/users.ts` (sospensione) | La sospensione revoca anche i dispositivi attendibili. |

## Verifica fatta

- `npx tsc --noEmit` su **app/** e su **mobile/**: entrambi senza errori.
- **Revisione indipendente** (adversarial) di tutte le correzioni: nessun nuovo aggiramento introdotto, nessuna correzione che rifiuti un'operazione legittima; le sette correzioni confermate corrette.
- **Non** ho eseguito i test end-to-end (richiedono PostgreSQL; qui non c'erano docker/podman): vanno eseguiti nella CI o sul nodo (`npm test` in `app/` con `TEST_DATABASE_URL`).
- Le modifiche **Kotlin** (autofill) sono state solo lette, non compilate: serve un build Android reale.

## ⚠ Da fare PRIMA del rilascio (obbligatorio)

1. **Popolare gli hash dei certificati dei browser** in `mobile/.../CallerVerifier.kt` (`BROWSERS`, ora vuoti = fail-closed). **Finché sono vuoti, l'autofill nei browser non funziona.** Come: su un dispositivo/emulatore, avviare l'autofill in ciascun browser e leggere nel Logcat (tag `ScAutofill`) la riga `browser non verificato <pkg> firma=<sha256>`; incollare l'hash (hex minuscolo, senza `:`) nell'insieme del pacchetto. In alternativa `apksigner verify --print-certs <apk>`.
2. **Ri-basare la catena del registro** sull'istanza di **produzione** esistente (`startcredentials5`), una volta sola, in una finestra fidata: con le variabili d'ambiente del servizio, `npm run build && node scripts/rebase-audit.mjs` in `app/`. Senza, dopo l'aggiornamento `audit/verify` segnalerebbe una (falsa) manomissione sulle righe vecchie. **Le nuove installazioni (es. `startcredentials6` di test) non ne hanno bisogno.**

## Residui noti (per il progetto)

- **Associazioni app vecchie:** quelle salvate prima di questa versione restano verificate solo per nome di pacchetto finché l'utente non le ri-salva (allora diventano legate alla firma). H1 è chiuso per i browser e per le nuove associazioni; le vecchie si rafforzano al primo uso.
- **Verifica su dispositivo reale** ancora da fare: firma corretta letta su Android 9+ e su versioni più vecchie; autofill reale in un browser vero vs. un'app con dominio falsificato; una copia ri-firmata (stesso pacchetto, firma diversa) non deve combaciare; cache di 60 s dentro una stessa sessione verificata.

## Verifica delle correzioni

Disponibile a rivedere le correzioni dopo i test e/o sull'istanza di test, quando sarà allestita.

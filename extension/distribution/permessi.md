# Motivazione dei permessi (per la revisione degli store)

- **storage**: salva le impostazioni (indirizzo del server, blocco automatico) e, solo in memoria di sessione, le chiavi sbloccate.
- **alarms**: blocca la cassaforte dopo il periodo di inattività scelto e svuota gli appunti dopo la copia di una password.
- **activeTab** e **scripting**: compilano utente e password nella scheda attiva, solo quando l'utente preme «Compila» e solo se il dominio corrisponde esattamente a quello salvato.
- **offscreen** e **clipboardWrite**: svuotano gli appunti dopo la copia di una password.
- **Permessi host opzionali**: richiesti una sola volta per l'indirizzo del server StartCredentials dell'azienda. Solo se l'utente attiva nelle impostazioni l'icona nei campi di accesso viene chiesto l'accesso alle pagine HTTPS: lo script aggiunto alle pagine mostra soltanto un'icona e apre il popup, non legge né invia contenuti delle pagine.

L'estensione non raccoglie dati di navigazione, non contatta servizi di terze parti e non contiene codice remoto: tutto il codice è incluso nel pacchetto.

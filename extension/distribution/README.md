# Distribuzione dell'estensione StartCredentials

La sicurezza di StartCredentials si basa sul fatto che la crittografia giri in
un client **firmato** che il server non può modificare. L'estensione caricata in
modalità sviluppatore va bene solo per le prove: non si aggiorna da sola e, se il
server venisse compromesso, potrebbe distribuire uno zip alterato.

Per l'uso reale scegliete una delle strade seguenti. Il file da caricare è
sempre `extension/startcredentials-extension.zip`, prodotto da `npm run build -w extension`.

## 1. Chrome Web Store (consigliata)

1. Registrate un account sviluppatore su <https://chrome.google.com/webstore/devconsole>
   con un account aziendale (quota una tantum di 5 USD).
2. **Nuovo elemento** → caricate lo zip.
3. Scheda **Privacy**: incollate il testo di `privacy.md` (va anche pubblicato a
   un indirizzo web, ad esempio `https://secures.startappitalia.it/privacy`) e
   motivate i permessi con le frasi di `permessi.md`.
4. Visibilità: **Non in elenco** (installabile solo da chi ha il link) oppure,
   con Google Workspace, **Privata** per il vostro dominio.
5. Dopo l'approvazione annotate l'**ID dell'estensione** (32 lettere): serve per i
   criteri di gruppo.

Ogni nuova versione: aumentate `version` in `extension/static/manifest.json`,
ricostruite e caricate il nuovo zip. Chrome aggiorna i browser da solo.

## 2. Microsoft Edge Add-ons

Stessa procedura su <https://partner.microsoft.com/dashboard/microsoftedge>
(registrazione gratuita), con visibilità **Nascosta**. Edge può anche installare
direttamente la versione del Chrome Web Store, se il criterio
`ExtensionInstallSources` lo consente: in quel caso basta pubblicarla una volta.

## 3. Installazione obbligatoria con i criteri di gruppo

Una volta pubblicata, potete installarla in automatico su tutti i PC aziendali,
senza che l'utente possa rimuoverla. Sostituite `ID_ESTENSIONE` nei file:

| Sistema | File | Come applicarlo |
| --- | --- | --- |
| Windows, Chrome | `windows-chrome.reg` | Doppio clic come amministratore, oppure GPO |
| Windows, Edge | `windows-edge.reg` | Doppio clic come amministratore, oppure GPO |
| Linux, Chrome | `linux-chrome.json` | Copiare in `/etc/opt/chrome/policies/managed/` |
| Linux, Edge | `linux-chrome.json` | Copiare in `/etc/opt/edge/policies/managed/` cambiando l'URL come nel file Edge |

Per Edge con l'estensione pubblicata solo sul Chrome Web Store, usate in
`windows-edge.reg` l'URL di aggiornamento di Google
(`https://clients2.google.com/service/update2/crx`).

Verifica: aprite `chrome://policy` o `edge://policy` e controllate che
`ExtensionInstallForcelist` sia presente e senza errori.

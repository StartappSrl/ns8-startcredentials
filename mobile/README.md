# StartCredentials per Android

App Android di StartCredentials (Expo SDK 57, React Native 0.86).

## Architettura

La crittografia gira in un **motore** (`engine/engine.ts`): lo stesso SDK
dell'estensione (libsodium, OPAQUE, Argon2id), eseguito in una WebView
invisibile che supporta WebAssembly. L'interfaccia nativa gli chiede le
operazioni e riceve i risultati.

- Le chiavi restano solo nella memoria del motore.
- La WebView non ha rete (CSP senza `connect-src`): le richieste le esegue
  l'app, solo verso l'origine del server configurato.
- Nessun modulo crittografico nativo: solo componenti ufficiali Expo.

## Funzioni

Permessi Android: rete, impronta, vibrazione e fotocamera (solo per i QR code
OTP); nessun accesso a microfono, archivio o sovrapposizione ad altre app.

Accesso (OPAQUE), codice MFA o di riserva, prima configurazione dell'MFA,
dispositivo attendibile per 30 giorni, sblocco con l'impronta (sessione
nell'Android Keystore, leggibile solo dopo l'autenticazione biometrica),
clienti, cartelle comprimibili, dettaglio delle password, codici OTP, siti
apribili, allegati, ricerca, password condivise singolarmente, blocco
automatico, blocco degli screenshot, appunti svuotati dopo 30 secondi.

**Offline**: con la rete ogni lettura viene salvata nella memoria privata
dell'app (dati cifrati, come sul server) e dopo ogni sblocco parte una
sincronizzazione completa. Senza rete l'app si apre con la master password o
con l'impronta e mostra, in sola lettura, i dati dell'ultima sincronizzazione.
Uscendo dall'account, o disattivando l'opzione, i dati offline vengono
cancellati.

**Primo accesso**: incollando il collegamento d'invito si crea l'account
direttamente dal telefono (master password, MFA, codici di riserva).

**Modifiche**: nuove password e note, modifica, eliminazione e cestino con
ripristino, cronologia delle versioni con ritorno a una versione precedente,
allegati caricati dal telefono (fino a 25 MB) ed eliminati, nuove cartelle e
sottocartelle, generatore di password. Il **codice OTP** si
aggancia a una password esistente scansionando il QR code del servizio o
incollando la chiave segreta o il link `otpauth://`; prima di salvare compare
il codice per il confronto. Senza rete le modifiche sono disattivate.
**Condivisioni**: per i gestori, condivisione del cliente con colleghi e gruppi
(con revoca e rotazione della chiave) e di una singola password (con revoca e
ricifratura). Le chiavi dei colleghi si certificano dall'estensione.

**Account**: cambio della master password, nuovi codici di riserva, rapporto
sulla salute delle password.

**Aggiornamenti**: ogni 30 secondi, con l'app attiva e la rete, l'app rileva i
cambiamenti dei colleghi e aggiorna le schermate e la copia offline. Se la
sessione scade sul server si torna alla schermata di sblocco.

**Aspetto**: tema chiaro o scuro secondo il sistema (all'avvio), contenuto
centrato sui tablet.

Restano solo nell'estensione l'amministrazione (utenti, certificazioni,
uscite, recupero, gruppi, registro attività) e import/export: operazioni rare,
più sicure e comode su un computer.

**Autofill di sistema**: StartCredentials può essere scelto come servizio di
compilazione automatica di Android (Impostazioni dell'app → «Compilazione
automatica»). Nelle app e nei siti compare «Compila con StartCredentials»: al
tocco si apre una schermata che sblocca la cassaforte (impronta o master
password, anche offline), mostra le credenziali del dominio esatto o dell'app
e compila utente, password e codice OTP. Il servizio di sistema non riceve mai
password: le consegna ad Android solo la schermata, al momento della scelta.
A fine accesso Android propone «Salvare in StartCredentials?»: la schermata
salva il nuovo accesso o aggiorna la password cambiata. Negli accessi in due
passaggi (utente e password su pagine diverse) i valori appena scelti restano
in memoria per 60 secondi, solo per lo stesso sito o la stessa app.
Scegliendo a mano una credenziale per un'app, la si può associare
(`androidapp://pacchetto`) così la volta dopo compare subito. In Chrome va
attivato anche «Compila automaticamente utilizzando un altro servizio».

Codice nativo: `modules/sc-autofill` (servizio, analisi dei campi, consegna
dei valori; verificato con il compilatore Kotlin sulle API di Android 15) e
`plugins/autofill` (aggiunge l'attività della schermata durante la generazione
del progetto Android).

## Preparazione

Dalla radice del repository:

```bash
npm install
npm run build -w packages/crypto -w packages/client
node mobile/scripts/build-engine.mjs        # rigenera src/engine/engineHtml.ts
node mobile/engine/engine.test.mjs          # test del motore (serve PostgreSQL, come per i test dell'app)
cd mobile && npm install && npm run typecheck
```

Ricordarsi di rigenerare il motore ogni volta che cambiano `packages/`.

## Compilare l'APK

**Con GitHub Actions (consigliato, nessuna installazione):** nella scheda
Actions del repository scegliere «App Android (APK)» → «Run workflow»; dopo
circa 20 minuti l'APK è tra gli artefatti dell'esecuzione. In alternativa si
crea un tag `app-X.Y.Z`. Per la firma aziendale aggiungere nei segreti del
repository `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`,
`ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`; senza segreti l'APK usa la chiave
di prova di React Native, adatta solo ai test.

**Con EAS (cloud di Expo):** serve un account Expo gratuito.

```bash
cd mobile
npx eas-cli login
npx eas-cli build -p android --profile preview      # APK installabile
npx eas-cli build -p android --profile production   # AAB per Google Play
```

**In locale:** servono JDK 17 e Android SDK (Android Studio).

```bash
cd mobile
npx expo prebuild -p android
cd android && ./gradlew assembleRelease
```

Per una build di produzione configurate la vostra chiave di firma
(`android/app/build.gradle`, sezione `signingConfigs`) e conservatela con
cura: gli aggiornamenti devono essere firmati sempre con la stessa chiave.

## Distribuzione

- **Prove**: installare l'APK del profilo `preview` (consentendo le origini
  sconosciute).
- **Azienda**: Google Play con test interno o app privata tramite Managed
  Google Play / MDM, così gli aggiornamenti arrivano da soli.

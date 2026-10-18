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

Le modifiche (nuove password, condivisioni, amministrazione) si fanno
dall'estensione. L'autofill di sistema di Android è previsto in una versione
successiva.

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

**Con EAS (cloud di Expo, consigliato):** serve un account Expo gratuito.

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

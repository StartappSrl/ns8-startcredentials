# ns8-startcredentials

StartCredentials è un gestore zero-knowledge di password, codici OTP e allegati
per i team che amministrano i sistemi dei clienti. Ogni cliente è un
contenitore con la propria chiave; il server, distribuito come modulo
[NethServer 8](https://github.com/NethServer/ns8-core), conserva solo dati
cifrati sul dispositivo dell'utente.

## Componenti

| Cartella | Contenuto |
| --- | --- |
| `packages/crypto` | Core crittografico (libsodium): Argon2id, X25519/Ed25519, XChaCha20-Poly1305, allegati a blocchi, TOTP |
| `packages/client` | SDK usato da estensione e app mobile: API, flussi crittografici, import |
| `app` | Backend Node.js (Fastify + PostgreSQL 16): API REST, login OPAQUE, MFA, audit a catena di hash |
| `extension` | Estensione Manifest V3 per Chrome ed Edge: popup con compilazione automatica e applicazione completa |
| `imageroot`, `ui` | Modulo NethServer 8: servizi, azioni, backup, pannello di amministrazione |

## Installazione su NethServer 8

```
add-module ghcr.io/<org>/startcredentials:latest 1
api-cli run module/startcredentials1/configure-module --data '{"host": "credenziali.example.com", "lets_encrypt": true}'
```

Il modulo avvia un pod rootless con l'applicazione e PostgreSQL, pubblica
l'host tramite Traefik solo in HTTPS e usa lo smarthost del cluster per gli inviti.

### Primo amministratore

1. Nel pannello NethServer, pagina **Impostazioni** del modulo, copia il codice di attivazione.
2. Scarica l'estensione da `https://<host>/download/startcredentials-extension.zip`
   (oppure distribuiscila con i criteri di gruppo di Chrome/Edge) e installala.
3. Nell'estensione inserisci l'indirizzo del server, poi codice di attivazione, nome, email e master password.
4. Attiva l'MFA e, dalla pagina **Organizzazione**, inizializzala: stampa le quote di recupero e consegnale a persone diverse.

Il codice di attivazione smette di funzionare dopo la creazione del primo amministratore.

### Backup e ripristino

Il backup di NethServer include il dump del database (`module-dump-state`),
i segreti dell'istanza e il volume degli allegati. Tutti i dati sono cifrati
lato client: il backup non contiene password, OTP o allegati in chiaro.
Al ripristino il dump viene ricaricato automaticamente al primo avvio di PostgreSQL.

## Modello di sicurezza in breve

- La master password non lascia mai il dispositivo: login con OPAQUE, chiavi derivate con Argon2id (256 MiB).
- Ogni cliente ha una chiave propria, consegnata a ogni membro cifrata con la sua chiave pubblica e firmata da chi la concede; il server verifica la firma.
- Le chiavi dei colleghi sono certificate da un amministratore dopo il confronto dell'impronta a voce; l'estensione fissa la chiave dell'organizzazione al primo accesso.
- Revocare un membro ruota la chiave del cliente in modo atomico.
- Il recupero di un account richiede almeno 2 quote Shamir su 3 e un codice comunicato all'utente su un canale separato.
- La compilazione automatica avviene solo su corrispondenza esatta del nome host, in HTTPS, nel frame principale.
- Il registro di audit è una catena di hash: una modifica diretta al database viene rilevata.

## Sviluppo e test

Serve Node.js 22 e un PostgreSQL di test (`TEST_DATABASE_URL`, predefinito `postgres://sc:sc@127.0.0.1/sc`).

```
npm ci
npm test -w packages/crypto          # 13 test del core crittografico
npm run build -w packages/client
npm test -w app                      # 9 scenari end-to-end su server e database reali
npm run build -w extension           # produce extension/startcredentials-extension.zip
npm run test:ui -w extension         # test di fumo dell'interfaccia (jsdom + server reale)
./build-images.sh                    # immagini del modulo e dell'applicazione (buildah)
```

## Stato

Fasi 0, 1 e 2 implementate e testate. Prima dell'uso in produzione servono un
penetration test esterno e una revisione indipendente della crittografia.
L'app mobile (fase 3) userà `packages/crypto` e `packages/client`.

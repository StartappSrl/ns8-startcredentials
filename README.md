# ns8-startcredentials

StartCredentials è un gestore di credenziali zero-knowledge per team che
amministrano i sistemi dei clienti: contenitori cliente, password, codici OTP,
allegati e condivisione tra utenti. Il server conserva solo dati cifrati sul
dispositivo dell'utente.

Questo repository è il modulo [NethServer 8](https://github.com/NethServer/ns8-core),
creato dal template [ns8-kickstart](https://github.com/NethServer/ns8-kickstart).

## Stato: fase 0 (fondazioni)

| Parte | Stato |
| --- | --- |
| `packages/crypto` – core crittografico | Implementato, 13 test verdi |
| `imageroot/actions/configure-module` – host e Let's Encrypt | Implementato |
| Backend API, frontend web, PostgreSQL | Fase 1 |
| Estensione Chrome / Edge | Fase 2 |
| App mobile | Fase 3 |

Il servizio systemd avvia ancora il container di esempio del template:
verrà sostituito dai container `app`, `web` e `db` nella fase 1.

## Core crittografico

```
cd packages/crypto
npm install
npm test
```

Primitive (tutte da libsodium): Argon2id per la master key, X25519 ed
Ed25519 per le chiavi utente, XChaCha20-Poly1305 per i dati, secretstream
per gli allegati, BLAKE2b per gli hash dei domini, HMAC Web Crypto per TOTP.
Ogni blob cifrato è legato al proprio contesto (contenitore, elemento,
versione) e non può essere spostato su un altro record.

## Install

Instantiate the module with:

    add-module ghcr.io/nethserver/startcredentials:latest 1

The output of the command will return the instance name.
Output example:

    {"module_id": "startcredentials1", "image_name": "startcredentials", "image_url": "ghcr.io/nethserver/startcredentials:latest"}

## Configure

Let's assume that the startcredentials instance is named `startcredentials1`.

Launch `configure-module`, by setting the following parameters:
- `host`: nome host pubblico (FQDN) dell'istanza
- `lets_encrypt`: `true` per richiedere il certificato Let's Encrypt

Example:

    api-cli run module/startcredentials1/configure-module --data '{"host": "credenziali.example.com", "lets_encrypt": true}'

The above command will:
- start and configure the startcredentials instance
- (describe configuration process)
- ...

Send a test HTTP request to the startcredentials backend service:

    curl http://127.0.0.1/startcredentials/

## Smarthost setting discovery

Some configuration settings, like the smarthost setup, are not part of the
`configure-module` action input: they are discovered by looking at some
Redis keys.  To ensure the module is always up-to-date with the
centralized [smarthost
setup](https://nethserver.github.io/ns8-core/core/smarthost/) every time
startcredentials starts, the command `bin/discover-smarthost` runs and refreshes
the `state/smarthost.env` file with fresh values from Redis.

Furthermore if smarthost setup is changed when startcredentials is already
running, the event handler `events/smarthost-changed/10reload_services`
restarts the main module service.

See also the `systemd/user/startcredentials.service` file.

This setting discovery is just an example to understand how the module is
expected to work: it can be rewritten or discarded completely.

## Uninstall

To uninstall the instance:

    remove-module --no-preserve startcredentials1

## Running tests locally

This module uses the NS8 standard testing infrastructure. For instructions on how to run the test suite locally, refer to the [Running tests locally](https://github.com/NethServer/ns8-github-actions/blob/v1/README.md#running-tests-locally) section of the ns8-github-actions README.

## UI translation

Translated with [Weblate](https://hosted.weblate.org/projects/ns8/).

To setup the translation process:

- add [GitHub Weblate app](https://docs.weblate.org/en/latest/admin/code-hosting.html#code-hosting-github-notifications) to your repository
- add your repository to [hosted.weblate.org](https://hosted.weblate.org) or ask a NethServer developer to add it to ns8 Weblate project

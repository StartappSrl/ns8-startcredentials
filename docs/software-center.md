# StartCredentials nel Software Center di NethServer 8

Questa guida spiega come iscrivere un cluster NS8 al repository software di
StartCredentials, così che il modulo e i suoi aggiornamenti compaiano nel
**Software Center** invece di dover usare `api-cli run update-module` a mano.

I comandi `api-cli` vanno eseguiti come **root sul nodo leader** del cluster.

## 1. Prerequisito (lato pubblicazione)

L'indice del repository è servito via HTTPS da GitHub Pages:

```
https://startappsrl.github.io/ns8-startcredentials/repodata.json
```

Viene generato e pubblicato automaticamente a ogni tag di release dal job
`repodata` del workflow `publish-images.yml` (vedi
[`ns8-repo/README.md`](../ns8-repo/README.md)). Una tantum, in **Settings → Pages**
del repository GitHub, impostare **Source: GitHub Actions**.

## 2. Iscrivere il cluster al repository

```bash
api-cli run add-repository --data '{
  "name": "startappsrl",
  "url": "https://startappsrl.github.io/ns8-startcredentials/",
  "status": true,
  "testing": false
}'
```

- **name** — nome univoco del repository nel cluster (es. `startappsrl`).
- **url** — URL della **cartella** che contiene `repodata.json` (NS8 vi aggiunge
  da solo `repodata.json`). Barra finale consigliata.
- **status** — `true` abilita subito il repository.
- **testing** — `false`: vengono offerte solo le **release stabili**. Metterlo a
  `true` solo se si vogliono ricevere anche le pre-release (vedi §5).

> Nota: nelle versioni core più datate `add-repository` accetta solo
> `name`/`url`/`status`. Se il comando rifiuta `testing`, ometterlo: il valore
> predefinito è comunque “solo stabili”. Il flag `testing` si può impostare
> anche dopo (vedi §5).

Aggiornare la cache dei repository e verificare:

```bash
api-cli run list-repositories          # deve elencare "startappsrl"
api-cli run list-updates               # deve mostrare l'aggiornamento di startcredentials
```

La cache dei metadati dei repository dura 3600 s: dopo l'iscrizione può servire
attendere qualche minuto o forzare un refresh (es. ricaricando la pagina
Software Center / rieseguendo `list-updates`).

## 3. Verifica nel Software Center

Nella UI del cluster → **Software Center**:

- in **Available** compare **StartCredentials** (con logo, descrizione,
  categorie prese da `metadata.json`);
- per un'istanza già installata, in **Installed/Updates** compare il pulsante di
  aggiornamento verso l'ultima versione pubblicata (es. `0.9.0`).

## 4. Caveat: istanza già installata per URL immagine

Le istanze `startcredentials5` (produzione) e `startcredentials6` (test) sono
state installate con `api-cli run add-module` indicando direttamente l'URL
immagine. Perché il Software Center offra loro gli aggiornamenti **dal
repository**, la *source* dell'istanza installata deve combaciare con la
`source` dichiarata nell'indice:

```
ghcr.io/startappsrl/startcredentials
```

Verifica della source registrata per un'istanza (sostituire l'id modulo reale):

```bash
# elenca le istanze installate e i rispettivi id (es. startcredentials1)
api-cli run list-installed-modules

# mostra la source da cui l'istanza riceve gli aggiornamenti
redis-cli HGET "module/startcredentials1/environment" IMAGE_URL
```

- Se la source è già `ghcr.io/startappsrl/startcredentials` (senza tag o con un
  tag), **non serve altro**: una volta aggiunto il repository, l'aggiornamento
  alla versione in `repodata.json` viene calcolato e offerto automaticamente.
- Se l'istanza fosse stata agganciata a una source diversa (es. un path/registry
  differente), il Software Center non assocerebbe l'aggiornamento. In quel caso
  si continua ad aggiornare con `api-cli run update-module` oppure si reinstalla
  l'istanza puntando alla source canonica. Non è richiesto alcun intervento sui
  dati: StartCredentials è E2EE e il database resta invariato tra gli update.

> In pratica, poiché le immagini sono sempre state pubblicate come
> `ghcr.io/startappsrl/startcredentials`, le istanze esistenti dovrebbero già
> allinearsi senza modifiche. Confermarlo con il comando `redis-cli` qui sopra
> prima del primo aggiornamento via Software Center.

## 5. Offrire anche le pre-release (opzionale)

Se in futuro si pubblicano tag pre-release (es. `1.0.0-beta1`), per vederle nel
Software Center abilitare il flag `testing` sul repository:

```bash
# se supportato dalla versione core:
api-cli run edit-repository --data '{"name":"startappsrl","testing":true,"status":true,"url":"https://startappsrl.github.io/ns8-startcredentials/"}'
```

Con `testing: false` (default consigliato) le pre-release restano comunque
elencate in `repodata.json` ma **non** vengono proposte come aggiornamento.

## 6. Rimozione del repository

```bash
api-cli run remove-repository --data '{"name":"startappsrl"}'
```

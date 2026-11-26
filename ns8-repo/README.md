# Repository software NethServer 8 — StartCredentials

Questa cartella genera l'**indice di repository NS8** (`repodata.json`) che permette
a StartCredentials e ai suoi aggiornamenti di comparire nel **Software Center**
dei cluster NethServer 8.

Senza questo indice il modulo si puo' installare/aggiornare solo per URL immagine
(`api-cli run add-module` / `update-module`): il Software Center elenca gli
aggiornamenti **solo** dai repository configurati che espongono un `repodata.json`.

## Come funziona

Al push di un **tag di release** il workflow [`publish-images.yml`](../.github/workflows/publish-images.yml):

1. costruisce e pubblica l'immagine su `ghcr.io/startappsrl/startcredentials:<tag>` (+ `:latest`);
2. nel job `repodata` (che parte **dopo** la pubblicazione dell'immagine):
   - prepara la cartella `.dst/startcredentials/` con `metadata.json` (copia di
     [`ui/public/metadata.json`](../ui/public/metadata.json), fonte unica dei
     metadati del modulo) e `logo.png`;
   - esegue [`createrepo.py`](createrepo.py), che interroga i tag semver
     dell'immagine su ghcr con `skopeo`, seleziona l'ultima versione stabile
     (+ eventuale pre-release piu' recente) e ne legge le label, producendo
     `.dst/repodata.json`;
   - valida `repodata.json` contro lo schema ufficiale con
     [`validate-repodata.py`](validate-repodata.py);
   - pubblica `.dst/` su **GitHub Pages**.

URL pubblico dell'indice:

```
https://startappsrl.github.io/ns8-startcredentials/repodata.json
```

L'indice viene ricostruito interamente dal registry a ogni release, quindi e'
sempre allineato alle versioni effettivamente pubblicate (operazione idempotente).

## File

| File | Ruolo |
|------|-------|
| `createrepo.py` | Genera `repodata.json` (derivato da `NethServer/ns8-repomd`, GPL-3.0; senza download da org terze). |
| `repodata-schema.json` | Copia dello schema ufficiale `ns8-core` per la validazione. |
| `validate-repodata.py` | Valida `repodata.json` contro lo schema + controlli extra. |
| `requirements.txt` | Dipendenze Python (`semver`, `filetype`, `jsonschema`). `skopeo` va installato a parte. |
| `startcredentials/logo.png` *(opzionale)* | Logo dedicato (PNG 256x256). Se assente si usa `ui/src/assets/module_default_logo.png`. |
| `startcredentials/screenshots/*.png` *(opzionale)* | Screenshot (PNG 1024x768). |

## Esecuzione locale (facoltativa)

```bash
sudo apt-get install -y skopeo
pip3 install -r ns8-repo/requirements.txt

mkdir -p .dst/startcredentials
cp ui/public/metadata.json .dst/startcredentials/metadata.json
cp ui/src/assets/module_default_logo.png .dst/startcredentials/logo.png
python3 ns8-repo/createrepo.py .dst
python3 ns8-repo/validate-repodata.py .dst/repodata.json ns8-repo/repodata-schema.json
```

## Prerequisito una tantum

In **Settings → Pages** del repository GitHub impostare **Source: GitHub Actions**
(il workflow usa `actions/deploy-pages`). Va fatto una sola volta.

## Iscrizione del cluster

Vedi [`docs/software-center.md`](../docs/software-center.md).

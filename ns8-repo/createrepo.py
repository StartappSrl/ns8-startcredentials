#!/usr/bin/env python3

#
# Copyright (C) 2021 Nethesis S.r.l.
# Copyright (C) 2026 Startapp S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Derivato da NethServer/ns8-repomd createrepo.py (GPL-3.0-or-later).
# Genera l'indice `repodata.json` di un repository software NethServer 8.
#
# Differenze rispetto all'originale, volute per un repository autocontenuto
# nel repo del singolo modulo:
#   * NESSUN download da raw.githubusercontent.com: metadata.json e logo.png
#     devono essere gia' presenti nella directory del modulo (nessuna
#     dipendenza di rete verso organizzazioni terze -> superficie ridotta,
#     coerente con la regola di revisione di sicurezza del progetto).
#   * skopeo interroga SOLO i registry indicati dal campo "source" dei
#     metadata locali.
# Il FORMATO di output e la logica di selezione delle versioni (filtro
# semver, ordine decrescente, ultima stabile + eventuali pre-release piu'
# recenti) sono IDENTICI all'originale, per restare compatibili con lo schema
# ufficiale ns8-core (repodata-schema.json) e con il Software Center.
#

import os
import sys
import copy
import json
import glob
import subprocess

import filetype
import semver


def is_pngfile(file_path):
    kind = filetype.guess(file_path)
    if kind is None:
        return False
    return kind.extension == 'png'


def skopeo_inspect(image_ref):
    """Esegue `skopeo inspect docker://<image_ref>` e ritorna il JSON."""
    with subprocess.Popen(
        ["skopeo", "inspect", "docker://" + image_ref],
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    ) as proc:
        return json.load(proc.stdout)


path = sys.argv[1] if len(sys.argv) >= 2 else '.'
index = []

defaults = {
    "name": "",
    "description": {"en": ""},
    "logo": None,
    "screenshots": [],
    "categories": ["unknown"],
    "authors": [{"name": "unknown", "email": "info@nethserver.org"}],
    "docs": {
        "documentation_url": "https://docs.nethserver.org",
        "bug_url": "https://github.com/NethServer/dev",
        "code_url": "https://github.com/NethServer/",
    },
    "source": "ghcr.io/nethserver",
    "versions": [],
}

# Ogni sottodirectory rappresenta un pacchetto; il nome e' l'id del modulo.
for entry_path in sorted(glob.glob(path + '/*')):
    if not os.path.isdir(entry_path):
        continue  # ignora i file (es. repodata.json, createrepo.py)

    entry_name = os.path.basename(entry_path.rstrip('/'))

    metadata = copy.deepcopy(defaults)
    metadata["name"] = entry_name
    metadata["description"]["en"] = f"Auto-generated description for {entry_name}"
    metadata["source"] = f"{metadata['source']}/{entry_name}"
    metadata["id"] = entry_name

    metadata_file = os.path.join(entry_path, "metadata.json")
    if not os.path.isfile(metadata_file):
        print(f'[ERROR] {metadata_file} mancante: salto {entry_name}', file=sys.stderr)
        continue

    with open(metadata_file) as metadata_fp:
        # i metadati locali hanno la precedenza sui default
        metadata = {**metadata, **json.load(metadata_fp)}

    # il logo e' incluso solo se e' un vero PNG
    logo = os.path.join(entry_path, "logo.png")
    if os.path.isfile(logo) and is_pngfile(logo):
        metadata["logo"] = "logo.png"

    # screenshot (PNG) opzionali
    metadata.setdefault("screenshots", [])
    screenshot_dir = os.path.join(entry_path, "screenshots")
    if os.path.isdir(screenshot_dir):
        with os.scandir(screenshot_dir) as sdir:
            for screenshot in sorted(sdir, key=lambda e: e.name):
                if is_pngfile(screenshot.path):
                    metadata["screenshots"].append(
                        os.path.join("screenshots", screenshot.name)
                    )

    print("Inspect " + metadata["source"], file=sys.stderr)
    metadata["versions"] = []
    try:
        repo_inspect = skopeo_inspect(metadata["source"])
        # scarta i tag non-semver e ordina dal piu' recente al piu' vecchio
        semver_tags = list(sorted(
            filter(semver.Version.is_valid, repo_inspect.get("RepoTags", [])),
            key=semver.Version.parse,
            reverse=True,
        ))
    except Exception as ex:
        print(f'[ERROR] cannot inspect {metadata["source"]}', ex, file=sys.stderr)
        continue

    testing_found = False  # registra se e' gia' stata trovata una pre-release
    for tag in semver_tags:
        semver_tag = semver.Version.parse(tag)

        if testing_found and semver_tag.prerelease is not None:
            # basta una sola pre-release (la piu' recente): salta le altre
            continue

        try:
            image_inspect = skopeo_inspect(f'{metadata["source"]}:{tag}')
            image_labels = image_inspect['Labels']
        except Exception as ex:
            print(f'[ERROR] cannot inspect {metadata["source"]}:{tag}', ex, file=sys.stderr)
            continue

        metadata["versions"].append({
            "tag": tag,
            "testing": semver_tag.prerelease is not None,
            "labels": image_labels,
        })
        print("* Add registry version", tag, file=sys.stderr)

        if semver_tag.prerelease is None:
            # serve solo l'ultima versione stabile: stop
            break
        else:
            testing_found = True

    if metadata["versions"]:
        index.append(metadata)
    else:
        print("[ERROR] no versions found for", metadata["source"], file=sys.stderr)

with open(os.path.join(path, 'repodata.json'), 'w') as outfile:
    json.dump(index, outfile, separators=(',', ':'))

print(f"[OK] scritto {os.path.join(path, 'repodata.json')} ({len(index)} moduli)", file=sys.stderr)

#!/usr/bin/env python3
#
# Copyright (C) 2026 Startapp S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Valida repodata.json contro lo schema ufficiale NethServer 8
# (repodata-schema.json, copia di ns8-core). Esce con codice != 0 se il
# file non e' conforme, cosi' la CI fallisce prima della pubblicazione.
#
# Uso:
#   python3 validate-repodata.py [repodata.json] [repodata-schema.json]
#

import json
import sys
import os

import jsonschema

here = os.path.dirname(os.path.abspath(__file__))
data_file = sys.argv[1] if len(sys.argv) >= 2 else os.path.join(here, "repodata.json")
schema_file = sys.argv[2] if len(sys.argv) >= 3 else os.path.join(here, "repodata-schema.json")

with open(schema_file) as fp:
    schema = json.load(fp)

with open(data_file) as fp:
    data = json.load(fp)

# Validazione strutturale contro lo schema ufficiale (Draft-07).
jsonschema.validate(instance=data, schema=schema)

# Controlli aggiuntivi non espressi dallo schema (lo schema ns8-core usa
# erroneamente "parameters" al posto di "properties" per authors/docs, quindi
# questi campi non verrebbero verificati: li controlliamo a mano).
errors = []
if not isinstance(data, list) or not data:
    errors.append("repodata.json deve essere un array non vuoto")

for mod in data:
    mid = mod.get("id") or mod.get("name") or "?"
    if not mod.get("versions"):
        errors.append(f"[{mid}] nessuna versione presente")
    src = mod.get("source", "")
    if src.startswith("docker://") or "://" in src:
        errors.append(f"[{mid}] 'source' non deve contenere il prefisso docker:// : {src}")
    docs = mod.get("docs", {})
    for k in ("documentation_url", "bug_url", "code_url"):
        if not docs.get(k):
            errors.append(f"[{mid}] docs.{k} mancante")
    for v in mod.get("versions", []):
        for k in ("tag", "testing", "labels"):
            if k not in v:
                errors.append(f"[{mid}] versione {v.get('tag','?')}: campo '{k}' mancante")
        if not isinstance(v.get("labels"), dict):
            errors.append(f"[{mid}] versione {v.get('tag','?')}: 'labels' deve essere un oggetto")

if errors:
    print("[FAIL] repodata.json non conforme:", file=sys.stderr)
    for e in errors:
        print("  -", e, file=sys.stderr)
    sys.exit(1)

print(f"[OK] {data_file} conforme allo schema NS8 ({len(data)} moduli)")

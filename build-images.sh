#!/bin/bash

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Terminate on error
set -e

# Prepare variables for later use
images=()
# The image will be pushed to GitHub container registry
repobase="${REPOBASE:-ghcr.io/startappsrl}"
# Configure the image name
reponame="startcredentials"

# Create a new empty container image
container=$(buildah from scratch)

# Reuse existing nodebuilder-startcredentials container, to speed up builds
if ! buildah containers --format "{{.ContainerName}}" | grep -q nodebuilder-startcredentials; then
    echo "Pulling NodeJS runtime..."
    buildah from --name nodebuilder-startcredentials -v "${PWD}:/usr/src:Z" docker.io/library/node:24.21.0-slim
fi

echo "Build static UI files with node..."
buildah run \
    --workingdir=/usr/src/ui \
    --env="NODE_OPTIONS=--openssl-legacy-provider" \
    nodebuilder-startcredentials \
    sh -c "corepack enable && yarn install && yarn build"

# Immagine dell'applicazione (API, pagina iniziale, estensione scaricabile)
echo "Build dell'immagine applicativa..."
buildah bud --layers -f app/Containerfile -t "${repobase}/${reponame}-app" .
images+=("${repobase}/${reponame}-app")

# Gli script del modulo devono essere eseguibili: l'agente NS8 salta i
# passaggi senza permesso di esecuzione.
find imageroot/actions -type f ! -name '*.json' -exec chmod 755 {} +
chmod 755 imageroot/bin/* imageroot/events/*/*

# Add imageroot directory to the container image
buildah add "${container}" imageroot /imageroot
buildah add "${container}" ui/dist /ui
# Setup the entrypoint, ask to reserve one TCP port with the label and set a rootless container
buildah config --entrypoint=/ \
    --label="org.nethserver.authorizations=traefik@node:routeadm" \
    --label="org.nethserver.tcp-ports-demand=1" \
    --label="org.nethserver.rootfull=0" \
    --label="org.nethserver.images=${repobase}/${reponame}-app:${IMAGETAG:-latest} docker.io/library/postgres:16.6-alpine" \
    "${container}"
# Commit the image
buildah commit "${container}" "${repobase}/${reponame}"

# Append the image URL to the images array
images+=("${repobase}/${reponame}")

#
# NOTICE:
#
# It is possible to build and publish multiple images.
#
# 1. create another buildah container
# 2. add things to it and commit it
# 3. append the image url to the images array
#

#
# Setup CI when pushing to Github. 
# Warning! docker::// protocol expects lowercase letters (,,)
if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "images=%s\n" "${images[*],,}" >> "${GITHUB_OUTPUT}"
else
    # Just print info for manual push
    printf "Publish the images with:\n\n"
    for image in "${images[@],,}"; do printf "  buildah push %s docker://%s:%s\n" "${image}" "${image}" "${IMAGETAG:-latest}" ; done
    printf "\n"
fi

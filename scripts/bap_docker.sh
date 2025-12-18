#!/bin/bash
#
# bap_docker.sh
# Wrapper to run BAP in Docker container
# Usage: ./bap_docker.sh <binary_path> [bap_options]
#

set -e

# Get absolute path to binary
BINARY_PATH="$(readlink -f "$1")"
shift  # Remove first argument

if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found: $BINARY_PATH" >&2
    exit 1
fi

# Docker image for BAP
BAP_IMAGE="binaryanalysisplatform/bap:latest"

# Pull image if not present
if ! docker image inspect "$BAP_IMAGE" &>/dev/null; then
    echo "Pulling BAP Docker image..." >&2
    docker pull "$BAP_IMAGE" >&2
fi

# Get directory and filename
BINARY_DIR="$(dirname "$BINARY_PATH")"
BINARY_NAME="$(basename "$BINARY_PATH")"

# Run BAP in Docker with binary mounted
docker run --rm \
    -v "$BINARY_DIR:/workdir:ro" \
    "$BAP_IMAGE" \
    bap "/workdir/$BINARY_NAME" "$@"

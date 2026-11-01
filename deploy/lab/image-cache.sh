#!/usr/bin/env bash
# Phase 5.6 Item 10: this session's own build pain, automated away - the
# manager/agent-ubuntu/agent-rocky images took hours to build from scratch
# more than once, and a lost background process or a stuck build killed
# partway through (both happened repeatedly this session) meant starting
# over from zero rather than resuming. `docker save` after a known-good
# build, to a location OUTSIDE the repo (never committed, these are
# multi-GB), lets a fresh checkout or a wiped local Docker image cache
# `docker load` straight back to where the build left off instead of
# rebuilding.
#
# Usage:
#   ./image-cache.sh save              # save manager/agent-ubuntu/agent-rocky
#   ./image-cache.sh load              # load them back
#   SHADOWTRACER_IMAGE_CACHE=/other/path ./image-cache.sh save
set -euo pipefail

CACHE_DIR="${SHADOWTRACER_IMAGE_CACHE:-$HOME/.cache/shadowtracer-images}"
IMAGES=(
  "shadowtracer-lab/manager:local"
  "shadowtracer-lab/agent-ubuntu:local"
  "shadowtracer-lab/agent-rocky:local"
)

cmd="${1:-}"
case "$cmd" in
  save)
    mkdir -p "$CACHE_DIR"
    for image in "${IMAGES[@]}"; do
      file="$CACHE_DIR/${image//[:\/]/_}.tar"
      echo "saving $image -> $file"
      docker save "$image" -o "$file"
    done
    echo "done - $(du -sh "$CACHE_DIR" | cut -f1) in $CACHE_DIR"
    ;;
  load)
    for image in "${IMAGES[@]}"; do
      file="$CACHE_DIR/${image//[:\/]/_}.tar"
      if [ ! -f "$file" ]; then
        echo "missing $file - run './image-cache.sh save' first on a machine that has $image built" >&2
        exit 1
      fi
      echo "loading $file"
      docker load -i "$file"
    done
    echo "done - verify with: docker images | grep shadowtracer-lab"
    ;;
  *)
    echo "usage: $0 save|load" >&2
    exit 1
    ;;
esac

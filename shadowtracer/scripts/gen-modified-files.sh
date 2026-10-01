#!/usr/bin/env bash
# Prints every inherited-path change (added/modified/deleted) vs the
# v4.14.8 fork point, one "STATUS<TAB>path" line per change, sorted.
# shadowtracer/ and deploy/ are ours, not inherited, so they're excluded.
#
# Regenerate the committed copy with:
#   shadowtracer/scripts/gen-modified-files.sh > shadowtracer/docs/MODIFIED_FILES.txt
set -euo pipefail
cd "$(dirname "$0")/../.."
git diff --name-status v4.14.8 -- . ':!shadowtracer' ':!deploy' | sort

#!/usr/bin/env bash
# Snapshots every user-visible "Wazuh" occurrence in the files Phase 2
# Pass A/B actually rebrand (installer prompts, control script banners,
# systemd units, the API spec, rule descriptions, version.rc, packaging
# text) - the same surface listed in UPSTREAM.md's Pass A/B rows. Prints
# "path:line:text", sorted. check-project.sh fails if a FRESH scan finds
# any line not already in the committed snapshot (shadowtracer/docs/
# ALLOWLIST_WAZUH_TEXT.txt) - a line disappearing (fixed) is fine, a new
# one appearing (an unreviewed Wazuh mention added to user-facing text)
# is not.
#
# Regenerate the committed copy with:
#   shadowtracer/scripts/gen-wazuh-text-allowlist.sh > shadowtracer/docs/ALLOWLIST_WAZUH_TEXT.txt
set -euo pipefail
cd "$(dirname "$0")/../.."

git grep -nw "Wazuh" -- \
    'src/init/templates/*.service' \
    'etc/templates/**' \
    'install.sh' \
    'src/init/wazuh-server.sh' \
    'src/init/wazuh-client.sh' \
    'src/init/wazuh-local.sh' \
    'src/init/pkg_installer.sh' \
    'api/api/spec/spec.yaml' \
    'ruleset/rules/*.xml' \
    'src/win32/version.rc' \
    'packages/debs/SPECS/*/debian/control' \
    'packages/debs/SPECS/*/debian/postinst' \
    'packages/rpms/SPECS/*.spec' \
    2>/dev/null | sort

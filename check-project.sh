#!/usr/bin/env bash
# Fails loudly if the repo's Phase 0 invariants are broken.
set -u
cd "$(dirname "$0")"

fail=0
die() { echo "FAIL: $1" >&2; fail=1; }

# install.sh (the entry point) must be executable. src/init/*.sh is not
# checked blanket: several of those files are upstream library scripts
# meant to be `source`d, not executed, and are never +x in upstream.
[ -x install.sh ] || die "install.sh is not executable"

# No CRLF in tracked shell scripts
crlf=$(git grep -lI $'\r' -- '*.sh' 2>/dev/null)
[ -z "$crlf" ] || die "CRLF found in: $(echo "$crlf" | tr '\n' ' ')"

# http-request submodule must be present and populated
[ -d src/shared_modules/http-request ] || die "src/shared_modules/http-request is missing"
[ -n "$(ls -A src/shared_modules/http-request 2>/dev/null)" ] || die "src/shared_modules/http-request submodule is empty (not initialized)"

# UPSTREAM.md must exist
[ -f UPSTREAM.md ] || die "UPSTREAM.md is missing"

# LICENSE must credit Wazuh Inc.
grep -q "Wazuh Inc." LICENSE 2>/dev/null || die "LICENSE does not mention 'Wazuh Inc.'"

# Fork point must still trace back to v4.14.8
if git rev-parse v4.14.8^{commit} >/dev/null 2>&1; then
    mb=$(git merge-base HEAD v4.14.8 2>/dev/null)
    v=$(git rev-parse v4.14.8^{commit})
    [ "$mb" = "$v" ] || die "git merge-base HEAD v4.14.8 ($mb) is not the v4.14.8 commit ($v)"
else
    die "v4.14.8 tag not found locally (git fetch upstream tag v4.14.8 first)"
fi

if [ "$fail" -eq 0 ]; then
    echo "check-project.sh: OK"
else
    exit 1
fi

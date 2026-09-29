#!/usr/bin/env bash
# Fails loudly if the repo's Phase 0 invariants are broken.
set -u
cd "$(dirname "$0")"

fail=0
die() { echo "FAIL: $1" >&2; fail=1; }

# No CRLF in tracked shell scripts
crlf=$(git grep -lI $'\r' -- '*.sh' 2>/dev/null)
[ -z "$crlf" ] || die "CRLF found in: $(echo "$crlf" | tr '\n' ' ')"

# No file outside our own paths (shadowtracer/, deploy/) may have a
# different mode (e.g. lost/gained an exec bit) from v4.14.8.
if git rev-parse v4.14.8^{commit} >/dev/null 2>&1; then
    mode_changes=$(git diff --summary v4.14.8 -- . ':!shadowtracer' ':!deploy' 2>/dev/null | grep 'mode change')
    [ -z "$mode_changes" ] || die "file mode changed vs v4.14.8 outside shadowtracer/ and deploy/: $(echo "$mode_changes" | tr '\n' ';')"

    # Every inherited file that changed or was deleted vs v4.14.8 must be
    # recorded in UPSTREAM.md's "Wazuh files we modified" table.
    patterns=$(grep -oE '^\| `[^`]+`' UPSTREAM.md | sed -E 's/^\| `//; s/`$//')
    missing=""
    while IFS=$'\t' read -r status path; do
        case "$status" in M|D) ;; *) continue ;; esac
        matched=0
        while IFS= read -r pat; do
            [ -z "$pat" ] && continue
            case "$path" in $pat) matched=1; break ;; esac
        done <<<"$patterns"
        [ "$matched" -eq 1 ] || missing="$missing $path"
    done < <(git diff --name-status v4.14.8 -- . ':!shadowtracer' ':!deploy' 2>/dev/null)
    [ -z "$missing" ] || die "inherited file(s) changed/deleted but not recorded in UPSTREAM.md:$missing"
fi

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

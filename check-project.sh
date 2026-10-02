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

    # shadowtracer/docs/MODIFIED_FILES.txt must exactly match the real
    # inherited-path diff - it's generated, not hand-maintained, so a stale
    # copy means someone changed an inherited file and forgot to rerun
    # gen-modified-files.sh (or regenerate it and forgot to commit it).
    current_diff=$(shadowtracer/scripts/gen-modified-files.sh 2>/dev/null)
    committed_list=$(cat shadowtracer/docs/MODIFIED_FILES.txt 2>/dev/null)
    if [ "$current_diff" != "$committed_list" ]; then
        die "shadowtracer/docs/MODIFIED_FILES.txt is stale - rerun shadowtracer/scripts/gen-modified-files.sh and commit the result"
    fi

    # Every path in MODIFIED_FILES.txt must match a Patterns entry in
    # UPSTREAM.md's change-categories table - a reason recorded by category,
    # not hunted down file by file after the fact.
    patterns=$(awk -F'|' '/^\|/{print $3}' UPSTREAM.md | grep -oE '`[^`]+`' | sed -E 's/`//g')
    missing=""
    while IFS=$'\t' read -r status path; do
        [ -z "$path" ] && continue
        matched=0
        while IFS= read -r pat; do
            [ -z "$pat" ] && continue
            case "$path" in $pat) matched=1; break ;; esac
        done <<<"$patterns"
        [ "$matched" -eq 1 ] || missing="$missing $path"
    done <<<"$committed_list"
    [ -z "$missing" ] || die "inherited path(s) changed but not covered by any category in UPSTREAM.md:$missing"
fi

# No "wazuh-control", "wazuh-manager.service" or "wazuh-agent.service"
# outside the allowlist - Phase 2 Pass B renamed these; any other hit is a
# real leftover reference, not a style nit (this is how Pass B itself
# found wodles/utils.py, wazuh_logtest.py, two cgroup-path lookups, and a
# stale API spec example still pointing at the old names).
control_name_patterns=$(grep -vE '^\s*#|^\s*$' shadowtracer/docs/ALLOWLIST_CONTROL_NAMES.txt 2>/dev/null)
control_name_hits=$(git grep -lE 'wazuh-control|wazuh-manager\.service|wazuh-agent\.service' -- . ':!.git' 2>/dev/null)
missing=""
while IFS= read -r path; do
    [ -z "$path" ] && continue
    matched=0
    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        case "$path" in $pat) matched=1; break ;; esac
    done <<<"$control_name_patterns"
    [ "$matched" -eq 1 ] || missing="$missing $path"
done <<<"$control_name_hits"
[ -z "$missing" ] || die "wazuh-control/wazuh-*.service found outside shadowtracer/docs/ALLOWLIST_CONTROL_NAMES.txt:$missing"

# User-visible "Wazuh" text scan: fail only on a NEW occurrence (one not
# already in the committed snapshot) in the Pass A/B text surface - a
# line disappearing (fixed) is fine, a new one appearing is not.
if [ -f shadowtracer/docs/ALLOWLIST_WAZUH_TEXT.txt ]; then
    current_wazuh_text=$(shadowtracer/scripts/gen-wazuh-text-allowlist.sh 2>/dev/null)
    new_wazuh_text=$(comm -23 <(echo "$current_wazuh_text") <(sort shadowtracer/docs/ALLOWLIST_WAZUH_TEXT.txt))
    [ -z "$new_wazuh_text" ] || die "new user-visible 'Wazuh' text not in shadowtracer/docs/ALLOWLIST_WAZUH_TEXT.txt (rerun shadowtracer/scripts/gen-wazuh-text-allowlist.sh and review/commit if intentional):$(echo "$new_wazuh_text" | tr '\n' ';')"
else
    die "shadowtracer/docs/ALLOWLIST_WAZUH_TEXT.txt is missing"
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

# Phase 3: a shipper/writer test suite that only proves normalize_alert()
# or insert_batch() work when called directly would miss a main loop that
# never actually starts draining - require a test that starts run() in a
# thread/process and checks real output instead (see
# test_{shipper,writer}_is_actually_running_and_draining_not_just_callable).
for component in shipper writer; do
    test_file="shadowtracer/ingest/tests/test_${component}.py"
    if [ -f "$test_file" ]; then
        grep -qE "^def test_.*${component}.*draining" "$test_file" \
            || die "$test_file has no started-and-draining test (a test function matching test_.*${component}.*draining)"
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "check-project.sh: OK"
else
    exit 1
fi

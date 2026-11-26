#!/bin/bash
# Offline self-check for shadowtracer-yara-scan (bash AR script): FIM-path confinement, re-hash before
# report (changed/gone), and one flat JSON line per match. Uses a stub `yr` and a temp FIM root — no
# real YARA-X, no agent. Run: bash test-yara-scan.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../shadowtracer-yara-scan"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FIM="$TMP/fim"; mkdir -p "$FIM"
OUT="$TMP/out.log"

# stub yr: "match" if the scanned file contains MATCHME, else nothing
cat > "$TMP/yr" <<'EOF'
#!/bin/bash
f="${@: -1}"; grep -q MATCHME "$f" 2>/dev/null && echo "default:ST_TEST_RULE $f"
exit 0
EOF
chmod +x "$TMP/yr"
run() { ST_YARA_BIN="$TMP/yr" ST_YARA_RULES="$TMP/rules.yarc" ST_YARA_LOG="$OUT" \
        ST_YARA_FIM_DIRS="$FIM" bash "$SCRIPT"; }
touch "$TMP/rules.yarc"

# 1. path outside a FIM root -> refused
: > "$OUT"; echo '{"parameters":{"alert":{"syscheck":{"path":"/outside/x"}}}}' | run
grep -q '"status":"refused"' "$OUT" || { echo "FAIL: outside path not refused"; exit 1; }

# 2. file inside FIM, matching rule -> one match line with the rule
printf 'hello MATCHME world' > "$FIM/evil"
sha=$(sha256sum "$FIM/evil" | awk '{print $1}')
: > "$OUT"; echo "{\"parameters\":{\"alert\":{\"syscheck\":{\"path\":\"$FIM/evil\",\"sha256_after\":\"$sha\"}}}}" | run
grep -q '"status":"match"' "$OUT" && grep -q '"yara_rule":"ST_TEST_RULE"' "$OUT" || { echo "FAIL: match not emitted"; cat "$OUT"; exit 1; }

# 3. sha changed since the alert -> "changed", not scanned
: > "$OUT"; echo "{\"parameters\":{\"alert\":{\"syscheck\":{\"path\":\"$FIM/evil\",\"sha256_after\":\"deadbeef\"}}}}" | run
grep -q '"status":"changed"' "$OUT" || { echo "FAIL: changed not reported"; exit 1; }

# 4. file gone -> "gone"
: > "$OUT"; echo "{\"parameters\":{\"alert\":{\"syscheck\":{\"path\":\"$FIM/missing\"}}}}" | run
grep -q '"status":"gone"' "$OUT" || { echo "FAIL: gone not reported"; exit 1; }

# 5. benign file inside FIM, no rule match -> "no_match"
printf 'nothing here' > "$FIM/benign"
: > "$OUT"; echo "{\"parameters\":{\"alert\":{\"syscheck\":{\"path\":\"$FIM/benign\"}}}}" | run
grep -q '"status":"no_match"' "$OUT" || { echo "FAIL: no_match not reported"; exit 1; }

echo "shadowtracer-yara-scan self-check ok"

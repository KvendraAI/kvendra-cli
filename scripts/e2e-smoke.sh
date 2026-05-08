#!/usr/bin/env bash
# E2E smoke harness — REQ-KVD-CLI-001 / ISSUE-KVD-CLI-037
# Ejercita las 7 fases T1/T1.5/T2/T3/D/E/F contra el binario real.
# Mitigates PAT-KVD-004 (shape MCP real).

set -euo pipefail

# ---------- Config ----------
KVENDRA_BIN="${KVENDRA_BIN:-./target/release/kvendra}"   # default release build
SMOKE_PASSWORD="smoke-test-hunter2-${RANDOM}"            # ephemeral
SMOKE_PROFILE_OK="smoke-git-readonly"
SMOKE_PROFILE_DENY="smoke-aws-out-of-scope"
SKIP_T1_5="${SMOKE_SKIP_T1_5:-1}"                        # default skip (Apple Dev ID gated)

# ---------- Tempdir + cleanup ----------
TMPHOME="$(mktemp -d -t kvendra-smoke-XXXXXX)"
export KVENDRA_HOME="$TMPHOME"
cleanup() {
  local rc=$?
  echo "[F] cleanup: rm -rf $TMPHOME"
  rm -rf "$TMPHOME" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------- Helpers ----------
phase()  { printf '\n=== [%s] %s ===\n' "$1" "$2"; }
fail()   { printf '\nFAIL [%s]: %s\n' "$1" "$2" >&2; exit "$3"; }
assert_perm() {
  local f="$1" want="$2"
  local got
  got=$(stat -f '%A' "$f" 2>/dev/null || stat -c '%a' "$f")
  [ "$got" = "$want" ] || fail "T1" "perms $f: got 0$got want 0$want" 11
}

# ---------- T1: init ----------
phase T1 "kvendra init"
KVENDRA_INIT_PASSWORD="$SMOKE_PASSWORD" \
KVENDRA_INIT_CONFIRM_CODE="0" \
"$KVENDRA_BIN" init --no-verify >/dev/null \
  || fail T1 "init failed" 10

[ -f "$TMPHOME/audit.db" ]            || fail T1 "audit.db missing" 12
[ -f "$TMPHOME/recovery_codes.json" ] || fail T1 "recovery_codes.json missing" 13
[ -f "$TMPHOME/sentinel.blob" ]       || fail T1 "sentinel.blob missing" 14
[ -f "$TMPHOME/config.toml" ]         || fail T1 "config.toml missing" 15
assert_perm "$TMPHOME/recovery_codes.json" 600
assert_perm "$TMPHOME/config.toml" 600
T1_AUDIT_JSON_OUT=$("$KVENDRA_BIN" audit --json)
echo "$T1_AUDIT_JSON_OUT" | grep -q vault_created || fail T1 "no vault_created audit row" 16

# ---------- T1.5: keychain ACL (gated) ----------
phase T1.5 "kvendra config mcp-password enable"
if [ "$SKIP_T1_5" = "0" ] && [ "$(uname)" = "Darwin" ]; then
  printf '%s\n%s\n' "$SMOKE_PASSWORD" "$SMOKE_PASSWORD" | \
    "$KVENDRA_BIN" config mcp-password enable >/dev/null \
    || fail T1.5 "mcp-password enable failed" 20
else
  echo "[T1.5] skipped (pending-automation:apple-id-ci)"
fi

# ---------- T2: secret add + set-allowlist + validate ----------
phase T2 "kvendra secret add/set-allowlist/validate"
SMOKE_SECRET_VAR=SMOKE_TEST_TOKEN
export SMOKE_TEST_TOKEN="ghp_smoketest$(printf '%036d' $RANDOM)"

printf '%s\n' "$SMOKE_PASSWORD" | \
  "$KVENDRA_BIN" secret add "$SMOKE_PROFILE_OK" \
    --secret-env "$SMOKE_SECRET_VAR" \
    --secret-type github_pat \
    --password-stdin >/dev/null \
  || fail T2 "secret add failed" 30

ALLOWLIST_FILE="$TMPHOME/allow-ok.yaml"
cat >"$ALLOWLIST_FILE" <<'YAML'
profile_id: smoke-git-readonly
secret:
  type: github_pat
allowlist:
  primitives:
    - name: kvendra.git
      operations:
        - clone:
            repos: ["github.com/KvendraAI/kvendra-cli"]
        - pull:
            repos: ["github.com/KvendraAI/kvendra-cli"]
            refs: ["refs/heads/main"]
expiration: 2099-12-31
audit_level: minimal
YAML

printf '%s\n' "$SMOKE_PASSWORD" | \
  "$KVENDRA_BIN" secret set-allowlist "$SMOKE_PROFILE_OK" \
    --file "$ALLOWLIST_FILE" \
    --password-stdin >/dev/null \
  || fail T2 "set-allowlist failed" 31

T2_VALIDATE_OUT=$("$KVENDRA_BIN" secret validate "$SMOKE_PROFILE_OK")
echo "$T2_VALIDATE_OUT" | grep -q "VALID" \
  || fail T2 "validate not green" 32

[ -f "$TMPHOME/secrets/$SMOKE_PROFILE_OK.blob" ] || fail T2 "blob not written" 33
T2_GETMETA_OUT=$("$KVENDRA_BIN" secret get-meta "$SMOKE_PROFILE_OK")
echo "$T2_GETMETA_OUT" | grep -q "allowlist_hmac_hex" \
  || fail T2 "HMAC sidecar missing in profile meta" 34

# ---------- T3: mcp serve + JSON-RPC roundtrip ----------
phase T3 "kvendra mcp serve — initialize/tools/list/tools/call shape MCP real"
MCP_FIFO_IN="$TMPHOME/mcp.in"
MCP_FIFO_OUT="$TMPHOME/mcp.out"
mkfifo "$MCP_FIFO_IN" "$MCP_FIFO_OUT"

KVENDRA_MCP_PASSWORD="$SMOKE_PASSWORD" \
  "$KVENDRA_BIN" mcp serve <"$MCP_FIFO_IN" >"$MCP_FIFO_OUT" &
MCP_PID=$!

exec 3>"$MCP_FIFO_IN"
exec 4<"$MCP_FIFO_OUT"

send() { printf '%s\n' "$1" >&3; }
recv() { read -r -u 4 line; printf '%s' "$line"; }

# initialize
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}'
RESP="$(recv)"
echo "$RESP" | grep -q '"id":1'                       || fail T3 "initialize id mismatch (E2E-D-3 finding?)" 40
echo "$RESP" | grep -q '"protocolVersion":"2025-03-26"' || fail T3 "initialize protocolVersion wrong" 41
echo "$RESP" | grep -q '"name":"kvendra"'             || fail T3 "initialize serverInfo.name wrong" 42

# tools/list
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
RESP="$(recv)"
for tool in kvendra.git kvendra.github kvendra.npm kvendra.pypi kvendra.aws kvendra.http kvendra.shell kvendra.unsafe.raw_token; do
  echo "$RESP" | grep -q "\"$tool\"" || fail T3 "tools/list missing $tool" 43
done
echo "$RESP" | grep -q '\[UNSAFE\]' || fail T3 "unsafe escape hatch not flagged" 44

# tools/call — SHAPE MCP REAL ENVELOPE (PAT-KVD-004 critical)
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kvendra.git","arguments":{"profile_id":"smoke-git-readonly","operation":"clone","args":{"repo":"github.com/KvendraAI/kvendra-cli"}}}}'
RESP="$(recv)"
echo "$RESP" | grep -q '"id":3' || fail T3 "tools/call id mismatch" 45
if echo "$RESP" | grep -qiE 'allowlist[ _]?violation'; then
  fail T3 "false-positive AllowlistViolation on in-scope call (PAT-KVD-004 RECURRENCE?)" 46
fi

# ---------- D: boundary tests — out-of-scope must reject ----------
phase D "boundary — out-of-scope must reject AllowlistViolation"
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"kvendra.git","arguments":{"profile_id":"smoke-git-readonly","operation":"push","args":{"repo":"github.com/attacker-org/evil","ref":"refs/heads/main"}}}}'
RESP="$(recv)"
echo "$RESP" | grep -qiE 'allowlist[ _]?violation|not allowed|out of scope' \
  || fail D "out-of-scope did NOT trigger AllowlistViolation (PAT-KVD-004 RECURRENCE?)" 50
echo "$RESP" | grep -q '"id":4' || fail D "boundary response id mismatch" 51

exec 3>&-
exec 4<&-
wait "$MCP_PID" 2>/dev/null || true

# ---------- E: audit --verify ----------
phase E "kvendra audit --verify"
E_AUDIT_VERIFY_OUT=$(printf '%s\n' "$SMOKE_PASSWORD" | "$KVENDRA_BIN" audit --verify --password-stdin)
echo "$E_AUDIT_VERIFY_OUT" | grep -q "Audit chain valid" \
  || fail E "audit chain BROKEN (PAT-KVD-004 recurrence on UPDATE path?)" 60

"$KVENDRA_BIN" audit --json > "$TMPHOME/audit.json"
ROW_COUNT=$(grep -c '"id"' "$TMPHOME/audit.json" || true)
[ "$ROW_COUNT" -ge 3 ] || fail E "expected >=3 audit rows, got $ROW_COUNT" 61
grep -q 'allowlist_violation\|AllowlistViolation\|allowlist_denied' "$TMPHOME/audit.json" \
  || fail E "no boundary-violation row in audit log" 62

# ---------- F: cleanup (handled by trap) ----------
phase F "cleanup (trap)"
echo
echo "=== ALL PHASES PASSED ==="
echo "Baseline: $($KVENDRA_BIN --version)"
echo "Tempdir:  $TMPHOME (will be removed)"
exit 0

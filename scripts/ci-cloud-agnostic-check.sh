#!/usr/bin/env bash
# Lint guard — REQ-KVD-CLI-004 AC-RESOLVER-8 + ADR-KVD-026.
#
# Enforces that the cloud-agnostic wire layers (secret_resolver, auth,
# protocol, workspace, session) NEVER mention provider-specific strings.
# A leak into these paths means the abstraction has been broken in a way
# that ties the CLI to AWS-specific concepts; the fix is to push the
# string back behind a cloud-provider-shaped boundary in the broker.
#
# Mirrors STD-KVD-ENTERPRISE-001 §6 (the kvendra-enterprise sibling).

set -e

# Resolve to the repo root regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

WIRE_PATHS=(
  "src/secret_resolver"
  "src/auth"
  "src/protocol"
  "src/workspace"
  "src/session"
)

# Case-insensitive: forbidden vendor strings inside the wire-agnostic layer.
# Doc comments can use the words inside `// allowed:` exceptions.
FORBIDDEN_PATTERN='\b(cognito|dynamodb|aws-managed|kms-managed|stsassumerole)\b'

VIOLATIONS=0

for dir in "${WIRE_PATHS[@]}"; do
  if [ -d "$dir" ]; then
    if matches=$(grep -rIniE "$FORBIDDEN_PATTERN" "$dir" \
                  --include="*.rs" \
                  | grep -v '// allowed:' \
                  | grep -v 'allowed-leak-justified' || true); then
      if [ -n "$matches" ]; then
        echo "❌ Cloud provider strings leaked in wire-agnostic path '$dir':"
        echo "$matches"
        VIOLATIONS=$((VIOLATIONS + 1))
      fi
    fi
  fi
done

if [ "$VIOLATIONS" -gt 0 ]; then
  echo ""
  echo "✘ Cloud-agnostic check FAILED. $VIOLATIONS path(s) with violations."
  echo ""
  echo "Fix: push the provider-specific identifier back to a generic OIDC /"
  echo "broker-shaped name (client_id, broker_url, ...) or move the file"
  echo "outside the wire-agnostic layer."
  exit 1
fi

echo "✓ Cloud-agnostic check passed — 0 vendor strings in wire layers."

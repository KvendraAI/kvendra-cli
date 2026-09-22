#!/usr/bin/env bash
# Lint guard — SA10 (ISSUE-KVD-CLI-0F929A), supply chain of a binary crate.
#
# Enforces that the resolved dependency graph is versioned and actually
# bound to every CI build:
#   1. Cargo.lock is tracked by git and not ignored.
#   2. Every dependency-resolving cargo invocation in .github/workflows
#      passes --locked (cargo fmt rejects the flag and must not get it).
#   3. A blocking cargo-deny job exists and runs with --locked.
#
# Mirrors scripts/ci-cloud-agnostic-check.sh.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

WORKFLOWS=".github/workflows"
VIOLATIONS=0

fail() {
  echo "❌ $1"
  VIOLATIONS=$((VIOLATIONS + 1))
}

# `git ls-files Cargo.lock` alone exits 0 with empty output: --error-unmatch
# is what makes this check non-inert.
if ! git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then
  fail "Cargo.lock is not tracked by git."
fi

if git check-ignore -q Cargo.lock; then
  fail "Cargo.lock is gitignored: $(git check-ignore -v Cargo.lock)"
fi

CARGO_LINES=$(grep -nE '\bcargo (build|test|check|clippy|run|doc|install|bench)\b' "$WORKFLOWS"/*.yml || true)
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    *--locked*) ;;
    *) fail "cargo invocation without --locked: $line" ;;
  esac
done <<< "$CARGO_LINES"

FMT_LOCKED=$(grep -nE '\bcargo fmt\b.*--locked' "$WORKFLOWS"/*.yml || true)
if [ -n "$FMT_LOCKED" ]; then
  fail "cargo fmt does not accept --locked: $FMT_LOCKED"
fi

if ! grep -qE 'EmbarkStudios/cargo-deny-action|cargo[- ]deny' "$WORKFLOWS"/*.yml; then
  fail "no cargo-deny job in $WORKFLOWS (deny.toml would never be executed)."
fi

if ! grep -A6 -E 'EmbarkStudios/cargo-deny-action' "$WORKFLOWS"/*.yml | grep -qE 'arguments:.*--locked'; then
  fail "cargo-deny step does not pass --locked in its arguments."
fi

if grep -B8 -A6 -E 'EmbarkStudios/cargo-deny-action' "$WORKFLOWS"/*.yml | grep -qE 'continue-on-error:[[:space:]]*true'; then
  fail "cargo-deny job is non-blocking (continue-on-error)."
fi

if [ "$VIOLATIONS" -gt 0 ]; then
  echo ""
  echo "✘ Supply-chain check FAILED. $VIOLATIONS violation(s)."
  exit 1
fi

echo "✓ Supply-chain check passed — lockfile versioned, --locked everywhere, cargo-deny wired."

#!/usr/bin/env bash
# Regenerate Rust types from the closed-source OpenAPI 3.1 spec.
#
# Per ADR-KVD-026, the wire protocol is published as both:
#   - A canonical OpenAPI 3.1 document inside the closed-source server repo
#     (`packages/protocol-spec/openapi.yaml` of KvendraAI/kvendra-enterprise).
#   - Human-readable markdown in this repo (`docs/protocols/v1.md`).
#
# This script consumes the closed-source YAML — it is expected to live at the
# adjacent sibling path `../kvendra-enterprise/packages/protocol-spec/openapi.yaml`
# during development. CI builds use a stamped copy.
#
# Outputs `src/protocol/v1.rs`.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SPEC_PATH="${KVENDRA_SPEC_PATH:-${ROOT}/../kvendra-enterprise/packages/protocol-spec/openapi.yaml}"
OUTPUT_PATH="${ROOT}/src/protocol/v1.rs"

if [ ! -f "$SPEC_PATH" ]; then
  echo "ERROR: OpenAPI spec not found at $SPEC_PATH"
  echo "Set KVENDRA_SPEC_PATH or clone kvendra-enterprise alongside kvendra-cli."
  exit 1
fi

if ! command -v progenitor >/dev/null 2>&1; then
  echo "ERROR: progenitor CLI not installed. Install with:"
  echo "  cargo install progenitor-cli"
  echo
  echo "If you are not yet wiring the broker client (M0b is the scaffolding"
  echo "sprint; M1 Sprint 4 is where kvendra-cli starts consuming these types),"
  echo "you can leave src/protocol/v1.rs as the empty stub it ships as."
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

echo "Generating Rust client types from $SPEC_PATH ..."
progenitor \
  --input "$SPEC_PATH" \
  --output "$OUTPUT_PATH" \
  --interface positional

echo "✓ Wrote $OUTPUT_PATH"
echo
echo "Next: run 'cargo build -p kvendra' to verify the generated module compiles."

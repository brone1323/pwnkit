#!/usr/bin/env bash
# bun-compile.sh — produce a self-contained pwnkit binary via `bun build --compile`.
#
# Usage:
#   scripts/bun-compile.sh                    # compile for the host platform
#   scripts/bun-compile.sh bun-linux-x64      # cross-compile for a specific target
#   scripts/bun-compile.sh bun-darwin-arm64 ./dist-bin/pwnkit-darwin-arm64
#
# Must be run from the repo root. Assumes pnpm install + pnpm -r build have
# already run (workspace packages need their dist/ directories so Bun can
# resolve @pwnkit/shared etc.).
#
# Externals are chosen to match the runtime pattern in the source:
#   - playwright / playwright-core / electron / chromium-bidi  — loaded via
#     try/catch dynamic import in racing.ts / oracles.ts / egats.ts. Safe to
#     skip at compile time; runtime gracefully degrades when absent.
#   - bun:ffi                                                  — only resolved
#     on Bun at runtime anyway; no compile-time resolver exists.
#   - sharp                                                    — optional peer
#     of opentui's @opentui/core; not exercised by pwnkit code paths.

set -euo pipefail

TARGET="${1:-}"
OUTFILE="${2:-dist-bin/pwnkit}"

mkdir -p "$(dirname "$OUTFILE")"

if [ -n "$TARGET" ]; then
  TARGET_ARG="--target=$TARGET"
  # Append target suffix to default outfile if caller didn't override
  if [ "$OUTFILE" = "dist-bin/pwnkit" ]; then
    OUTFILE="dist-bin/pwnkit-${TARGET#bun-}"
  fi
else
  TARGET_ARG=""
fi

cd packages/cli

bun build src/index.ts \
  --compile \
  ${TARGET_ARG} \
  --outfile "../../$OUTFILE" \
  --external playwright \
  --external playwright-core \
  --external electron \
  --external chromium-bidi \
  --external bun:ffi \
  --external sharp

echo "Built $OUTFILE"

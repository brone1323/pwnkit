#!/usr/bin/env bash
# Generate Open Graph social preview images for pwnkit.
#
# Requirements: librsvg (provides `rsvg-convert`).
#   brew install librsvg
#
# Outputs (written to www/public/):
#   og-image.png         1200x630   - default OG / Twitter summary_large_image
#   og-image-square.png  1200x1200  - Instagram / LinkedIn square
#   twitter-card.png     1200x600   - Twitter (alias of og-image, slight crop)
#
# Source SVGs live next to this script and can be edited freely.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC_DIR="$(cd "$SCRIPT_DIR/../public" && pwd)"

if ! command -v rsvg-convert >/dev/null 2>&1; then
  echo "error: rsvg-convert is required. brew install librsvg" >&2
  exit 1
fi

echo "Rendering og-image.png (1200x630)..."
rsvg-convert -w 1200 -h 630 "$SCRIPT_DIR/og-image.svg" -o "$PUBLIC_DIR/og-image.png"

echo "Rendering og-image-square.png (1200x1200)..."
rsvg-convert -w 1200 -h 1200 "$SCRIPT_DIR/og-image-square.svg" -o "$PUBLIC_DIR/og-image-square.png"

echo "Rendering twitter-card.png (1200x600)..."
# Twitter summary_large_image accepts 1200x630; we render the same artwork at 1200x600.
rsvg-convert -w 1200 -h 600 "$SCRIPT_DIR/og-image.svg" -o "$PUBLIC_DIR/twitter-card.png"

echo "Rendering favicon-32.png (32x32) from favicon.svg..."
rsvg-convert -w 32 -h 32 "$PUBLIC_DIR/favicon.svg" -o "$PUBLIC_DIR/favicon-32.png"

echo "Rendering apple-touch-icon.png (180x180) from favicon.svg..."
rsvg-convert -w 180 -h 180 "$PUBLIC_DIR/favicon.svg" -o "$PUBLIC_DIR/apple-touch-icon.png"

echo
echo "Done. Wrote:"
ls -lh \
  "$PUBLIC_DIR/og-image.png" \
  "$PUBLIC_DIR/og-image-square.png" \
  "$PUBLIC_DIR/twitter-card.png" \
  "$PUBLIC_DIR/favicon-32.png" \
  "$PUBLIC_DIR/apple-touch-icon.png"

#!/usr/bin/env bash
# pwnkit install script.
#
# Detects the host platform, downloads the matching standalone binary from
# the latest GitHub Release, and drops it into $PWNKIT_INSTALL_DIR
# (default: $HOME/.pwnkit/bin).
#
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/PwnKit-Labs/pwnkit/main/install.sh | bash
#
# Pin a specific version:
#   curl -fsSL https://raw.githubusercontent.com/PwnKit-Labs/pwnkit/main/install.sh | PWNKIT_VERSION=v0.8.0 bash
#
# Override install directory:
#   curl -fsSL https://raw.githubusercontent.com/PwnKit-Labs/pwnkit/main/install.sh | PWNKIT_INSTALL_DIR=/usr/local/bin bash

set -euo pipefail

REPO="PwnKit-Labs/pwnkit"

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

say()  { printf '%s %s\n' "$(green '[pwnkit]')" "$*"; }
warn() { printf '%s %s\n' "$(yellow '[pwnkit]')" "$*" >&2; }
die()  { printf '%s %s\n' "$(red '[pwnkit]')" "$*" >&2; exit 1; }

# ── Host detection ────────────────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)  ARCH=x64   ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac

case "$OS" in
  linux)  TARGET="linux-${ARCH}"  ;;
  darwin) TARGET="darwin-${ARCH}" ;;
  msys*|mingw*|cygwin*)
    die "Windows detected. Download pwnkit-windows-x64.exe from
       https://github.com/$REPO/releases/latest and add it to your PATH manually."
    ;;
  *) die "Unsupported OS: $OS" ;;
esac

# Intel Mac is intentionally not shipped — Apple stopped selling them in 2022
# and building on GH's macos-13 pool is unreliable. Advise Bun-from-source.
if [ "$TARGET" = "darwin-x64" ]; then
  die "pwnkit does not ship a darwin-x64 binary. Install Bun and build from source:
       curl -fsSL https://bun.sh/install | bash
       git clone https://github.com/$REPO.git
       cd pwnkit && pnpm install --frozen-lockfile && pnpm -r build
       bash scripts/bun-compile.sh
       mv dist-bin/pwnkit ~/.pwnkit/bin/pwnkit"
fi

# ── Resolve release tag ───────────────────────────────────────────────────

TAG="${PWNKIT_VERSION:-}"
if [ -z "$TAG" ]; then
  say "Resolving latest release..."
  TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
  [ -n "$TAG" ] || die "Could not determine the latest release. Set PWNKIT_VERSION=vX.Y.Z."
fi

# ── Download ──────────────────────────────────────────────────────────────

INSTALL_DIR="${PWNKIT_INSTALL_DIR:-$HOME/.pwnkit/bin}"
ASSET="pwnkit-${TARGET}"
URL="https://github.com/$REPO/releases/download/${TAG}/${ASSET}"

say "Installing pwnkit $(bold "$TAG") for $(bold "$TARGET")..."
say "  from: $URL"
say "  to:   $INSTALL_DIR/pwnkit"

mkdir -p "$INSTALL_DIR"

TMP="$(mktemp -t pwnkit.XXXXXX)"
trap 'rm -f "$TMP"' EXIT

if ! curl -fSL --progress-bar -o "$TMP" "$URL"; then
  die "Download failed. Verify the release exists: https://github.com/$REPO/releases/tag/$TAG"
fi

chmod +x "$TMP"
mv "$TMP" "$INSTALL_DIR/pwnkit"
trap - EXIT

# ── Post-install guidance ─────────────────────────────────────────────────

say "Installed to $(bold "$INSTALL_DIR/pwnkit")"

# PATH hint — only nag if the install dir isn't already resolvable.
case ":$PATH:" in
  *:"$INSTALL_DIR":*) ;;
  *)
    echo ""
    warn "$INSTALL_DIR is not in your PATH. Add this line to your shell profile:"
    echo ""
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    warn "Or run pwnkit by its full path: $INSTALL_DIR/pwnkit"
    echo ""
    ;;
esac

say "Try it:"
echo "    pwnkit --version"
echo "    pwnkit scan --target https://example.com --mode web"

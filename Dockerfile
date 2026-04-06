# syntax=docker/dockerfile:1.7
#
# pwnkit-cli — pre-built distribution image
#
# Multi-stage build:
#   stage 1 (builder): node:20 + pnpm, builds the bundled CLI in /app/dist
#   stage 2 (runtime): ubuntu:24.04 + Node 20 + pentest tooling + Playwright
#
# Usage:
#   docker run --rm -e AZURE_OPENAI_API_KEY=$KEY \
#     ghcr.io/peaktwilight/pwnkit:latest scan --target https://example.com
#
# Build args:
#   INSTALL_SECLISTS=1   include SecLists wordlists (~1GB extra, off by default)

# ---------- Stage 1: builder ----------
FROM node:20-bookworm AS builder

ENV PNPM_HOME=/root/.local/share/pnpm \
    PATH=/root/.local/share/pnpm:$PATH \
    CI=1

RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app

# Copy manifests first for better layer caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.base.json ./
COPY scripts ./scripts
COPY packages ./packages
COPY assets ./assets

# Pull in any other workspace files referenced by package.json globs
COPY LICENSE README.md ./

RUN pnpm install --frozen-lockfile
RUN pnpm build

# Install runtime production deps that the bundle externalizes
# (better-sqlite3, drizzle-orm, cfonts) into dist/node_modules.
# playwright is installed in the runtime stage via apt + pip-less npm install.
WORKDIR /app/dist
RUN npm install --omit=dev --no-audit --no-fund

# ---------- Stage 2: runtime ----------
FROM ubuntu:24.04 AS runtime

ARG INSTALL_SECLISTS=0
ARG DEBIAN_FRONTEND=noninteractive

ENV NODE_ENV=production \
    PWNKIT_DOCKER=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PATH=/usr/local/bin:/usr/bin:/bin

# Base system + Node 20 + pentest tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget gnupg jq git unzip xz-utils \
        python3 python3-requests python3-bs4 \
        sqlmap nmap nikto gobuster hydra john ffuf wfuzz \
        whatweb wafw00f dirb \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Optional: SecLists wordlists (large)
RUN if [ "$INSTALL_SECLISTS" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends seclists \
        && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app

# Copy the bundled CLI + its production node_modules from the builder
COPY --from=builder /app/dist /app/dist

# Install Playwright + Chromium with system deps.
# Pinning to whatever the bundle's package.json expects via the workspace
# isn't necessary — playwright is externalized, so any recent version works.
RUN npm install -g playwright@1.48.0 \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* /root/.npm

# Make the bundled CLI globally invocable as `pwnkit-cli` too
RUN ln -s /app/dist/pwnkit.js /usr/local/bin/pwnkit-cli \
    && chmod +x /app/dist/pwnkit.js

# Drop a non-root user for safer default runs
RUN useradd -m -u 1001 pwnkit \
    && mkdir -p /work \
    && chown -R pwnkit:pwnkit /work /app/dist
USER pwnkit
WORKDIR /work

ENTRYPOINT ["node", "/app/dist/pwnkit.js"]
CMD ["--help"]

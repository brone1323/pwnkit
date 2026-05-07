#!/usr/bin/env node
/**
 * pwnkit-cli npm launcher.
 *
 * The npm package is a launcher that downloads the right standalone binary
 * for the host platform on first run, caches it, and re-execs every
 * subsequent run with the user's args. The standalone binary has the Bun
 * runtime baked in, so the full OpenTUI experience is available even
 * though npm itself runs under Node.
 *
 * The build script (`scripts/build-npm-shim.mjs`) substitutes
 * `__PWNKIT_VERSION__` with the published version at build time, so this
 * launcher always pulls the binary that matches its own npm version.
 *
 * Cache layout:
 *   ~/.pwnkit/cache/v<version>/pwnkit         (executable)
 *   ~/.pwnkit/cache/v<version>/pwnkit.exe     (Windows)
 *
 * Env knobs:
 *   PWNKIT_BINARY                 — explicit path to a binary; bypasses
 *                                   the cache + download entirely.
 *                                   Used by tests and operators who
 *                                   build from source.
 *   PWNKIT_NO_DOWNLOAD=1          — never download; if the binary isn't
 *                                   cached, print the install.sh fallback
 *                                   URL and exit 1.
 *   PWNKIT_DOWNLOAD_TIMEOUT_MS    — per-attempt timeout for the GH
 *                                   release download (default: 120000).
 */

"use strict";

const { existsSync, mkdirSync, chmodSync, renameSync, statSync, createWriteStream, unlinkSync } = require("node:fs");
const { homedir, tmpdir } = require("node:os");
const { join, dirname } = require("node:path");
const { spawn } = require("node:child_process");
const { request } = require("node:https");

const VERSION = "__PWNKIT_VERSION__";
const REPO = "PwnKit-Labs/pwnkit";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const ORANGE = "\x1b[38;2;250;178;131m";
const RED = "\x1b[31m";

function err(msg) {
  process.stderr.write(`${RED}[pwnkit]${RESET} ${msg}\n`);
}

function detectAsset() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "darwin" && arch === "arm64") return "pwnkit-darwin-arm64";
  if (platform === "linux" && arch === "x64") return "pwnkit-linux-x64";
  if (platform === "linux" && arch === "arm64") return "pwnkit-linux-arm64";
  if (platform === "win32" && arch === "x64") return "pwnkit-windows-x64.exe";
  return null;
}

function cachePath(asset) {
  return join(homedir(), ".pwnkit", "cache", `v${VERSION}`, asset);
}

function downloadUrl(asset) {
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
}

// Follow redirects (GH releases bounce through codeload). Returns a
// readable stream of body bytes once we land on a 2xx, or rejects.
function fetchFollowRedirects(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    let redirects = 0;
    const MAX_REDIRECTS = 5;

    const go = (currentUrl) => {
      const req = request(currentUrl, { method: "GET" }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          redirects++;
          if (redirects > MAX_REDIRECTS) {
            reject(new Error(`too many redirects (${MAX_REDIRECTS}+) for ${url}`));
            return;
          }
          // Drain the redirect response body so the socket can be reused.
          res.resume();
          // GH gives absolute URLs in Location, but be defensive.
          const next = new URL(res.headers.location, currentUrl).toString();
          go(next);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} fetching ${currentUrl}`));
          res.resume();
          return;
        }
        resolve(res);
      });
      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`download timeout after ${timeoutMs}ms`));
      });
      req.on("error", reject);
      req.end();
    };

    go(url);
  });
}

function printInstallFallback(asset) {
  const url = downloadUrl(asset);
  err("could not provision the standalone binary automatically.");
  err("");
  err("install via:");
  err(`  ${ORANGE}curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash${RESET}`);
  err("");
  err("or download the binary directly:");
  err(`  ${url}`);
  err("");
}

async function ensureBinary() {
  // Operator override — used by tests + source builds.
  const explicit = process.env.PWNKIT_BINARY;
  if (explicit && existsSync(explicit)) return explicit;

  const asset = detectAsset();
  if (!asset) {
    err(`unsupported platform: ${process.platform}/${process.arch}`);
    err("supported: darwin-arm64, linux-x64, linux-arm64, windows-x64");
    err("");
    err(`Intel Mac users: install Bun and build from source — see ${ORANGE}https://github.com/${REPO}#standalone-binary${RESET}`);
    process.exit(2);
  }

  const cached = cachePath(asset);
  if (existsSync(cached)) return cached;

  if (process.env.PWNKIT_NO_DOWNLOAD === "1") {
    printInstallFallback(asset);
    process.exit(1);
  }

  // Lazy first-run UX: tell the user we're fetching ~75-130 MB so they
  // don't think the CLI is hung.
  const url = downloadUrl(asset);
  process.stderr.write(`${DIM}[pwnkit] first-run setup — downloading ${asset} (${url})${RESET}\n`);

  const cacheDir = dirname(cached);
  mkdirSync(cacheDir, { recursive: true });
  const tmpFile = join(tmpdir(), `pwnkit-${process.pid}-${Date.now()}-${asset}`);

  try {
    const timeoutMs = Number(process.env.PWNKIT_DOWNLOAD_TIMEOUT_MS ?? 120000);
    const body = await fetchFollowRedirects(url, timeoutMs);
    await new Promise((resolve, reject) => {
      const out = createWriteStream(tmpFile, { mode: 0o755 });
      body.pipe(out);
      body.on("error", reject);
      out.on("error", reject);
      out.on("finish", resolve);
    });
    // Sanity-check size; an empty file means we got something pathological.
    const size = statSync(tmpFile).size;
    if (size < 1024 * 1024) {
      try { unlinkSync(tmpFile); } catch { /* ignore */ }
      throw new Error(`downloaded file is only ${size} bytes — refusing to cache`);
    }
    // Atomic publish into the cache.
    chmodSync(tmpFile, 0o755);
    renameSync(tmpFile, cached);
    process.stderr.write(`${DIM}[pwnkit] cached at ${cached}${RESET}\n`);
    return cached;
  } catch (e) {
    try { unlinkSync(tmpFile); } catch { /* ignore */ }
    err(`download failed: ${e.message}`);
    err("");
    printInstallFallback(asset);
    process.exit(1);
  }
}

(async () => {
  const binary = await ensureBinary();
  // Re-exec the user's args against the standalone binary. stdio:'inherit'
  // wires the parent's terminal through so OpenTUI works as if invoked
  // directly. The launcher exits with the binary's own exit code.
  const child = spawn(binary, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });
  child.on("error", (e) => {
    err(`failed to spawn ${binary}: ${e.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      // Mirror the signal so shells see the right exit reason.
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 0);
  });
})().catch((e) => {
  err(`launcher error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});

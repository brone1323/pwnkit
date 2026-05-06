#!/usr/bin/env node
/**
 * Build the npm-shim package — a tiny replacement for the previous
 * full-bundle `pwnkit-cli` that npm-published from `dist/`.
 *
 * From v0.9.0 onwards, pwnkit ships as a self-contained binary (with the
 * Bun runtime baked in) via `install.sh` + GitHub Releases. The npm
 * package becomes a courtesy redirect: on `npx pwnkit-cli` /
 * `bun add -g pwnkit-cli`, it prints install instructions and exits.
 *
 * Output: dist-npm/  — ready to `npm publish` from.
 */

import { mkdirSync, writeFileSync, rmSync, copyFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT = join(ROOT, "dist-npm");

// Read version from root package.json so a single bump propagates.
const rootPkg = JSON.parse(
  await import("node:fs/promises").then((fs) => fs.readFile(join(ROOT, "package.json"), "utf8")),
);
const VERSION = rootPkg.version;

// ── Clean output ────────────────────────────────────────────────────────────
if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
mkdirSync(join(OUT, "bin"), { recursive: true });

// ── Shim binary ─────────────────────────────────────────────────────────────
//
// The shim works under both Node and Bun — the message is the same in both
// cases since users in either environment should switch to the standalone
// binary for the full TUI experience.
const SHIM = `#!/usr/bin/env node
const RESET = "\\x1b[0m";
const BOLD = "\\x1b[1m";
const DIM = "\\x1b[2m";
const ORANGE = "\\x1b[38;2;250;178;131m";

console.log("");
console.log("  " + ORANGE + "pwnkit" + RESET + " " + DIM + "v${VERSION}" + RESET);
console.log("");
console.log("  " + BOLD + "From v0.9.0, pwnkit ships as a self-contained binary." + RESET);
console.log("");
console.log("  The full TUI (mission control + live scan view) is built on OpenTUI,");
console.log("  which needs Bun's runtime. The standalone binary has Bun baked in,");
console.log("  so you don't need Node or Bun installed to run it.");
console.log("");
console.log("  " + BOLD + "Install:" + RESET);
console.log("    " + ORANGE + "curl -fsSL https://raw.githubusercontent.com/PwnKit-Labs/pwnkit/main/install.sh | bash" + RESET);
console.log("");
console.log("  This drops a single binary into ~/.pwnkit/bin/ for your platform.");
console.log("  Supports macOS arm64 and Linux x64 / arm64. Windows users should");
console.log("  download pwnkit-windows-x64.exe directly from the releases page:");
console.log("");
console.log("    https://github.com/PwnKit-Labs/pwnkit/releases/latest");
console.log("");
console.log(DIM + "  (npm-published shim — passing args to this package will not run pwnkit.)" + RESET);
console.log("");
process.exit(1);
`;
writeFileSync(join(OUT, "bin", "pwnkit-cli.cjs"), SHIM, { mode: 0o755 });

// ── package.json ────────────────────────────────────────────────────────────
const pkg = {
  name: "pwnkit-cli",
  version: VERSION,
  description: "Install pwnkit. From v0.9.0 pwnkit ships as a self-contained binary; this package prints install instructions.",
  bin: { "pwnkit-cli": "bin/pwnkit-cli.cjs" },
  files: ["bin", "README.md", "LICENSE"],
  homepage: "https://github.com/PwnKit-Labs/pwnkit",
  repository: { type: "git", url: "git+https://github.com/PwnKit-Labs/pwnkit.git" },
  bugs: { url: "https://github.com/PwnKit-Labs/pwnkit/issues" },
  license: "MIT",
  keywords: rootPkg.keywords ?? [],
  author: rootPkg.author,
  engines: { node: ">=18" },
};
writeFileSync(join(OUT, "package.json"), JSON.stringify(pkg, null, 2) + "\n");

// ── README ──────────────────────────────────────────────────────────────────
const README = `# pwnkit-cli (install redirect)

From **v0.9.0** onwards, **pwnkit ships as a self-contained binary** with the
Bun runtime baked in. The full TUI (OpenTUI mission control + live scan view)
needs Bun's runtime, and shipping one binary is simpler than asking users to
install Bun first.

## Install

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/PwnKit-Labs/pwnkit/main/install.sh | bash
\`\`\`

This drops a single binary into \`~/.pwnkit/bin/\` for your platform.

Supported: **macOS arm64**, **Linux x64**, **Linux arm64**.
Windows users: download \`pwnkit-windows-x64.exe\` from the
[releases page](https://github.com/PwnKit-Labs/pwnkit/releases/latest).

## Why this package still exists

This npm package is now a redirect — installing it via \`npm i -g pwnkit-cli\`,
\`bunx pwnkit-cli\`, or \`npx pwnkit-cli\` will print install instructions for
the standalone binary and exit. It exists to give a clear migration message
to anyone with the npm package wired into a CI / dotfiles workflow.

## Source

Source code, releases, and docs: <https://github.com/PwnKit-Labs/pwnkit>
`;
writeFileSync(join(OUT, "README.md"), README);

// ── LICENSE ─────────────────────────────────────────────────────────────────
const licenseSrc = join(ROOT, "LICENSE");
if (existsSync(licenseSrc)) {
  copyFileSync(licenseSrc, join(OUT, "LICENSE"));
}

console.log(`Built npm shim v${VERSION} → dist-npm/`);

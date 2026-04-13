#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
RESULT_JSON="${TMP_DIR}/kernel-validator-result.json"
RAW_OUTPUT="${TMP_DIR}/kernel-validator-raw.txt"

REPORT_URL="${PWNKIT_KERNEL_E2E_REPORT_URL:-https://syzkaller.appspot.com/text?tag=CrashReport&x=144881ca580000}"
REPRO_URL="${PWNKIT_KERNEL_E2E_REPRO_URL:-https://syzkaller.appspot.com/text?tag=ReproC&x=1253b3d6580000}"
INPUT_DIR="${TMP_DIR}/input"
ARTIFACT_DIR="${PWNKIT_KERNEL_QEMU_ARTIFACT_DIR:-${TMP_DIR}/vm-artifacts}"

mkdir -p "${INPUT_DIR}" "${ARTIFACT_DIR}"

curl -fL --retry 3 --retry-delay 2 -s "${REPORT_URL}" > "${INPUT_DIR}/sample.log"
curl -fL --retry 3 --retry-delay 2 -s "${REPRO_URL}" > "${INPUT_DIR}/sample.c"

export PWNKIT_KERNEL_QEMU=1
export PWNKIT_KERNEL_QEMU_ARTIFACT_DIR="${ARTIFACT_DIR}"

node "${ROOT_DIR}/packages/cli/dist/index.js" ingest "${INPUT_DIR}" --verify -o json > "${RAW_OUTPUT}"

node - "${RAW_OUTPUT}" "${RESULT_JSON}" <<'EOF'
const fs = require("node:fs");
const [rawPath, jsonPath] = process.argv.slice(2);
const raw = fs.readFileSync(rawPath, "utf8");
const jsonStart = raw.indexOf("[");
if (jsonStart === -1) {
  throw new Error("kernel validator E2E output did not contain a JSON array");
}
const payload = raw.slice(jsonStart);
JSON.parse(payload);
fs.writeFileSync(jsonPath, payload);
EOF

node - "${RESULT_JSON}" <<'EOF'
const fs = require("node:fs");
const path = process.argv[2];
const parsed = JSON.parse(fs.readFileSync(path, "utf8"));

if (!Array.isArray(parsed) || parsed.length === 0) {
  throw new Error("kernel validator E2E produced no findings");
}

const entry = parsed[0];
if (!entry.verification) {
  throw new Error("kernel validator E2E produced no verification payload");
}

if (entry.verification.reproduced !== true) {
  const reason = entry.verification.reason || "unknown";
  const evidence = entry.verification.evidence || "no evidence";
  throw new Error(`kernel validator E2E did not reproduce the crash: ${reason}\n${evidence}`);
}

const summary = {
  templateId: entry.finding?.templateId ?? null,
  verified: entry.verification.verified ?? null,
  reproduced: entry.verification.reproduced ?? null,
  crashMatch: entry.verification.crashMatch ?? null,
  reason: entry.verification.reason ?? null,
  confidence: entry.verification.confidence ?? null,
};

console.log(JSON.stringify(summary, null, 2));
EOF

echo "Kernel validator E2E artifacts saved to: ${ARTIFACT_DIR}"

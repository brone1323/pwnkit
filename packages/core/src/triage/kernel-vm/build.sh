#!/usr/bin/env bash
# Build KASAN-enabled kernel + rootfs for pwnkit kernel crash validator
#
# Usage: ./build.sh [output-dir]
#
# Outputs:
#   bzImage       — KASAN-enabled kernel
#   rootfs.img    — Debian root filesystem with SSH + GCC
#   kernel.config — kernel .config
#
# After building, configure the kernel VM runner:
#   export PWNKIT_KERNEL_QEMU=1
#   export PWNKIT_KERNEL_QEMU_KERNEL=/path/to/bzImage
#   export PWNKIT_KERNEL_QEMU_DISK=/path/to/rootfs.img
#   pwnkit ingest --verify <crash-reports-dir>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/out}"

mkdir -p "${OUT_DIR}"

echo "Building pwnkit kernel VM image..."
echo "  Dockerfile: ${SCRIPT_DIR}/Dockerfile"
echo "  Output dir: ${OUT_DIR}"
echo ""
echo "This will take 15-30 minutes (kernel compilation)."
echo ""

docker build \
  -t pwnkit-kernel-builder \
  -f "${SCRIPT_DIR}/Dockerfile" \
  "${SCRIPT_DIR}"

docker run --rm \
  --privileged \
  -v "${OUT_DIR}:/out" \
  pwnkit-kernel-builder

echo ""
echo "Done. Kernel VM artifacts:"
ls -lh "${OUT_DIR}"/bzImage "${OUT_DIR}"/rootfs.img "${OUT_DIR}"/kernel.config 2>/dev/null

echo ""
echo "To use with pwnkit:"
echo "  export PWNKIT_KERNEL_QEMU=1"
echo "  export PWNKIT_KERNEL_QEMU_KERNEL=${OUT_DIR}/bzImage"
echo "  export PWNKIT_KERNEL_QEMU_DISK=${OUT_DIR}/rootfs.img"
echo "  pwnkit ingest --verify <crash-reports-dir>"

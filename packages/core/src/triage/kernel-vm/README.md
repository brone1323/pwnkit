# pwnkit Kernel VM — KASAN-enabled crash reproducer

Pre-built KASAN-enabled Linux kernel + root filesystem for automated kernel crash validation.

## Quick start

```bash
# Build (15-30 min, requires Docker)
./build.sh ./out

# Configure
export PWNKIT_KERNEL_QEMU=1
export PWNKIT_KERNEL_QEMU_KERNEL=./out/bzImage
export PWNKIT_KERNEL_QEMU_DISK=./out/rootfs.img

# Run with verification
pwnkit ingest --verify /path/to/crash-reports/
```

## What's included

**Kernel** (bzImage):
- Linux 6.8.12 with KASAN (generic, inline, stack, vmalloc)
- UBSAN (bounds, shift, div-zero, bool, enum, alignment)
- KCSAN (data race detection)
- PROVE_LOCKING, DEBUG_ATOMIC_SLEEP, RCU stall detection
- Subsystem support: NFS/NFSd, bluetooth, WiFi (mac80211), SCTP, 9P, ext4
- nokaslr for reproducible crash addresses
- virtio drivers for QEMU

**Root filesystem** (rootfs.img, 512MB ext4):
- Debian Bookworm minimal
- OpenSSH server (root:root)
- GCC + libc-dev for reproducer compilation
- gdb, strace for debugging

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PWNKIT_KERNEL_QEMU` | - | Set to `1` to enable |
| `PWNKIT_KERNEL_QEMU_KERNEL` | - | Path to bzImage |
| `PWNKIT_KERNEL_QEMU_DISK` | - | Path to rootfs.img |
| `PWNKIT_KERNEL_QEMU_SSH_PORT` | `10022` | SSH forwarded port |
| `PWNKIT_KERNEL_QEMU_MEMORY_MB` | `2048` | VM memory |
| `PWNKIT_KERNEL_QEMU_SMP` | `2` | CPU cores |
| `PWNKIT_KERNEL_QEMU_TIMEOUT_SEC` | `60` | Reproducer timeout |
| `PWNKIT_KERNEL_QEMU_BOOT_TIMEOUT_SEC` | `120` | Boot timeout |
| `PWNKIT_KERNEL_QEMU_ACCEL` | - | QEMU accelerator (e.g. `kvm`) |

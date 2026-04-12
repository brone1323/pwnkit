# pwnkit kernel crash validator — KASAN-enabled kernel builder
#
# Builds a minimal Linux kernel with KASAN + UBSAN enabled, plus a
# Debian root filesystem with SSH and GCC for reproducer compilation.
#
# Usage:
#   docker build -t pwnkit-kernel-builder -f Dockerfile .
#   docker run --rm -v $(pwd)/out:/out pwnkit-kernel-builder
#
# Outputs in /out:
#   bzImage       — KASAN-enabled kernel
#   rootfs.img    — ext4 root filesystem (512MB) with SSH + GCC
#   kernel.config — .config used for the build
#
# The resulting artifacts work with the kernel-vm-runner.ts QEMU config:
#   PWNKIT_KERNEL_QEMU=1
#   PWNKIT_KERNEL_QEMU_KERNEL=/path/to/bzImage
#   PWNKIT_KERNEL_QEMU_DISK=/path/to/rootfs.img

FROM debian:bookworm-slim AS kernel-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    bc \
    bison \
    flex \
    libelf-dev \
    libssl-dev \
    libncurses-dev \
    wget \
    xz-utils \
    ca-certificates \
    cpio \
    kmod \
    && rm -rf /var/lib/apt/lists/*

ARG KERNEL_VERSION=6.8.12
ARG KERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz

# Download and extract kernel source
WORKDIR /build
RUN wget -q "${KERNEL_URL}" -O linux.tar.xz \
    && tar xf linux.tar.xz \
    && rm linux.tar.xz \
    && mv linux-* linux

# Generate kernel config with KASAN + UBSAN + debug info
WORKDIR /build/linux
RUN make defconfig \
    && scripts/config \
        --enable CONFIG_KASAN \
        --set-str CONFIG_KASAN_MODE "generic" \
        --enable CONFIG_KASAN_GENERIC \
        --enable CONFIG_KASAN_INLINE \
        --enable CONFIG_KASAN_STACK \
        --enable CONFIG_KASAN_VMALLOC \
        --enable CONFIG_UBSAN \
        --enable CONFIG_UBSAN_BOUNDS \
        --enable CONFIG_UBSAN_SHIFT \
        --enable CONFIG_UBSAN_DIV_ZERO \
        --enable CONFIG_UBSAN_BOOL \
        --enable CONFIG_UBSAN_ENUM \
        --enable CONFIG_UBSAN_ALIGNMENT \
        --enable CONFIG_KCSAN \
        --enable CONFIG_DEBUG_INFO \
        --enable CONFIG_DEBUG_INFO_DWARF5 \
        --enable CONFIG_DEBUG_KERNEL \
        --enable CONFIG_PROVE_LOCKING \
        --enable CONFIG_LOCK_STAT \
        --enable CONFIG_DEBUG_ATOMIC_SLEEP \
        --enable CONFIG_STACKTRACE \
        --enable CONFIG_RCU_CPU_STALL_TIMEOUT \
        --enable CONFIG_DETECT_HUNG_TASK \
        --enable CONFIG_DEFAULT_HUNG_TASK_TIMEOUT \
        --enable CONFIG_PANIC_ON_OOPS \
        --enable CONFIG_VIRTIO \
        --enable CONFIG_VIRTIO_PCI \
        --enable CONFIG_VIRTIO_NET \
        --enable CONFIG_VIRTIO_BLK \
        --enable CONFIG_EXT4_FS \
        --enable CONFIG_TMPFS \
        --enable CONFIG_DEVTMPFS \
        --enable CONFIG_DEVTMPFS_MOUNT \
        --enable CONFIG_NET \
        --enable CONFIG_INET \
        --enable CONFIG_NFS_FS \
        --enable CONFIG_NFSD \
        --enable CONFIG_SUNRPC \
        --enable CONFIG_BT \
        --enable CONFIG_BT_HCIUART \
        --enable CONFIG_CFG80211 \
        --enable CONFIG_MAC80211 \
        --enable CONFIG_SCTP_DEFAULT_COOKIE_HMAC_MD5 \
        --enable CONFIG_IP_SCTP \
        --enable CONFIG_9P_FS \
        --enable CONFIG_NET_9P \
        --disable CONFIG_RANDOMIZE_BASE \
        --set-val CONFIG_FRAME_WARN 2048 \
    && make olddefconfig

# Build kernel (parallel, uses all cores)
RUN make -j$(nproc) bzImage

# ── Root filesystem builder ──
FROM debian:bookworm-slim AS rootfs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    debootstrap \
    e2fsprogs \
    qemu-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create minimal Debian rootfs
RUN mkdir -p /rootfs \
    && debootstrap --variant=minbase --include=\
openssh-server,gcc,libc6-dev,make,kmod,procps,iproute2,iputils-ping,\
net-tools,strace,gdb,dmesg,systemd-sysv \
    bookworm /rootfs http://deb.debian.org/debian

# Configure rootfs
RUN chroot /rootfs bash -c '\
    echo "root:root" | chpasswd && \
    mkdir -p /root/.ssh && \
    ssh-keygen -A && \
    sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config && \
    sed -i "s/#PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config && \
    systemctl enable ssh && \
    echo "pwnkit-kernel" > /etc/hostname && \
    mkdir -p /root/pwnkit-kernel && \
    echo "nameserver 8.8.8.8" > /etc/resolv.conf \
'

# Create ext4 disk image
RUN dd if=/dev/zero of=/rootfs.img bs=1M count=512 \
    && mkfs.ext4 -F /rootfs.img \
    && mkdir -p /mnt/rootfs \
    && mount -o loop /rootfs.img /mnt/rootfs \
    && cp -a /rootfs/* /mnt/rootfs/ \
    && umount /mnt/rootfs

# ── Final output stage ──
FROM debian:bookworm-slim

COPY --from=kernel-builder /build/linux/arch/x86/boot/bzImage /artifacts/bzImage
COPY --from=kernel-builder /build/linux/.config /artifacts/kernel.config
COPY --from=rootfs-builder /rootfs.img /artifacts/rootfs.img

# Output script: copy artifacts to /out volume
CMD ["sh", "-c", "cp /artifacts/* /out/ && echo 'Kernel VM artifacts exported to /out/' && ls -lh /out/"]

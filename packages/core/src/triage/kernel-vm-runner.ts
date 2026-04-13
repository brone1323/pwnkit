import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReproducerResult, CrashReport } from "./kernel-oracle.js";

export interface KernelVmConfig {
  qemuBinary: string;
  kernelImage: string;
  diskImage: string;
  diskFormat: "raw" | "qcow2";
  bootTimeoutSec: number;
  memoryMb: number;
  smp: number;
  kernelAppend: string;
  qemuAccel?: string;
  initrdPath?: string;
  timeoutSec: number;
  shareTag: string;
  artifactDir?: string;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function inferDiskFormat(diskImage: string): "raw" | "qcow2" {
  return diskImage.endsWith(".qcow2") || diskImage.endsWith(".qcow") ? "qcow2" : "raw";
}

export function loadKernelVmConfigFromEnv(): KernelVmConfig {
  const kernelImage = process.env.PWNKIT_KERNEL_QEMU_KERNEL?.trim();
  const diskImage = process.env.PWNKIT_KERNEL_QEMU_DISK?.trim();

  const missing = [
    !kernelImage ? "PWNKIT_KERNEL_QEMU_KERNEL" : "",
    !diskImage ? "PWNKIT_KERNEL_QEMU_DISK" : "",
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(
      `kernel VM runner is enabled but missing required env vars: ${missing.join(", ")}`,
    );
  }

  const resolvedKernelImage = kernelImage!;
  const resolvedDiskImage = diskImage!;

  return {
    qemuBinary: process.env.PWNKIT_KERNEL_QEMU_BINARY?.trim() || "qemu-system-x86_64",
    kernelImage: resolvedKernelImage,
    diskImage: resolvedDiskImage,
    diskFormat: (process.env.PWNKIT_KERNEL_QEMU_DISK_FORMAT?.trim() as "raw" | "qcow2" | undefined) || inferDiskFormat(resolvedDiskImage),
    bootTimeoutSec: parseInt(process.env.PWNKIT_KERNEL_QEMU_BOOT_TIMEOUT_SEC?.trim() || "120", 10),
    memoryMb: parseInt(process.env.PWNKIT_KERNEL_QEMU_MEMORY_MB?.trim() || "2048", 10),
    smp: parseInt(process.env.PWNKIT_KERNEL_QEMU_SMP?.trim() || "2", 10),
    kernelAppend: process.env.PWNKIT_KERNEL_QEMU_APPEND?.trim() || "console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/pwnkit-init",
    qemuAccel: process.env.PWNKIT_KERNEL_QEMU_ACCEL?.trim() || undefined,
    initrdPath: process.env.PWNKIT_KERNEL_QEMU_INITRD?.trim() || undefined,
    timeoutSec: parseInt(process.env.PWNKIT_KERNEL_QEMU_TIMEOUT_SEC?.trim() || "60", 10),
    shareTag: process.env.PWNKIT_KERNEL_QEMU_SHARE_TAG?.trim() || "pwnkitshare",
    artifactDir: process.env.PWNKIT_KERNEL_QEMU_ARTIFACT_DIR?.trim() || undefined,
  };
}

export function buildQemuCommand(
  config: KernelVmConfig,
  serialLogPath: string,
  sharedDir: string,
): { command: string; args: string[] } {
  const args = [
    "-m", String(config.memoryMb),
    "-smp", String(config.smp),
    "-kernel", config.kernelImage,
    "-drive", `file=${config.diskImage},format=${config.diskFormat},if=virtio`,
    "-append", config.kernelAppend,
    "-virtfs", `local,path=${sharedDir},mount_tag=${config.shareTag},security_model=none,id=hostshare`,
    "-nographic",
    "-monitor", "none",
    "-serial", `file:${serialLogPath}`,
    "-no-reboot",
  ];

  if (config.qemuAccel) {
    args.push("-accel", config.qemuAccel);
  }
  if (config.initrdPath) {
    args.push("-initrd", config.initrdPath);
  }

  return { command: config.qemuBinary, args };
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function stopVm(proc: ReturnType<typeof spawn>): Promise<void> {
  if (proc.exitCode !== null || proc.killed) return;
  proc.kill("SIGTERM");
  const deadline = Date.now() + 10_000;
  while (proc.exitCode === null && Date.now() < deadline) {
    await sleep(250);
  }
  if (proc.exitCode === null) {
    proc.kill("SIGKILL");
  }
}

function renderGuestRunnerScript(config: KernelVmConfig): string {
  return [
    "#!/bin/sh",
    "set -eu",
    "SHARE_DIR=/mnt/pwnkit",
    "WORK_DIR=/tmp/pwnkit-run",
    "mkdir -p \"$WORK_DIR\"",
    "compiled=0",
    "executed=0",
    "exit_code=0",
    "timed_out=0",
    "cp \"$SHARE_DIR/repro.c\" \"$WORK_DIR/repro.c\"",
    `if /usr/bin/gcc -B/usr/bin/ -O0 -g -o "$WORK_DIR/repro" "$WORK_DIR/repro.c" -lpthread >"$SHARE_DIR/compile.log" 2>&1; then`,
    "  compiled=1",
    "else",
    "  exit_code=$?",
    "fi",
    "if [ \"$compiled\" = \"1\" ]; then",
    "  dmesg -C 2>/dev/null || true",
    `  if timeout ${shellQuote(String(config.timeoutSec))}s "$WORK_DIR/repro" >"$SHARE_DIR/run.log" 2>&1; then`,
    "    executed=1",
    "    exit_code=0",
    "  else",
    "    exit_code=$?",
    "    if [ \"$exit_code\" = \"124\" ]; then",
    "      timed_out=1",
    "    else",
    "      executed=1",
    "    fi",
    "  fi",
    "else",
    "  : > \"$SHARE_DIR/run.log\"",
    "fi",
    "dmesg 2>/dev/null > \"$SHARE_DIR/dmesg.log\" || true",
    "printf '%s\\n' \"$compiled\" > \"$SHARE_DIR/compiled.ok\"",
    "printf '%s\\n' \"$executed\" > \"$SHARE_DIR/executed.ok\"",
    "printf '%s\\n' \"$exit_code\" > \"$SHARE_DIR/exit_code\"",
    "printf '%s\\n' \"$timed_out\" > \"$SHARE_DIR/timed_out\"",
    "sync",
  ].join("\n");
}

async function waitForVmResult(
  config: KernelVmConfig,
  proc: ReturnType<typeof spawn>,
  hostTmpDir: string,
  bootLogPath: string,
): Promise<void> {
  const totalBudgetSec = config.bootTimeoutSec + config.timeoutSec + 60;
  const deadline = Date.now() + totalBudgetSec * 1000;
  const compiledMarker = join(hostTmpDir, "compiled.ok");

  while (Date.now() < deadline) {
    if (existsSync(compiledMarker)) {
      return;
    }
    if (proc.exitCode !== null) {
      const bootLog = existsSync(bootLogPath) ? readFileSync(bootLogPath, "utf-8").slice(-4000) : "";
      throw new Error(`kernel VM exited before producing results (exit=${proc.exitCode}).\n${bootLog}`);
    }
    await sleep(2_000);
  }

  const bootLog = existsSync(bootLogPath) ? readFileSync(bootLogPath, "utf-8").slice(-4000) : "";
  throw new Error(`timed out waiting for kernel VM results in shared dir ${hostTmpDir} after ${totalBudgetSec}s.\n${bootLog}`);
}

export async function runReproducerInKernelVm(report: CrashReport): Promise<ReproducerResult> {
  if (!report.reproducer) {
    return {
      compiled: false,
      executed: false,
      output: "",
      dmesg: "",
      exitCode: -1,
      timedOut: false,
    };
  }

  const config = loadKernelVmConfigFromEnv();
  const hostTmpDir = config.artifactDir
    ? (() => {
        mkdirSync(config.artifactDir!, { recursive: true });
        return mkdtempSync(join(config.artifactDir!, "pwnkit-kvm-"));
      })()
    : mkdtempSync(join(tmpdir(), "pwnkit-kvm-"));
  const sourcePath = join(hostTmpDir, "repro.c");
  const runnerScriptPath = join(hostTmpDir, "runner.sh");
  const serialLogPath = join(hostTmpDir, "serial.log");
  writeFileSync(sourcePath, report.reproducer, "utf-8");
  writeFileSync(runnerScriptPath, renderGuestRunnerScript(config), "utf-8");

  const { command, args } = buildQemuCommand(config, serialLogPath, hostTmpDir);
  const vmProc = spawn(command, args, {
    stdio: "ignore",
  });

  try {
    await waitForVmResult(config, vmProc, hostTmpDir, serialLogPath);

    const compiled = readFileSync(join(hostTmpDir, "compiled.ok"), "utf-8").trim() === "1";
    const executed = existsSync(join(hostTmpDir, "executed.ok"))
      ? readFileSync(join(hostTmpDir, "executed.ok"), "utf-8").trim() === "1"
      : false;
    const exitCode = existsSync(join(hostTmpDir, "exit_code"))
      ? parseInt(readFileSync(join(hostTmpDir, "exit_code"), "utf-8").trim(), 10)
      : 1;
    const timedOut = existsSync(join(hostTmpDir, "timed_out"))
      ? readFileSync(join(hostTmpDir, "timed_out"), "utf-8").trim() === "1"
      : false;
    const compileLog = existsSync(join(hostTmpDir, "compile.log"))
      ? readFileSync(join(hostTmpDir, "compile.log"), "utf-8").trim()
      : "";
    const runLog = existsSync(join(hostTmpDir, "run.log"))
      ? readFileSync(join(hostTmpDir, "run.log"), "utf-8").trim()
      : "";
    const dmesg = existsSync(join(hostTmpDir, "dmesg.log"))
      ? readFileSync(join(hostTmpDir, "dmesg.log"), "utf-8").trim()
      : "";

    return {
      compiled,
      executed,
      output: compiled ? runLog : compileLog,
      dmesg,
      exitCode: Number.isFinite(exitCode) ? exitCode : 1,
      timedOut,
    };
  } finally {
    await stopVm(vmProc);
    if (!config.artifactDir) {
      rmSync(hostTmpDir, { recursive: true, force: true });
    }
  }
}

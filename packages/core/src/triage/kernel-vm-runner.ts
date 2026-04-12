import { execFile, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReproducerResult, CrashReport } from "./kernel-oracle.js";

export interface KernelVmConfig {
  qemuBinary: string;
  kernelImage: string;
  diskImage: string;
  diskFormat: "raw" | "qcow2";
  sshBinary: string;
  scpBinary: string;
  sshHost: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath?: string;
  bootTimeoutSec: number;
  memoryMb: number;
  smp: number;
  remoteWorkDir: string;
  kernelAppend: string;
  qemuAccel?: string;
  initrdPath?: string;
  timeoutSec: number;
}

const SSH_COMMON_ARGS = [
  "-o", "StrictHostKeyChecking=no",
  "-o", "UserKnownHostsFile=/dev/null",
  "-o", "BatchMode=yes",
  "-o", "ConnectTimeout=5",
];

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
    sshBinary: process.env.PWNKIT_KERNEL_QEMU_SSH_BINARY?.trim() || "ssh",
    scpBinary: process.env.PWNKIT_KERNEL_QEMU_SCP_BINARY?.trim() || "scp",
    sshHost: process.env.PWNKIT_KERNEL_QEMU_SSH_HOST?.trim() || "127.0.0.1",
    sshPort: parseInt(process.env.PWNKIT_KERNEL_QEMU_SSH_PORT?.trim() || "10022", 10),
    sshUser: process.env.PWNKIT_KERNEL_QEMU_SSH_USER?.trim() || "root",
    sshKeyPath: process.env.PWNKIT_KERNEL_QEMU_SSH_KEY?.trim() || undefined,
    bootTimeoutSec: parseInt(process.env.PWNKIT_KERNEL_QEMU_BOOT_TIMEOUT_SEC?.trim() || "120", 10),
    memoryMb: parseInt(process.env.PWNKIT_KERNEL_QEMU_MEMORY_MB?.trim() || "2048", 10),
    smp: parseInt(process.env.PWNKIT_KERNEL_QEMU_SMP?.trim() || "2", 10),
    remoteWorkDir: process.env.PWNKIT_KERNEL_QEMU_REMOTE_DIR?.trim() || "/root/pwnkit-kernel",
    kernelAppend: process.env.PWNKIT_KERNEL_QEMU_APPEND?.trim() || "console=ttyS0 root=/dev/vda rw nokaslr panic=-1",
    qemuAccel: process.env.PWNKIT_KERNEL_QEMU_ACCEL?.trim() || undefined,
    initrdPath: process.env.PWNKIT_KERNEL_QEMU_INITRD?.trim() || undefined,
    timeoutSec: parseInt(process.env.PWNKIT_KERNEL_QEMU_TIMEOUT_SEC?.trim() || "60", 10),
  };
}

export function buildQemuCommand(config: KernelVmConfig, serialLogPath: string): { command: string; args: string[] } {
  const args = [
    "-m", String(config.memoryMb),
    "-smp", String(config.smp),
    "-kernel", config.kernelImage,
    "-drive", `file=${config.diskImage},format=${config.diskFormat},if=virtio`,
    "-append", config.kernelAppend,
    "-netdev", `user,id=net0,hostfwd=tcp::${config.sshPort}-:22`,
    "-device", "virtio-net-pci,netdev=net0",
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

function buildSshBaseArgs(config: KernelVmConfig): string[] {
  const args = [...SSH_COMMON_ARGS];
  if (config.sshKeyPath) {
    args.push("-i", config.sshKeyPath);
  }
  return args;
}

function execFileCaptured(
  file: string,
  args: string[],
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string; exitCode: number; timedOut: boolean }> {
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      {
        encoding: "utf-8",
        timeout: timeoutMs,
        maxBuffer: 4 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (!error) {
          resolve({
            stdout: stdout ?? "",
            stderr: stderr ?? "",
            exitCode: 0,
            timedOut: false,
          });
          return;
        }
        const err = error as NodeJS.ErrnoException & { code?: string; killed?: boolean; signal?: string; };
        resolve({
          stdout: stdout ?? "",
          stderr: stderr ?? String(error),
          exitCode: typeof (err as { code?: number }).code === "number" ? (err as { code?: number }).code! : 1,
          timedOut: err.killed || err.signal === "SIGTERM",
        });
      },
    );
  });
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

async function waitForVmSsh(config: KernelVmConfig, proc: ReturnType<typeof spawn>, bootLogPath: string): Promise<void> {
  const target = `${config.sshUser}@${config.sshHost}`;
  const deadline = Date.now() + config.bootTimeoutSec * 1000;

  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      const bootLog = existsSync(bootLogPath) ? readFileSync(bootLogPath, "utf-8").slice(-4000) : "";
      throw new Error(`kernel VM exited before SSH became available (exit=${proc.exitCode}).\n${bootLog}`);
    }
    const result = await execFileCaptured(
      config.sshBinary,
      [...buildSshBaseArgs(config), "-p", String(config.sshPort), target, "true"],
      7_000,
    );
    if (result.exitCode === 0) return;
    await sleep(2_000);
  }

  const bootLog = existsSync(bootLogPath) ? readFileSync(bootLogPath, "utf-8").slice(-4000) : "";
  throw new Error(`timed out waiting for kernel VM SSH on ${config.sshHost}:${config.sshPort}.\n${bootLog}`);
}

async function runRemoteCommand(config: KernelVmConfig, command: string, timeoutSec: number): Promise<{ stdout: string; stderr: string; exitCode: number; timedOut: boolean }> {
  const target = `${config.sshUser}@${config.sshHost}`;
  return execFileCaptured(
    config.sshBinary,
    [...buildSshBaseArgs(config), "-p", String(config.sshPort), target, "bash", "-lc", command],
    timeoutSec * 1000,
  );
}

async function copyFileToVm(config: KernelVmConfig, localPath: string, remotePath: string): Promise<{ stdout: string; stderr: string; exitCode: number; timedOut: boolean }> {
  const target = `${config.sshUser}@${config.sshHost}:${remotePath}`;
  return execFileCaptured(
    config.scpBinary,
    [...buildSshBaseArgs(config), "-P", String(config.sshPort), localPath, target],
    30_000,
  );
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
  const hostTmpDir = mkdtempSync(join(tmpdir(), "pwnkit-kvm-"));
  const sourcePath = join(hostTmpDir, "repro.c");
  const serialLogPath = join(hostTmpDir, "serial.log");
  const remoteDir = config.remoteWorkDir.replace(/\/+$/, "");
  const remoteSource = `${remoteDir}/repro.c`;
  const remoteBinary = `${remoteDir}/repro`;
  writeFileSync(sourcePath, report.reproducer, "utf-8");

  const { command, args } = buildQemuCommand(config, serialLogPath);
  const vmProc = spawn(command, args, {
    stdio: "ignore",
  });

  try {
    await waitForVmSsh(config, vmProc, serialLogPath);

    const mkdirResult = await runRemoteCommand(
      config,
      `mkdir -p ${shellQuote(remoteDir)}`,
      15,
    );
    if (mkdirResult.exitCode !== 0) {
      return {
        compiled: false,
        executed: false,
        output: mkdirResult.stderr || mkdirResult.stdout,
        dmesg: "",
        exitCode: mkdirResult.exitCode,
        timedOut: mkdirResult.timedOut,
      };
    }

    const scpResult = await copyFileToVm(config, sourcePath, remoteSource);
    if (scpResult.exitCode !== 0) {
      return {
        compiled: false,
        executed: false,
        output: scpResult.stderr || scpResult.stdout,
        dmesg: existsSync(serialLogPath) ? readFileSync(serialLogPath, "utf-8").slice(-4000) : "",
        exitCode: scpResult.exitCode,
        timedOut: scpResult.timedOut,
      };
    }

    const compileResult = await runRemoteCommand(
      config,
      `gcc -O0 -g -o ${shellQuote(remoteBinary)} ${shellQuote(remoteSource)} -lpthread 2>&1`,
      config.timeoutSec,
    );
    if (compileResult.exitCode !== 0) {
      return {
        compiled: false,
        executed: false,
        output: (compileResult.stdout + compileResult.stderr).trim(),
        dmesg: "",
        exitCode: compileResult.exitCode,
        timedOut: compileResult.timedOut,
      };
    }

    await runRemoteCommand(config, "dmesg -C 2>/dev/null || true", 10);
    const runResult = await runRemoteCommand(
      config,
      `timeout ${config.timeoutSec}s ${shellQuote(remoteBinary)} 2>&1 || true`,
      config.timeoutSec + 15,
    );
    const dmesgResult = await runRemoteCommand(config, "dmesg 2>/dev/null || true", 20);

    return {
      compiled: true,
      executed: true,
      output: (runResult.stdout + runResult.stderr).trim(),
      dmesg: (dmesgResult.stdout + dmesgResult.stderr).trim(),
      exitCode: runResult.exitCode,
      timedOut: runResult.timedOut,
    };
  } finally {
    await stopVm(vmProc);
    rmSync(hostTmpDir, { recursive: true, force: true });
  }
}

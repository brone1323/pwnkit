/**
 * Docker executor — runs agent bash commands inside a Kali Linux container.
 *
 * Provides a full pentesting toolset (nmap, sqlmap, metasploit, nikto, etc.)
 * in an isolated environment, similar to BoxPwnr's approach.
 *
 * Usage:
 *   const docker = DockerExecutor.getInstance();
 *   await docker.ensureRunning();
 *   const result = await docker.exec("nmap -sV target.com", 60);
 *   await docker.stop();
 */

import { execSync, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const PREBUILT_IMAGE = "ghcr.io/pwnkit-labs/pwnkit-kali:latest";
const LEGACY_KALI_IMAGE = "kalilinux/kali-rolling";
const CONTAINER_PREFIX = "pwnkit-kali";

/** Packages to install inside the Kali container on first boot. */
const PENTEST_PACKAGES = [
  "nmap",
  "sqlmap",
  "nikto",
  "gobuster",
  "dirb",
  "hydra",
  "john",
  "whatweb",
  "wfuzz",
  "ffuf",
  "seclists",
  "curl",
  "wget",
  "netcat-openbsd",
  "socat",
  "proxychains4",
  "python3",
  "python3-pip",
  "gdb",
  "gdb-multiarch",
  "radare2",
  "binwalk",
  "foremost",
  "libimage-exiftool-perl",
  "ltrace",
  "strace",
  "file",
  "binutils",
  "python3-ropgadget",
];

/** Extra Python packages to pip-install after apt bootstrap. */
const PENTEST_PIP_PACKAGES = ["requests", "pwntools", "beautifulsoup4"];

export interface DockerExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

export class DockerExecutor {
  private static instance: DockerExecutor | null = null;

  private containerId: string | null = null;
  private containerName: string;
  private ready = false;
  private targetEnv: string = "";
  private image: string;

  private constructor() {
    this.containerName = `${CONTAINER_PREFIX}-${randomUUID().slice(0, 8)}`;
    this.image = process.env.PWNKIT_DOCKER_IMAGE || PREBUILT_IMAGE;
  }

  /** Singleton — one container per process. */
  static getInstance(): DockerExecutor {
    if (!DockerExecutor.instance) {
      DockerExecutor.instance = new DockerExecutor();
    }
    return DockerExecutor.instance;
  }

  /** Reset the singleton (for testing). */
  static resetInstance(): void {
    DockerExecutor.instance = null;
  }

  /** Set the TARGET environment variable inside the container. */
  setTarget(target: string): void {
    this.targetEnv = target;
  }

  /** Start the Kali container if not already running, install tools. */
  async ensureRunning(): Promise<void> {
    if (this.ready && this.containerId && this.isContainerAlive()) {
      return;
    }

    this.assertDockerAvailable();

    // Pull image if not present (best-effort, may already be cached)
    try {
      execSync(`docker image inspect ${this.image} > /dev/null 2>&1`, {
        timeout: 5_000,
      });
    } catch {
      // Image not found locally — pull it
      execSync(`docker pull ${this.image}`, {
        timeout: 300_000, // 5 min for pull
        stdio: "pipe",
      });
    }

    // Start the container with:
    //  - shared /tmp/pwnkit-shared volume for file exchange
    //  - bridge networking by default (override via PWNKIT_DOCKER_NETWORK)
    //  - --rm for automatic cleanup on stop
    //  - long-running sleep to keep it alive
    const network = process.env.PWNKIT_DOCKER_NETWORK || "bridge";
    const runCmd = [
      "docker",
      "run",
      "-d",
      "--rm",
      "--name",
      this.containerName,
      "--network",
      network,
      "-v",
      "/tmp/pwnkit-shared:/shared",
      "-e",
      `TARGET=${this.targetEnv}`,
      "--entrypoint",
      "sleep",
      this.image,
      "infinity",
    ];

    const id = execFileSync(runCmd[0], runCmd.slice(1), {
      timeout: 30_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();

    this.containerId = id;
    this.registerExitHandlers();

    // The GHCR image is pre-baked with the standard toolchain.
    // Keep the legacy Kali bootstrap path for raw-image fallback.
    if (this.shouldBootstrapTools()) {
      const aptCmd = `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${PENTEST_PACKAGES.join(" ")}`;
      this.dockerExecSync(aptCmd, 600_000); // 10 min for install
      const pipCmd = `pip3 install --no-cache-dir --break-system-packages ${PENTEST_PIP_PACKAGES.join(" ")}`;
      this.dockerExecSync(pipCmd, 300_000); // 5 min for pip
    }

    this.ready = true;
  }

  /**
   * Execute a command inside the Kali container.
   * Returns structured result with stdout, stderr, exit code, and timeout flag.
   */
  async exec(command: string, timeoutSec: number = 30): Promise<DockerExecResult> {
    if (!this.containerId || !this.ready) {
      await this.ensureRunning();
    }

    const timeoutMs = timeoutSec * 1000;

    try {
      const stdout = execFileSync(
        "docker",
        ["exec", "-e", `TARGET=${this.targetEnv}`, this.containerId!, "bash", "-c", command],
        {
          timeout: timeoutMs,
          maxBuffer: 1024 * 1024, // 1MB
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "pipe"],
        },
      );

      return {
        stdout: stdout ?? "",
        stderr: "",
        exitCode: 0,
        timedOut: false,
      };
    } catch (err: any) {
      if (err.killed) {
        return {
          stdout: (err.stdout as string) ?? "",
          stderr: (err.stderr as string) ?? "",
          exitCode: -1,
          timedOut: true,
        };
      }

      return {
        stdout: (err.stdout as string) ?? "",
        stderr: (err.stderr as string) ?? "",
        exitCode: err.status ?? 1,
        timedOut: false,
      };
    }
  }

  /** Stop and remove the container. */
  async stop(): Promise<void> {
    if (!this.containerId) return;

    try {
      execSync(`docker rm -f ${this.containerId}`, {
        timeout: 15_000,
        stdio: "pipe",
      });
    } catch {
      // Best-effort cleanup
    }

    this.containerId = null;
    this.ready = false;
    DockerExecutor.instance = null;
  }

  /** Check if container is still running. */
  private isContainerAlive(): boolean {
    if (!this.containerId) return false;
    try {
      const status = execSync(
        `docker inspect -f '{{.State.Running}}' ${this.containerId}`,
        { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
      return status === "true";
    } catch {
      return false;
    }
  }

  /** Run a command inside the container synchronously (used during setup). */
  private dockerExecSync(command: string, timeoutMs: number): string {
    return execFileSync(
      "docker",
      ["exec", this.containerId!, "bash", "-c", command],
      {
        timeout: timeoutMs,
        maxBuffer: 2 * 1024 * 1024,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
  }

  /** Throw if Docker CLI is not available. */
  private assertDockerAvailable(): void {
    try {
      execSync("docker info > /dev/null 2>&1", { timeout: 10_000 });
    } catch {
      throw new Error(
        "Docker is not available. Install Docker and ensure the daemon is running to use --docker mode.",
      );
    }
  }

  /** Register process exit handlers to stop the container on termination. */
  private registerExitHandlers(): void {
    const cleanup = () => {
      if (this.containerId) {
        try {
          execSync(`docker stop ${this.containerId}`, {
            timeout: 10_000,
            stdio: "pipe",
          });
        } catch {
          // Best-effort — container may already be gone (--rm)
        }
        this.containerId = null;
        this.ready = false;
      }
    };

    process.once("exit", cleanup);
    process.once("SIGINT", () => { cleanup(); process.exit(130); });
    process.once("SIGTERM", () => { cleanup(); process.exit(143); });
  }

  private shouldBootstrapTools(): boolean {
    if (process.env.PWNKIT_DOCKER_BOOTSTRAP_TOOLS === "1") return true;
    if (process.env.PWNKIT_DOCKER_BOOTSTRAP_TOOLS === "0") return false;
    return this.image === LEGACY_KALI_IMAGE;
  }
}

/**
 * Convenience function for use in the tool executor.
 * Matches the same interface pattern as shellExec.
 */
export async function execInDocker(
  command: string,
  timeout: number,
  target?: string,
): Promise<{ output: string; timedOut: boolean; exitCode: number }> {
  const docker = DockerExecutor.getInstance();
  if (target) docker.setTarget(target);
  await docker.ensureRunning();

  const result = await docker.exec(command, timeout);
  const output = (result.stdout + "\n" + result.stderr).trim();

  return {
    output,
    timedOut: result.timedOut,
    exitCode: result.exitCode,
  };
}

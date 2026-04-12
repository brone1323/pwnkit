import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";

vi.mock("./kernel-vm-runner.js", () => ({
  runReproducerInKernelVm: vi.fn(),
}));

import { compileAndRunReproducer, verifyKernelCrash } from "./kernel-oracle.js";
import { runReproducerInKernelVm } from "./kernel-vm-runner.js";

const runVmMock = vi.mocked(runReproducerInKernelVm);

describe("compileAndRunReproducer", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.PWNKIT_KERNEL_QEMU;
    runVmMock.mockReset();
  });

  it("returns a dry-run result when kernel VM execution is disabled", async () => {
    const result = await compileAndRunReproducer({
      raw: "BUG: KASAN: slab-out-of-bounds",
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: ["nfsd_dispatch+0x1a2/0x340"],
      reproducer: "int main(void) { return 0; }",
    });

    expect(result.executed).toBe(false);
    expect(result.output).toContain("PWNKIT_KERNEL_QEMU not set");
    expect(runVmMock).not.toHaveBeenCalled();
  });

  it("delegates to the kernel VM runner when enabled", async () => {
    process.env.PWNKIT_KERNEL_QEMU = "1";
    runVmMock.mockResolvedValue({
      compiled: true,
      executed: true,
      output: "executing program",
      dmesg: "BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340",
      exitCode: 0,
      timedOut: false,
    });

    const report = {
      raw: "BUG: KASAN: slab-out-of-bounds",
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: ["nfsd_dispatch+0x1a2/0x340"],
      reproducer: "int main(void) { return 0; }",
    };

    const result = await compileAndRunReproducer(report);

    expect(runVmMock).toHaveBeenCalledWith(report);
    expect(result.executed).toBe(true);
    expect(result.dmesg).toContain("KASAN");
  });
});

describe("verifyKernelCrash", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, PWNKIT_KERNEL_QEMU: "1" };
    runVmMock.mockReset();
  });

  it("returns a verified verdict when the VM runner reproduces a matching crash", async () => {
    runVmMock.mockResolvedValue({
      compiled: true,
      executed: true,
      output: "executing program",
      dmesg: `
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234
Call Trace:
 nfsd_dispatch+0x1a2/0x340
 svc_process+0x15c/0x2c0
 nfsd+0x1e7/0x310
`,
      exitCode: 0,
      timedOut: false,
    });

    const finding: Finding = {
      id: "finding-1",
      templateId: "kernel-kasan-oob",
      title: "Linux kernel kasan-oob: nfsd_dispatch in fs/nfsd",
      description: "desc",
      severity: "critical",
      category: "heap-overflow",
      status: "discovered",
      evidence: { request: "req", response: "resp", analysis: "analysis" },
      confidence: 0.8,
      timestamp: Date.now(),
    };

    const result = await verifyKernelCrash(finding, {
      raw: `
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234
Allocated by task 1100:
 nfsd_svc+0x58/0x90
`,
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: [
        "nfsd_dispatch+0x1a2/0x340",
        "svc_process+0x15c/0x2c0",
        "nfsd+0x1e7/0x310",
      ],
      reproducer: "int main(void) { return 0; }",
      accessType: "read",
      accessSize: 4,
      subsystem: "nfs",
    });

    expect(result.verified).toBe(true);
    expect(result.reproduced).toBe(true);
    expect(result.crashMatch).toBe(true);
    expect(result.reproducedCrashType).toBe("kasan-oob");
  });
});

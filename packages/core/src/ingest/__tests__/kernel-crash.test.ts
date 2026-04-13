import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  parseCrashReport,
  crashToFinding,
  crashTypeToCategory,
  crashSeverity,
  ingestArtifactsFromDirectory,
  ingestArtifactsFromFile,
  ingestFile,
  ingestDirectory,
} from "../kernel-crash.js";
import {
  validateCrashReportConsistency,
  matchCrashSignature,
} from "../../triage/kernel-oracle.js";
import type { CrashReport } from "@pwnkit/shared";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ────────────────────────────────────────────────────────────────────
// Fixtures — realistic kernel crash output
// ────────────────────────────────────────────────────────────────────

const KASAN_SLAB_OOB = `
==================================================================
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340 [nfsd]
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234

CPU: 2 PID: 1234 Comm: nfsd Not tainted 6.1.0-rc5+ #42
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)
Call Trace:
 [<ffffffff81234567>] dump_stack_lvl+0x34/0x44
 [<ffffffff81345678>] print_report+0x171/0x4b6
 [<ffffffff81456789>] kasan_report+0xad/0x130
 [<ffffffff81567890>] nfsd_dispatch+0x1a2/0x340
 [<ffffffff81678901>] svc_process+0x15c/0x2c0
 [<ffffffff81789012>] nfsd+0x1e7/0x310

Allocated by task 1100:
 [<ffffffff81234560>] kmalloc+0x24/0x40
 [<ffffffff81345670>] nfsd_svc+0x58/0x90
 [<ffffffff81456780>] write_threads+0x12c/0x1b0

The buggy address belongs to the object at ffff88800abcde00
 which belongs to the cache kmalloc-64 of size 64
==================================================================
`;

const KASAN_UAF = `
==================================================================
BUG: KASAN: slab-use-after-free in sk_filter_trim_cap+0x68/0x220
Write of size 8 at addr ffff888012345678 by task test_prog/5678

CPU: 1 PID: 5678 Comm: test_prog Not tainted 6.2.0+ #17
Call Trace:
 [<ffffffff81111111>] dump_stack_lvl+0x34/0x44
 [<ffffffff81222222>] print_report+0x171/0x4b6
 [<ffffffff81333333>] kasan_report+0xad/0x130
 [<ffffffff81444444>] sk_filter_trim_cap+0x68/0x220
 [<ffffffff81555555>] sock_queue_rcv_skb+0x30/0x60
 [<ffffffff81666666>] tcp_rcv_established+0x6e0/0xb70

Allocated by task 5600:
 [<ffffffff81777777>] kmalloc+0x24/0x40
 [<ffffffff81888888>] sk_alloc+0x48/0x90
 [<ffffffff81999999>] inet_create+0x1cc/0x360

Freed by task 5677:
 [<ffffffff81aaaaaa>] kfree+0x24/0x40
 [<ffffffff81bbbbbb>] sk_free+0x48/0x80
 [<ffffffff81cccccc>] tcp_close+0x1e0/0x350

The buggy address belongs to the object at ffff888012345600
==================================================================
`;

const UBSAN_SHIFT = `
================================================================================
UBSAN: shift-out-of-range in drivers/media/v4l2-core/v4l2_ctrl+0x18a/0x3c0
shift exponent 64 is too large for 64-bit type 'long unsigned int'
CPU: 0 PID: 321 Comm: v4l2-test Not tainted 6.3.0 #1
Call Trace:
 [<ffffffff81abcdef>] dump_stack_lvl+0x34/0x44
 [<ffffffff81fedcba>] __ubsan_handle_shift_out_of_bounds+0x1a2/0x200
 [<ffffffff81dcba09>] v4l2_ctrl+0x18a/0x3c0
`;

const KERNEL_OOPS_WITH_IP = `
BUG: unable to handle page fault at 0000000000001234
Oops: 0002 [#1] PREEMPT SMP KASAN
CPU: 3 PID: 999 Comm: kworker/3:1 Not tainted 6.4.0-rc1+ #5
IP: [<ffffffff8199aabb>] ext4_dirty_inode+0x38/0x90
Call Trace:
 [<ffffffff81aabbcc>] __mark_inode_dirty+0x1e0/0x340
 [<ffffffff81bbccdd>] generic_write_end+0xd0/0x150
 [<ffffffff81ccddee>] ext4_write_end+0x60/0x180
`;

const KERNEL_OOPS_INVALID_OPCODE = `
------------[ cut here ]------------
kernel BUG at fs/f2fs/segment.c:1900!
Oops: invalid opcode: 0000 [#1] SMP KASAN PTI
CPU: 1 UID: 0 PID: 7532 Comm: syz.1.186 Not tainted syzkaller #0 PREEMPT
RIP: 0010:f2fs_issue_discard_timeout+0x59b/0x5a0 fs/f2fs/segment.c:1900
Call Trace:
 <TASK>
 __f2fs_remount fs/f2fs/super.c:2960 [inline]
 f2fs_reconfigure+0x108a/0x1710 fs/f2fs/super.c:5443
 reconfigure_super+0x227/0x8a0 fs/super.c:1080
 path_mount+0xdc5/0x10e0 fs/namespace.c:4151
 do_mount fs/namespace.c:4172 [inline]
 __se_sys_mount+0x31d/0x420 fs/namespace.c:4338
 do_syscall_64+0x14d/0xf80 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
 </TASK>
---[ end trace 0000000000000000 ]---
`;

const GP_FAULT = `
general protection fault, probably for non-canonical address 0xdead000000000000: 0000 [#1] PREEMPT SMP
CPU: 0 PID: 42 Comm: syzkaller Not tainted 6.1.0 #3
IP: [<ffffffff81aabb00>] io_uring_setup+0x44/0x1b0
Call Trace:
 [<ffffffff81ddeeff>] __do_sys_io_uring_setup+0x18/0x30
 [<ffffffff81eeff00>] do_syscall_64+0x35/0x80
`;

const RCU_STALL = `
rcu: INFO: rcu_sched self-detected stall on CPU
rcu:   3-....: (5000 ticks this GP) idle=3b2/1/0x4000000000000000 softirq=1234/1235 fqs=2500
CPU: 3 PID: 789 Comm: stress Not tainted 6.5.0-rc2 #8
Call Trace:
 [<ffffffff81112233>] sched_show_task+0x1a8/0x240
 [<ffffffff81223344>] rcu_dump_cpu_stacks+0x174/0x1b0
 [<ffffffff81334455>] rcu_sched_clock_irq+0x960/0xac0
`;

const GARBAGE_INPUT = `
This is just a random text file
with no kernel crash report content at all.
Hello world!
`;

const EMPTY_INPUT = "";

// ────────────────────────────────────────────────────────────────────
// 1. parseCrashReport
// ────────────────────────────────────────────────────────────────────

describe("parseCrashReport", () => {
  it("extracts KASAN slab-out-of-bounds fields", () => {
    const report = parseCrashReport(KASAN_SLAB_OOB);
    expect(report.crashType).toBe("kasan-oob");
    expect(report.faultingFunction).toBe("nfsd_dispatch");
    expect(report.accessType).toBe("read");
    expect(report.accessSize).toBe(4);
    expect(report.callStack.length).toBeGreaterThan(0);
    expect(report.allocSite).toBe("nfsd_svc");
  });

  it("extracts KASAN use-after-free with free site and alloc site", () => {
    const report = parseCrashReport(KASAN_UAF);
    expect(report.crashType).toBe("kasan-uaf");
    expect(report.faultingFunction).toBe("sk_filter_trim_cap");
    expect(report.accessType).toBe("write");
    expect(report.accessSize).toBe(8);
    expect(report.allocSite).toBeDefined();
    expect(report.freeSite).toBeDefined();
    // The alloc/free site extractors skip allocator internals
    expect(report.allocSite).toBe("sk_alloc");
    expect(report.freeSite).toBe("sk_free");
  });

  it("extracts UBSAN shift-out-of-range fields", () => {
    const report = parseCrashReport(UBSAN_SHIFT);
    expect(report.crashType).toBe("ubsan");
    // After the UBSAN fix, we extract the real function name from the call trace
    // (first non-ubsan frame) instead of the file:line:col from the UBSAN header
    expect(report.faultingFunction).toBe("v4l2_ctrl");
  });

  it("extracts kernel oops with IP line", () => {
    const report = parseCrashReport(KERNEL_OOPS_WITH_IP);
    expect(report.crashType).toBe("kernel-oops");
    expect(report.faultingFunction).toBe("ext4_dirty_inode");
  });

  it("extracts kernel oops with invalid opcode RIP line", () => {
    const report = parseCrashReport(KERNEL_OOPS_INVALID_OPCODE);
    expect(report.crashType).toBe("kernel-oops");
    expect(report.faultingFunction).toBe("f2fs_issue_discard_timeout");
    expect(report.subsystem).toBe("f2fs");
  });

  it("extracts general protection fault", () => {
    const report = parseCrashReport(GP_FAULT);
    expect(report.crashType).toBe("general-protection");
    expect(report.faultingFunction).toBe("io_uring_setup");
  });

  it("extracts RCU stall", () => {
    const report = parseCrashReport(RCU_STALL);
    expect(report.crashType).toBe("rcu-stall");
    // faultingFunction should come from the call stack
    expect(report.faultingFunction).not.toBe("unknown");
  });

  it("returns crashType 'unknown' for empty input", () => {
    const report = parseCrashReport(EMPTY_INPUT);
    expect(report.crashType).toBe("unknown");
  });

  it("returns crashType 'unknown' for garbage input", () => {
    const report = parseCrashReport(GARBAGE_INPUT);
    expect(report.crashType).toBe("unknown");
  });

  describe("subsystem inference", () => {
    it("infers fs/nfsd for NFS functions", () => {
      const report = parseCrashReport(KASAN_SLAB_OOB);
      expect(report.subsystem).toBe("fs/nfsd");
    });

    it("infers net/tcp for tcp_ functions", () => {
      const tcpCrash = `
BUG: KASAN: slab-out-of-bounds in tcp_recvmsg+0x44/0x100
Read of size 2 at addr ffff888000112233 by task test/111

Call Trace:
 [<ffffffff81000001>] tcp_recvmsg+0x44/0x100
 [<ffffffff81000002>] inet_recvmsg+0x60/0x120

Allocated by task 100:
 [<ffffffff81000003>] kmalloc+0x24/0x40
 [<ffffffff81000004>] tcp_sendmsg+0x80/0x200
`;
      const report = parseCrashReport(tcpCrash);
      expect(report.subsystem).toBe("net/tcp");
    });

    it("infers fs/ext4 for ext4_ functions", () => {
      const report = parseCrashReport(KERNEL_OOPS_WITH_IP);
      expect(report.subsystem).toBe("fs/ext4");
    });
  });
});

// ────────────────────────────────────────────────────────────────────
// 2. crashTypeToCategory
// ────────────────────────────────────────────────────────────────────

describe("crashTypeToCategory", () => {
  it("maps kasan-oob to heap-overflow", () => {
    expect(crashTypeToCategory("kasan-oob")).toBe("heap-overflow");
  });

  it("maps kasan-uaf to use-after-free", () => {
    expect(crashTypeToCategory("kasan-uaf")).toBe("use-after-free");
  });

  it("maps ubsan to integer-overflow", () => {
    expect(crashTypeToCategory("ubsan")).toBe("integer-overflow");
  });

  it("maps rcu-stall to race-condition", () => {
    expect(crashTypeToCategory("rcu-stall")).toBe("race-condition");
  });

  it("maps lockdep to race-condition", () => {
    expect(crashTypeToCategory("lockdep")).toBe("race-condition");
  });

  it("maps general-protection to null-pointer-deref", () => {
    expect(crashTypeToCategory("general-protection")).toBe("null-pointer-deref");
  });
});

// ────────────────────────────────────────────────────────────────────
// 3. crashSeverity
// ────────────────────────────────────────────────────────────────────

describe("crashSeverity", () => {
  function makeReport(overrides: Partial<CrashReport>): CrashReport {
    return {
      rawText: "",
      crashType: "unknown",
      faultingFunction: "unknown",
      callStack: [],
      subsystem: "unknown",
      ...overrides,
    };
  }

  it("rates UAF as critical", () => {
    const sev = crashSeverity(makeReport({ crashType: "kasan-uaf" }));
    expect(sev).toBe("critical");
  });

  it("rates OOB write as critical", () => {
    const sev = crashSeverity(
      makeReport({ crashType: "kasan-oob", accessType: "write" }),
    );
    expect(sev).toBe("critical");
  });

  it("rates OOB read as high", () => {
    const sev = crashSeverity(
      makeReport({ crashType: "kasan-oob", accessType: "read" }),
    );
    expect(sev).toBe("high");
  });

  it("rates null-deref (kernel-oops) as medium", () => {
    const sev = crashSeverity(makeReport({ crashType: "kernel-oops" }));
    expect(sev).toBe("medium");
  });

  it("boosts OOB read in NFS subsystem from high to critical", () => {
    const sev = crashSeverity(
      makeReport({
        crashType: "kasan-oob",
        accessType: "read",
        subsystem: "fs/nfsd",
      }),
    );
    expect(sev).toBe("critical");
  });

  it("boosts rcu-stall in net/tcp from low to medium", () => {
    const sev = crashSeverity(
      makeReport({ crashType: "rcu-stall", subsystem: "net/tcp" }),
    );
    expect(sev).toBe("medium");
  });

  it("does not boost for non-network subsystems", () => {
    const sev = crashSeverity(
      makeReport({ crashType: "rcu-stall", subsystem: "fs/ext4" }),
    );
    expect(sev).toBe("low");
  });
});

// ────────────────────────────────────────────────────────────────────
// 4. crashToFinding
// ────────────────────────────────────────────────────────────────────

describe("crashToFinding", () => {
  it("returns a valid Finding with all required fields", () => {
    const report = parseCrashReport(KASAN_SLAB_OOB);
    const finding = crashToFinding(report);

    expect(finding.id).toBeDefined();
    expect(finding.templateId).toBe("kernel-kasan-oob");
    expect(finding.title).toContain("kasan-oob");
    expect(finding.title).toContain("nfsd_dispatch");
    expect(finding.severity).toBeDefined();
    expect(finding.category).toBe("heap-overflow");
    expect(finding.status).toBe("discovered");
    expect(finding.evidence).toBeDefined();
    expect(finding.evidence.analysis).toContain("kasan-oob");
    expect(finding.timestamp).toBeGreaterThan(0);
  });

  it("truncates evidence response when raw text exceeds 4000 chars", () => {
    const longText = KASAN_SLAB_OOB + "\n" + "x".repeat(5000);
    const report = parseCrashReport(longText);
    const finding = crashToFinding(report);

    expect(finding.evidence.response.length).toBeLessThanOrEqual(4020);
    expect(finding.evidence.response).toContain("[truncated]");
  });

  it("does not truncate evidence when raw text is under 4000 chars", () => {
    const report = parseCrashReport(KASAN_SLAB_OOB);
    const finding = crashToFinding(report);

    expect(finding.evidence.response).not.toContain("[truncated]");
  });

  it("assigns confidence 0.8 for KASAN reports", () => {
    const report = parseCrashReport(KASAN_SLAB_OOB);
    const finding = crashToFinding(report);
    expect(finding.confidence).toBe(0.8);
  });

  it("assigns confidence 0.7 for UBSAN reports", () => {
    const report = parseCrashReport(UBSAN_SHIFT);
    const finding = crashToFinding(report);
    expect(finding.confidence).toBe(0.7);
  });

  it("assigns confidence 0.6 for kernel-oops reports", () => {
    const report = parseCrashReport(KERNEL_OOPS_WITH_IP);
    const finding = crashToFinding(report);
    expect(finding.confidence).toBe(0.6);
  });
});

// ────────────────────────────────────────────────────────────────────
// 5. ingestFile
// ────────────────────────────────────────────────────────────────────

describe("ingestFile", () => {
  function writeTmpFile(content: string, ext = ".log"): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "kernel-crash-test-"));
    const filePath = path.join(tmpDir, `crash${ext}`);
    fs.writeFileSync(filePath, content, "utf-8");
    return filePath;
  }

  it("parses a single crash report file", () => {
    const filePath = writeTmpFile(KASAN_SLAB_OOB);
    const findings = ingestFile(filePath);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.category).toBe("heap-overflow");
  });

  it("returns artifact metadata for a single crash report file", () => {
    const filePath = writeTmpFile(KASAN_SLAB_OOB);
    const artifacts = ingestArtifactsFromFile(filePath);

    expect(artifacts).toHaveLength(1);
    expect(artifacts[0]!.sourcePath).toBe(filePath);
    expect(artifacts[0]!.report.crashType).toBe("kasan-oob");
    expect(artifacts[0]!.finding.category).toBe("heap-overflow");
  });

  it("splits multi-report files separated by ===", () => {
    const multiReport = [KASAN_SLAB_OOB, "===", KASAN_UAF].join("\n");
    const filePath = writeTmpFile(multiReport);
    const findings = ingestFile(filePath);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.category)).toContain("heap-overflow");
    expect(findings.map((f) => f.category)).toContain("use-after-free");
  });

  it("ingests kernel oops reports with invalid opcode RIP headers", () => {
    const filePath = writeTmpFile(KERNEL_OOPS_INVALID_OPCODE);
    const findings = ingestFile(filePath);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.templateId).toBe("kernel-kernel-oops");
    expect(findings[0]!.title).toContain("f2fs_issue_discard_timeout");
  });

  it("returns empty array for non-crash-report files", () => {
    const filePath = writeTmpFile(GARBAGE_INPUT);
    const findings = ingestFile(filePath);
    expect(findings).toHaveLength(0);
  });

  it("throws on non-existent file", () => {
    expect(() => ingestFile("/tmp/nonexistent-crash-report-xyz.log")).toThrow();
  });
});

// ────────────────────────────────────────────────────────────────────
// 6. ingestDirectory
// ────────────────────────────────────────────────────────────────────

describe("ingestDirectory", () => {
  function makeTmpDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), "kernel-crash-dir-test-"));
  }

  it("finds crash files by extension", () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, "report1.log"), KASAN_SLAB_OOB);
    fs.writeFileSync(path.join(dir, "report2.txt"), KASAN_UAF);
    fs.writeFileSync(path.join(dir, "readme.md"), "This is not a crash report");

    const findings = ingestDirectory(dir);
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("attaches reproducers by filename prefix", () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, "crash001.log"), KASAN_SLAB_OOB);
    fs.writeFileSync(
      path.join(dir, "crash001.c"),
      '#include <stdio.h>\nint main() { printf("repro"); return 0; }',
    );

    const findings = ingestDirectory(dir);
    expect(findings).toHaveLength(1);
    // The reproducer is attached to the report; evidence.request carries it
    expect(findings[0]!.evidence.request).toContain("repro");
  });

  it("returns artifact metadata with reproducer path", () => {
    const dir = makeTmpDir();
    const reportPath = path.join(dir, "crash001.log");
    const reproPath = path.join(dir, "crash001.c");
    fs.writeFileSync(reportPath, KASAN_SLAB_OOB);
    fs.writeFileSync(
      reproPath,
      '#include <stdio.h>\nint main() { printf("repro"); return 0; }',
    );

    const artifacts = ingestArtifactsFromDirectory(dir);
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0]!.sourcePath).toBe(reportPath);
    expect(artifacts[0]!.reproducerPath).toBe(reproPath);
    expect(artifacts[0]!.report.reproducer).toContain("repro");
  });

  it("deduplicates by function + crashType", () => {
    const dir = makeTmpDir();
    // Two identical crash reports in separate files
    fs.writeFileSync(path.join(dir, "dup1.log"), KASAN_SLAB_OOB);
    fs.writeFileSync(path.join(dir, "dup2.log"), KASAN_SLAB_OOB);

    const findings = ingestDirectory(dir);
    expect(findings).toHaveLength(1);
  });
});

// ────────────────────────────────────────────────────────────────────
// 7. validateCrashReportConsistency (kernel-oracle)
// ────────────────────────────────────────────────────────────────────

describe("validateCrashReportConsistency", () => {
  it("gives a high score for a valid KASAN OOB report", () => {
    const result = validateCrashReportConsistency({
      raw: KASAN_SLAB_OOB,
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: [
        "dump_stack_lvl+0x34/0x44",
        "print_report+0x171/0x4b6",
        "kasan_report+0xad/0x130",
        "nfsd_dispatch+0x1a2/0x340",
        "svc_process+0x15c/0x2c0",
        "nfsd+0x1e7/0x310",
      ],
      accessType: "read",
      accessSize: 4,
      subsystem: "nfs",
    });

    expect(result.valid).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(0.6);
  });

  it("gives a low score for garbage stack frames", () => {
    const result = validateCrashReportConsistency({
      raw: "BUG: KASAN: slab-out-of-bounds in foo\nRead of size 4 at addr ffff888000000000",
      crashType: "kasan-oob",
      faultingFunction: "foo",
      stackFrames: [
        "AAAA",
        "BBBB",
        "1234",
        "!!!garbage!!!",
        "@#$%",
      ],
      accessType: "read",
      accessSize: 4,
    });

    // Stack frames without +0x offsets should fail the format check
    expect(result.score).toBeLessThan(0.8);
    const frameCheck = result.checks.find((c) => c.name === "stack_frame_format");
    expect(frameCheck).toBeDefined();
    expect(frameCheck!.passed).toBe(false);
  });

  it("fails the alloc/free check for UAF without free site", () => {
    // UAF report that has "Allocated by task" but no "Freed by task"
    const rawMissingFree = `
BUG: KASAN: slab-use-after-free in test_func+0x10/0x20
Write of size 4 at addr ffff888000001234 by task test/100
Allocated by task 99:
 kmalloc+0x24/0x40
 test_alloc+0x30/0x50
The buggy address belongs to the object at ffff888000001200
`;

    const result = validateCrashReportConsistency({
      raw: rawMissingFree,
      crashType: "kasan-uaf",
      faultingFunction: "test_func",
      stackFrames: [
        "test_func+0x10/0x20",
      ],
      accessType: "write",
      accessSize: 4,
    });

    const allocFreeCheck = result.checks.find(
      (c) => c.name === "kasan_alloc_free_sections",
    );
    expect(allocFreeCheck).toBeDefined();
    expect(allocFreeCheck!.passed).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────
// 8. matchCrashSignature (kernel-oracle)
// ────────────────────────────────────────────────────────────────────

describe("matchCrashSignature", () => {
  it("returns a high score when crash type and function match", () => {
    const original = {
      raw: KASAN_SLAB_OOB,
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: [
        "nfsd_dispatch+0x1a2/0x340",
        "svc_process+0x15c/0x2c0",
        "nfsd+0x1e7/0x310",
      ],
      accessType: "read",
      accessSize: 4,
      subsystem: "nfs",
    };

    // Simulated reproduced output that matches
    const reproOutput = `
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340 [nfsd]
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234
Call Trace:
 nfsd_dispatch+0x1a2/0x340
 svc_process+0x15c/0x2c0
 nfsd+0x1e7/0x310
`;

    const result = matchCrashSignature(original, reproOutput);
    expect(result.matched).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(0.5);
    expect(result.matchedFields).toContain("crashType");
    expect(result.matchedFields).toContain("faultingFunction");
  });

  it("returns low score and matched=false for unrelated output", () => {
    const original = {
      raw: KASAN_UAF,
      crashType: "kasan-uaf",
      faultingFunction: "sk_filter_trim_cap",
      stackFrames: [
        "sk_filter_trim_cap+0x68/0x220",
        "sock_queue_rcv_skb+0x30/0x60",
        "tcp_rcv_established+0x6e0/0xb70",
      ],
      accessType: "write",
      accessSize: 8,
    };

    const reproOutput = `
Program executed successfully.
No kernel errors detected.
System running normally.
`;

    const result = matchCrashSignature(original, reproOutput);
    expect(result.matched).toBe(false);
    expect(result.score).toBeLessThan(0.5);
    expect(result.mismatchedFields.length).toBeGreaterThan(0);
  });

  it("gives partial score when crash type matches but function differs", () => {
    const original = {
      raw: KASAN_SLAB_OOB,
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: [
        "nfsd_dispatch+0x1a2/0x340",
      ],
      accessType: "read",
      accessSize: 4,
    };

    const reproOutput = `
BUG: KASAN: slab-out-of-bounds in completely_different_func+0x10/0x20
Read of size 4 at addr ffff888099887766 by task test/100
`;

    const result = matchCrashSignature(original, reproOutput);
    // Crash type matches (0.3) + access type partial (0.1) but function and frames don't
    expect(result.matchedFields).toContain("crashType");
    expect(result.mismatchedFields).toContain("faultingFunction");
  });
});

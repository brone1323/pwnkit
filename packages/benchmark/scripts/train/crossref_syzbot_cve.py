#!/usr/bin/env python3
"""Cross-reference syzbot fix commits with CVE databases for ground-truth labels.

Strategy (two-phase, offline-first):
  1. Download nluedtke/linux_kernel_cves kernel_cves.json (~6 MB) which maps
     CVE → {fixes: <full_hash>, cvss2, cvss3, ...}.  Build a reverse index
     short_hash → [(cve_id, cvss3_score)].
  2. For any remaining unmatched commits, optionally query the NVD REST API
     (rate-limited to 1 req / 6 s without an API key).

Outputs enriched JSONL with added fields:
    has_cve       bool   – True if at least one CVE references this fix commit
    cve_id        str    – first matched CVE (or null)
    cve_ids       list   – all matched CVEs
    cvss_score    float  – highest CVSS v3 score across matched CVEs (or null)

Usage:
    python crossref_syzbot_cve.py --input /tmp/syzbot-exploitability.jsonl
    python crossref_syzbot_cve.py --input /tmp/syzbot-exploitability.jsonl --output /tmp/syzbot-cve-labeled.jsonl
    python crossref_syzbot_cve.py --input /tmp/syzbot-exploitability.jsonl --nvd-fallback --nvd-limit 20
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path
from typing import Any

# ── Constants ───────────────────────────────────────────────────────────────

KERNEL_CVES_URL = (
    "https://raw.githubusercontent.com/nluedtke/linux_kernel_cves"
    "/master/data/kernel_cves.json"
)
KERNEL_CVES_CACHE = Path("/tmp/kernel_cves.json")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 6.0  # seconds between requests (no API key)

UA = "pwnkit-cve-crossref/0.1"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _fetch_json(url: str, timeout: int = 60) -> Any:
    return json.loads(_fetch(url, timeout))


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# ── Phase 1: Build reverse index from kernel_cves.json ─────────────────────

def download_kernel_cves(force: bool = False) -> dict:
    """Download or load cached kernel_cves.json (~6 MB)."""
    if KERNEL_CVES_CACHE.exists() and not force:
        age_h = (time.time() - KERNEL_CVES_CACHE.stat().st_mtime) / 3600
        if age_h < 168:  # 1 week
            log(f"Using cached {KERNEL_CVES_CACHE} (age {age_h:.0f}h)")
            with open(KERNEL_CVES_CACHE) as f:
                return json.load(f)

    log(f"Downloading kernel_cves.json from GitHub ...")
    data = _fetch(KERNEL_CVES_URL, timeout=120)
    KERNEL_CVES_CACHE.write_bytes(data)
    log(f"Saved {len(data):,} bytes to {KERNEL_CVES_CACHE}")
    return json.loads(data)


def _extract_cvss3(entry: dict) -> float | None:
    """Extract CVSS v3 base score from a kernel_cves.json entry."""
    c3 = entry.get("cvss3")
    if c3 and isinstance(c3, dict):
        score = c3.get("score")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
    return None


def _extract_cvss2(entry: dict) -> float | None:
    c2 = entry.get("cvss2")
    if c2 and isinstance(c2, dict):
        score = c2.get("score")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
    return None


def build_reverse_index(kernel_cves: dict) -> dict[str, list[tuple[str, float | None]]]:
    """Map short commit prefix → [(cve_id, best_cvss_score), ...].

    The fixes field may be a single hash or occasionally missing.
    We index on both 12-char and 8-char prefixes (syzbot uses 12-char
    abbreviated hashes).
    """
    index: dict[str, list[tuple[str, float | None]]] = defaultdict(list)
    n_indexed = 0

    for cve_id, entry in kernel_cves.items():
        fixes_hash = entry.get("fixes")
        if not fixes_hash or not isinstance(fixes_hash, str):
            continue
        fixes_hash = fixes_hash.strip()
        if len(fixes_hash) < 8:
            continue

        score = _extract_cvss3(entry) or _extract_cvss2(entry)
        record = (cve_id, score)

        # Index multiple prefix lengths for flexible matching
        for plen in (8, 10, 12, 16, 20, 40):
            prefix = fixes_hash[:plen]
            if len(fixes_hash) >= plen:
                index[prefix].append(record)

        # Also full hash
        if fixes_hash not in index:
            index[fixes_hash].append(record)
        elif record not in index[fixes_hash]:
            index[fixes_hash].append(record)

        n_indexed += 1

    log(f"Indexed {n_indexed:,} CVEs with fix commits, "
        f"{len(index):,} prefix entries")
    return dict(index)


def lookup_commit(index: dict, short_hash: str) -> list[tuple[str, float | None]]:
    """Look up a short commit hash in the reverse index."""
    short_hash = short_hash.strip().lower()
    # Try exact length first, then shorter prefixes
    for plen in (len(short_hash), 12, 10, 8):
        prefix = short_hash[:plen]
        if prefix in index:
            return index[prefix]
    return []


# ── Phase 2 (optional): NVD API fallback ───────────────────────────────────

def nvd_search_commit(commit_hash: str) -> list[dict]:
    """Search NVD for a kernel commit hash. Returns list of {cve_id, cvss_score}."""
    # NVD keywordSearch can find commit hashes in references/descriptions
    url = f"{NVD_API}?keywordSearch={commit_hash}&keywordExactMatch"
    try:
        data = _fetch_json(url, timeout=30)
    except urllib.error.HTTPError as e:
        log(f"  NVD HTTP {e.code} for {commit_hash}")
        return []
    except Exception as e:
        log(f"  NVD error for {commit_hash}: {e}")
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract CVSS v3.1 score
        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                score = metric_list[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    break

        results.append({"cve_id": cve_id, "cvss_score": score})

    return results


# ── Main pipeline ───────────────────────────────────────────────────────────

def enrich_records(
    input_path: str,
    output_path: str | None,
    nvd_fallback: bool = False,
    nvd_limit: int = 0,
) -> None:
    # Load syzbot data
    records = []
    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    log(f"Loaded {len(records):,} syzbot records")

    with_fix = [r for r in records if r.get("fix_commit")]
    log(f"  {len(with_fix):,} have fix_commit")

    # Phase 1: kernel_cves.json reverse index
    kernel_cves = download_kernel_cves()
    log(f"kernel_cves.json has {len(kernel_cves):,} CVE entries")
    index = build_reverse_index(kernel_cves)

    # Match
    matched = 0
    unmatched_with_fix = []
    for rec in records:
        commit = rec.get("fix_commit")
        if not commit:
            rec["has_cve"] = False
            rec["cve_id"] = None
            rec["cve_ids"] = []
            rec["cvss_score"] = None
            continue

        hits = lookup_commit(index, commit)
        if hits:
            matched += 1
            # Deduplicate
            seen = set()
            unique = []
            for cve_id, score in hits:
                if cve_id not in seen:
                    seen.add(cve_id)
                    unique.append((cve_id, score))

            rec["has_cve"] = True
            rec["cve_id"] = unique[0][0]
            rec["cve_ids"] = [c for c, _ in unique]
            scores = [s for _, s in unique if s is not None]
            rec["cvss_score"] = max(scores) if scores else None
        else:
            rec["has_cve"] = False
            rec["cve_id"] = None
            rec["cve_ids"] = []
            rec["cvss_score"] = None
            unmatched_with_fix.append(rec)

    log(f"\nPhase 1 results (kernel_cves.json):")
    log(f"  Matched:   {matched:,} / {len(with_fix):,} fix commits → CVE")
    log(f"  Unmatched: {len(unmatched_with_fix):,} fix commits (no CVE found)")

    # Phase 2: NVD fallback for unmatched
    if nvd_fallback and unmatched_with_fix:
        limit = min(nvd_limit, len(unmatched_with_fix)) if nvd_limit > 0 else len(unmatched_with_fix)
        log(f"\nPhase 2: Querying NVD API for {limit} unmatched commits "
            f"(~{limit * NVD_RATE_LIMIT:.0f}s) ...")
        nvd_found = 0
        for i, rec in enumerate(unmatched_with_fix[:limit]):
            commit = rec["fix_commit"]
            log(f"  [{i+1}/{limit}] NVD search: {commit}")
            results = nvd_search_commit(commit)
            if results:
                nvd_found += 1
                rec["has_cve"] = True
                rec["cve_id"] = results[0]["cve_id"]
                rec["cve_ids"] = [r["cve_id"] for r in results]
                scores = [r["cvss_score"] for r in results if r["cvss_score"] is not None]
                rec["cvss_score"] = max(scores) if scores else None
                log(f"    → {rec['cve_id']} (CVSS {rec['cvss_score']})")
            if i < limit - 1:
                time.sleep(NVD_RATE_LIMIT)

        log(f"  NVD found {nvd_found} additional CVEs from {limit} queries")

    # Summary stats
    cve_count = sum(1 for r in records if r.get("has_cve"))
    score_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for r in records:
        s = r.get("cvss_score")
        if s is None:
            continue
        if s >= 9.0:
            score_counts["critical"] += 1
        elif s >= 7.0:
            score_counts["high"] += 1
        elif s >= 4.0:
            score_counts["medium"] += 1
        elif s > 0:
            score_counts["low"] += 1
        else:
            score_counts["none"] += 1

    log(f"\n{'='*60}")
    log(f"Final summary:")
    log(f"  Total records:     {len(records):,}")
    log(f"  With fix_commit:   {len(with_fix):,}")
    log(f"  With CVE:          {cve_count:,} ({100*cve_count/len(with_fix):.1f}% of fixes)")
    log(f"  CVSS distribution: {score_counts}")

    # Cross-tab: syzbot heuristic vs CVE ground truth
    from collections import Counter
    cross = Counter()
    for r in records:
        label = r.get("exploitability", "unknown")
        has = "cve" if r.get("has_cve") else "no_cve"
        cross[(label, has)] += 1

    log(f"\nSyzbot-label × CVE cross-tabulation:")
    log(f"  {'label':<25} {'has_cve':>10} {'no_cve':>10} {'cve_rate':>10}")
    for label in sorted(set(l for l, _ in cross)):
        c = cross.get((label, "cve"), 0)
        n = cross.get((label, "no_cve"), 0)
        rate = c / (c + n) * 100 if (c + n) > 0 else 0
        log(f"  {label:<25} {c:>10,} {n:>10,} {rate:>9.1f}%")
    log(f"{'='*60}")

    # Write output
    out = output_path or input_path.replace(".jsonl", "-cve-labeled.jsonl")
    if out == input_path:
        out = input_path + ".cve-labeled.jsonl"

    with open(out, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    log(f"\nWrote {len(records):,} records to {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-reference syzbot fix commits with CVE databases"
    )
    parser.add_argument("--input", required=True, help="Input syzbot JSONL file")
    parser.add_argument("--output", default=None, help="Output JSONL (default: auto)")
    parser.add_argument(
        "--nvd-fallback", action="store_true",
        help="Query NVD API for commits not found in kernel_cves.json"
    )
    parser.add_argument(
        "--nvd-limit", type=int, default=0,
        help="Max NVD queries (0 = all unmatched, default: 0)"
    )
    parser.add_argument(
        "--refresh-cache", action="store_true",
        help="Re-download kernel_cves.json even if cached"
    )
    args = parser.parse_args()

    if args.refresh_cache:
        download_kernel_cves(force=True)

    enrich_records(
        input_path=args.input,
        output_path=args.output,
        nvd_fallback=args.nvd_fallback,
        nvd_limit=args.nvd_limit,
    )


if __name__ == "__main__":
    main()

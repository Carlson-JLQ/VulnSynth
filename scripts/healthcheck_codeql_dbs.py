#!/usr/bin/env python3
"""
Lightweight CodeQL DB healthcheck.

Runs a minimal query against each existing database to verify the DB is usable.

This is intentionally conservative:
- Sequential by default (avoid overloading IO/CPU).
- Per-DB timeout.
- Writes a JSON summary for reproducibility.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class DbCheckResult:
    db_dir: str
    ok: bool
    rc: Any
    seconds: float
    output: Optional[str]
    stderr_tail: str


def _tail_lines(text: str, n: int = 12) -> str:
    lines = (text or "").splitlines()
    return "\n".join(lines[-n:])


def _default_codeql_path() -> str:
    # Keep consistent with other scripts in this repo.
    codeql_home = os.environ.get("CODEQL_HOME", "/opt/codeql_2.23.3")
    return os.environ.get("CODEQL_PATH", f"{codeql_home}/codeql")


def _collect_db_dirs(cves_root: Path) -> List[Path]:
    db_dirs: List[Path] = []
    for cve_dir in sorted(cves_root.glob("CVE-*")):
        if not cve_dir.is_dir():
            continue
        for suffix in ("-vul", "-fix"):
            db_dir = cve_dir / f"{cve_dir.name}{suffix}"
            if (db_dir / "db-java").exists():
                db_dirs.append(db_dir)
    return db_dirs


def _run_analyze(
    codeql: str,
    db_dir: Path,
    query: Path,
    out_sarif: Path,
    timeout_s: int,
    threads: int,
) -> DbCheckResult:
    cmd = [
        codeql,
        "database",
        "analyze",
        str(db_dir),
        str(query),
        "--rerun",
        "--format=sarifv2.1.0",
        "--output",
        str(out_sarif),
        "--threads",
        str(threads),
    ]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        ok = p.returncode == 0
        return DbCheckResult(
            db_dir=str(db_dir),
            ok=ok,
            rc=p.returncode,
            seconds=round(time.time() - t0, 2),
            output=str(out_sarif) if ok else None,
            stderr_tail=_tail_lines(p.stderr, 12),
        )
    except subprocess.TimeoutExpired:
        return DbCheckResult(
            db_dir=str(db_dir),
            ok=False,
            rc="timeout",
            seconds=round(time.time() - t0, 2),
            output=None,
            stderr_tail="timeout",
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--cves-root",
        default=str(Path(__file__).resolve().parents[1] / "cves"),
        help="Path to the cves/ directory.",
    )
    ap.add_argument(
        "--query",
        default=str(Path(__file__).resolve().parents[1] / "src" / "queries" / "db_healthcheck.ql"),
        help="Healthcheck query to run on each DB.",
    )
    ap.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parents[1] / "logs" / "db_healthcheck"),
        help="Directory to write SARIF and summary.json.",
    )
    ap.add_argument("--timeout", type=int, default=120, help="Per-DB timeout in seconds.")
    ap.add_argument("--threads", type=int, default=2, help="Threads passed to codeql analyze.")
    ap.add_argument("--limit", type=int, default=0, help="Only check the first N DBs (0 = all).")
    ap.add_argument(
        "--codeql",
        default=_default_codeql_path(),
        help="Path to the codeql CLI.",
    )
    args = ap.parse_args()

    cves_root = Path(args.cves_root)
    query = Path(args.query)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not cves_root.exists():
        raise SystemExit(f"cves root not found: {cves_root}")
    if not query.exists():
        raise SystemExit(f"query not found: {query}")
    if not Path(args.codeql).exists():
        raise SystemExit(f"codeql CLI not found: {args.codeql}")

    db_dirs = _collect_db_dirs(cves_root)
    if args.limit and args.limit > 0:
        db_dirs = db_dirs[: args.limit]

    print("codeql:", args.codeql)
    print("query:", str(query))
    print("db_dirs:", len(db_dirs))
    print("timeout_s:", args.timeout)

    results: List[Dict[str, Any]] = []
    start = time.time()

    for idx, db_dir in enumerate(db_dirs, 1):
        out_sarif = out_dir / f"{db_dir.name}.sarif"
        r = _run_analyze(args.codeql, db_dir, query, out_sarif, args.timeout, args.threads)
        results.append(r.__dict__)
        status = "OK" if r.ok else "FAIL"
        print(f"[{idx}/{len(db_dirs)}] {status} {db_dir} ({r.seconds}s)")
        if not r.ok and r.stderr_tail:
            print("  stderr_tail:", r.stderr_tail.replace("\t", " "))

    ok_cnt = sum(1 for r in results if r["ok"])
    fail_cnt = len(results) - ok_cnt
    elapsed = round(time.time() - start, 2)

    summary = {
        "codeql": args.codeql,
        "query": str(query),
        "db_count": len(results),
        "ok": ok_cnt,
        "fail": fail_cnt,
        "seconds": elapsed,
        "results": results,
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("wrote:", summary_path)
    return 0 if fail_cnt == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""CLI confcheck.

    python3 -m confcheck router.cfg
    python3 -m confcheck configs/*.cfg --out laporan --format md,json
    python3 -m confcheck router.cfg --only cisco.telnet,umum
    python3 -m confcheck --dir ~/configs --format json
    python3 -m confcheck --list
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import __version__, parser, report as report_mod
from .model import Report, Severity, Status
from .rules import load_all, select, describe

PATTERNS = ("*.cfg", "*.conf", "*.rsc", "*.txt")


def _split(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def audit_file(path: Path, only=None, skip=None) -> Report:
    load_all()                      # idempoten: importlib meng-cache modul aturan
    dev = parser.parse(path)
    rep = Report(device=dev, started=dt.datetime.now().isoformat(timespec="seconds"))
    if not dev.warnings:
        for cls in select(dev.platform, only, skip):
            try:
                rep.findings.extend(cls().run(dev) or [])
            except Exception as exc:                   # noqa: BLE001
                rep.errors.append(f"{cls.CODE}: {type(exc).__name__}: {exc}")
    else:
        rep.errors.extend(dev.warnings)
    rep.finished = dt.datetime.now().isoformat(timespec="seconds")
    return rep


def collect_files(args) -> list[Path]:
    files = [Path(f).expanduser() for f in (args.files or [])]
    if args.dir:
        d = Path(args.dir).expanduser()
        if not d.is_dir():
            print(f"folder tidak ada: {d}", file=sys.stderr)
            return []
        for pat in PATTERNS:
            files += sorted(d.rglob(pat))
    seen, out = set(), []
    for f in files:
        rp = str(f.resolve())
        if rp not in seen:
            seen.add(rp)
            out.append(f)
    return out


def cmd_list() -> int:
    load_all()
    rows = describe()
    print(f"{'KODE':<28}{'KATEGORI':<12}PEMERIKSAAN")
    for code, cat, title in rows:
        print(f"{code:<28}{cat:<12}{title}")
    print(f"\nTotal {len(rows)} aturan. Filter: --only/--skip (kode atau kategori).")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="confcheck",
        description="Audit konfigurasi perangkat jaringan (Cisco IOS / MikroTik RouterOS), read-only")
    ap.add_argument("files", nargs="*", help="berkas konfigurasi")
    ap.add_argument("--dir", help="pindai folder secara rekursif")
    ap.add_argument("--only", help="hanya kode/kategori ini (dipisah koma)")
    ap.add_argument("--skip", help="lewati kode/kategori ini")
    ap.add_argument("--format", help="text,md,json (default: text ke stdout)")
    ap.add_argument("--out", help="folder laporan")
    ap.add_argument("--json", action="store_true", help="cetak JSON ke stdout")
    ap.add_argument("--list", action="store_true", help="daftar aturan")
    ap.add_argument("--fail-under", type=int, help="exit ≠ 0 bila skor di bawah ini")
    ap.add_argument("--fail-on-critical", action="store_true",
                    help="exit ≠ 0 bila ada temuan CRITICAL yang FAIL")
    ap.add_argument("--version", action="version", version=f"confcheck {__version__}")
    args = ap.parse_args(argv)

    if args.list:
        return cmd_list()

    load_all()
    files = collect_files(args)
    if not files:
        print("tidak ada berkas konfigurasi. Contoh: confcheck router.cfg", file=sys.stderr)
        return 2

    only, skip = _split(args.only), _split(args.skip)
    reports = []
    for f in files:
        try:
            reports.append(audit_file(f, only, skip))
        except Exception as exc:                       # noqa: BLE001
            print(f"gagal memproses {f}: {type(exc).__name__}: {exc}", file=sys.stderr)

    if not reports:
        return 2

    single = len(reports) == 1
    if single and not args.out:
        print(report_mod.to_json(reports[0]) if args.json else report_mod.to_text(reports[0]))
    else:
        print(f"{'PERANGKAT':<24}{'PLATFORM':<20}{'SKOR':>6}  FAIL/WARN  SUMBER")
        for r in reports:
            nama = (r.device.hostname or Path(r.device.source).name)[:22]
            print(f"{nama:<24}{r.device.platform:<20}{r.score:>5}%  "
                  f"{r.count(Status.FAIL)}/{r.count(Status.WARN):<9} {r.device.source}")

    if args.out:
        formats = _split(args.format) or ["text", "md", "json"]
        for r in reports:
            for p in report_mod.write(Path(args.out).expanduser(), r, formats):
                print(f"  -> {p}")
        summary = Path(args.out).expanduser() / "ringkasan.json"
        summary.write_text(json.dumps(
            [{"source": r.device.source, "platform": r.device.platform,
              "hostname": r.device.hostname, "score": r.score,
              "fail": r.count(Status.FAIL), "warn": r.count(Status.WARN)}
             for r in reports], indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  -> {summary}")

    if args.fail_under is not None:
        worst = min(r.score for r in reports)
        if worst < args.fail_under:
            print(f"\nskor terendah {worst}% di bawah ambang {args.fail_under}%", file=sys.stderr)
            return 1
    if args.fail_on_critical:
        for r in reports:
            if any(f.status is Status.FAIL and f.severity is Severity.CRITICAL
                   for f in r.findings):
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

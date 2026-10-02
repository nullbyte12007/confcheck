"""Penyusun laporan confcheck: teks, Markdown, JSON."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .model import Report, Status


def to_text(r: Report) -> str:
    bar = "=" * 72
    L = [bar, f"  AUDIT KONFIGURASI — {r.device.hostname or '(tanpa hostname)'}", bar]
    L.append(f"platform : {r.device.platform}")
    L.append(f"sumber   : {r.device.source}")
    L.append(f"waktu    : {r.started} → {r.finished}")
    L.append(f"skor     : {r.score}%  ({r.count(Status.PASS)} lolos / {r.applicable} diperiksa)")
    L.append("")
    L.append(f"  ✅ PASS {r.count(Status.PASS):>3}   ❌ FAIL {r.count(Status.FAIL):>3}   "
             f"⚠️  WARN {r.count(Status.WARN):>3}   ➖ SKIP {r.count(Status.SKIP):>3}")
    L.append("")
    problems = r.by_severity()
    if problems:
        L.append("TEMUAN (urut prioritas)")
        L.append("-" * 72)
        for f in problems:
            L.append(f"{f.status.symbol} [{f.severity.value}] {f.code} — {f.title}")
            if f.detail:
                L.append(f"    kondisi   : {f.detail}")
            if f.remediation:
                L.append(f"    perbaikan : {f.remediation}")
            L.append("")
    else:
        L.append("Tidak ada temuan. 🎉")
        L.append("")
    L.append("HASIL LENGKAP")
    L.append("-" * 72)
    for f in sorted(r.findings, key=lambda x: (x.category, x.code)):
        L.append(f"{f.status.symbol} {f.code:<28} {f.title}")
    if r.errors:
        L.append("\nERROR\n" + "-" * 72)
        L.extend(f"  {e}" for e in r.errors)
    return "\n".join(L)


def to_markdown(r: Report) -> str:
    L = [f"# Audit Konfigurasi — `{r.device.hostname or r.device.source}`", ""]
    L.append(f"- **Platform**: {r.device.platform}")
    L.append(f"- **Sumber**: `{r.device.source}`")
    L.append(f"- **Skor**: **{r.score}%** ({r.count(Status.PASS)} lolos / {r.applicable} diperiksa)")
    L.append("")
    L.append("| PASS | FAIL | WARN | SKIP |")
    L.append("|---|---|---|---|")
    L.append(f"| {r.count(Status.PASS)} | {r.count(Status.FAIL)} | "
             f"{r.count(Status.WARN)} | {r.count(Status.SKIP)} |")
    L.append("")
    L.append("## Temuan")
    L.append("")
    probs = r.by_severity()
    if not probs:
        L.append("_Tidak ada. 🎉_")
    else:
        L.append("| Prioritas | Kode | Temuan | Kondisi | Perbaikan |")
        L.append("|---|---|---|---|---|")

        def esc(s: str) -> str:
            return s.replace("|", "\\|").replace("\n", " ")[:180]

        for f in probs:
            L.append(f"| {f.severity.value} | `{f.code}` | {f.title} | "
                     f"{esc(f.detail)} | {esc(f.remediation)} |")
    L.append("")
    L.append("## Hasil lengkap")
    L.append("")
    L.append("| Status | Kode | Kategori | Pemeriksaan |")
    L.append("|---|---|---|---|")
    for f in sorted(r.findings, key=lambda x: (x.category, x.code)):
        L.append(f"| {f.status.value} | `{f.code}` | {f.category} | {f.title} |")
    return "\n".join(L)


def to_json(r: Report) -> str:
    return json.dumps(r.as_dict(), indent=2, ensure_ascii=False)


def write(outdir: Path, r: Report, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"confcheck-{(r.device.hostname or 'perangkat')}-{stamp}"
    written: list[Path] = []
    for fmt, renderer, ext in (("text", to_text, "txt"), ("md", to_markdown, "md"),
                               ("json", to_json, "json")):
        if fmt in formats:
            p = outdir / f"{base}.{ext}"
            p.write_text(renderer(r), encoding="utf-8")
            written.append(p)
    return written

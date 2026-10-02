# confcheck

**Audit konfigurasi perangkat jaringan** — Cisco IOS & MikroTik RouterOS.
Satu perintah, temuan berprioritas, plus perintah perbaikannya.

Teman sekamar [hardening-audit](https://github.com/myusufcs/hardening-audit):
yang itu untuk server, yang ini untuk switch/router.

[![CI](https://github.com/myusufcs/confcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/myusufcs/confcheck/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero deps](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Rules](https://img.shields.io/badge/rules-19-informational)

---

## Kenapa ini ada

Konfigurasi perangkat jaringan biasanya diperiksa manual, satu per satu baris, dan cuma saat
ada audit. Akibatnya: telnet dibiarkan menyala, community SNMP masih `public`, atau
`transport input telnet` terlewat di satu baris `line vty`. `confcheck` mengubah itu jadi
pemeriksaan yang konsisten dan bisa dijalankan di CI sebelum konfigurasi naik ke produksi.

**Read-only** — hanya membaca berkas konfigurasi. Tdk pernah menyentuh perangkat.

## Keluaran contoh

```
$ python3 -m confcheck router-buruk.cfg
========================================================================
  AUDIT KONFIGURASI — ROUTER-BURUK
========================================================================
platform : cisco-ios
skor     : 0%  (0 lolos / 13 diperiksa)

  ✅ PASS   0   ❌ FAIL   4   ⚠️  WARN   9   ➖ SKIP   0

TEMUAN (urut prioritas)
------------------------------------------------------------------------
❌ [HIGH] cisco.enable_secret — Privileged EXEC memakai enable secret
    kondisi   : `enable password` dipakai tanpa `enable secret`
    perbaikan : Ganti ke `enable secret <kuat>` (hash) dan hapus `enable password`.

❌ [HIGH] cisco.telnet — Telnet dimatikan pada line vty
    kondisi   : line vty menerima Telnet — transport input: telnet
    perbaikan : Batasi ke SSH saja: `line vty 0 15` → `transport input ssh`.

❌ [HIGH] umum.snmp_default — Tidak memakai community SNMP default
    kondisi   : community default: public
    perbaikan : Ganti dengan string acak panjang + ACL sumber, atau pakai SNMPv3.
...
```

Beberapa berkas sekaligus → ringkasan per perangkat:

```
$ python3 -m confcheck --dir ~/configs --out laporan
PERANGKAT               PLATFORM              SKOR  FAIL/WARN  SUMBER
ROUTER-BAIK             cisco-ios             100%  0/0         ~/configs/cisco-good.cfg
MTK-BURUK               mikrotik-routeros       8%  5/7         ~/configs/routeros-bad.rsc
```

## Instalasi & pemakaian

Zero dependency — cukup standard library Python 3.10+.

```bash
git clone https://github.com/myusufcs/confcheck
cd confcheck

python3 -m confcheck router.cfg                                   # satu perangkat
python3 -m confcheck --dir ~/configs --out laporan --format md,json
python3 -m confcheck sw.cfg --only cisco.telnet,umum.snmp_default  # aturan tertentu
python3 -m confcheck sw.cfg --skip umum.banner
python3 -m confcheck --list                                        # daftar aturan
```

Hasil ditulis ke `--out` dalam **teks + Markdown + JSON**, plus `ringkasan.json` bila
memeriksa banyak berkas.

## Aturan (19)

| Kategori | Kode | Yang diperiksa |
|---|---|---|
| **cisco** | `cisco.telnet` | line vty hanya menerima SSH |
| | `cisco.password_encryption` | `service password-encryption` aktif |
| | `cisco.enable_secret` | Pakai `enable secret`, bukan `enable password` |
| | `cisco.http_server` | `ip http server` (tanpa TLS) mati |
| | `cisco.aaa` | `aaa new-model` aktif |
| | `cisco.exec_timeout` | `exec-timeout` bukan `0 0` |
| | `cisco.unused_interfaces` | Port tak terpakai di-`shutdown` |
| | `cisco.cdp` | CDP tidak bocorkan info di tepi |
| **mikrotik** | `mikrotik.services` | telnet/ftp/www/api dimatikan |
| | `mikrotik.snmp_default` | Community SNMP bukan default |
| | `mikrotik.firewall` | Ada aturan `action=drop` di chain input/forward |
| | `mikrotik.mac_server` | Winbox-via-MAC dimatikan |
| | `mikrotik.bandwidth_server` | Bandwidth server mati |
| | `mikrotik.ntp` | Klien NTP aktif |
| | `mikrotik.logging` | Log dikirim ke syslog terpusat |
| | `mikrotik.discovery` | MNDP/LLDP tidak aktif di interface luar |
| **umum** | `umum.snmp_default` | Tidak ada community default (public/private/cisco) |
| | `umum.snmp_version` | SNMPv3 bila tersedia |
| | `umum.ntp` | Waktu tersinkron |
| | `umum.logging` | Logging remote terkonfigurasi |
| | `umum.banner` | Banner peringatan akses ada (Cisco) |

## Dipakai di CI

Audit konfigurasi sebelum di-commit ke repo Git — mencegah setelan tidak aman lolos ke produksi:

```yaml
- name: Audit konfigurasi jaringan
  run: |
    python3 -m confcheck --dir configs --out reports --format md,json \
      --fail-under 80 --fail-on-critical
```

`--fail-under N` menggagalkan pipeline bila skor turun di bawah N.
`--fail-on-critical` hanya menggagalkan bila ada temuan CRITICAL.

## Desain

```
confcheck/
  cli.py        # argparse: berkas/--dir, filter, format, ambang kegagalan
  parser.py     # deteksi platform + parsing → "facts" ternormalisasi
  model.py      # Device, Finding, Report (skor & prioritas)
  report.py     # render teks / Markdown / JSON
  rules/
    __init__.py # registry: aturan auto-register lewat subclass
    cisco.py    # aturan Cisco IOS
    mikrotik.py # aturan RouterOS
    common.py   # aturan lintas platform
```

Parser mengubah sintaks vendor menjadi fakta ternormalisasi (`telnet_input`, `snmp_communities`,
`firewall_input_drop`, …), sehingga satu aturan bisa dipakai lintas vendor tanpa tahu
perbedaan sintaks.

Cara parser Cisco bekerja: mengikuti aturan **indentasi** seperti output `show running-config` —
baris menjorok adalah atribut dari blok `interface` / `line vty` terakhir.

Menambah aturan baru = subclass `Rule`:

```python
from ..model import Finding, Severity, Status
from . import Rule

class SshVersion(Rule):
    CODE = "cisco.ssh_version"
    TITLE = "SSH memakai versi 2"
    CATEGORY = "cisco"
    PLATFORMS = {"cisco-ios"}

    def run(self, dev):
        v = dev.fact("ssh_version")
        ok = str(v).startswith("2")
        return [Finding(self.CODE, self.TITLE,
                        Status.PASS if ok else Status.WARN, Severity.MEDIUM,
                        f"ip ssh version {v}", "Set `ip ssh version 2`.", self.CATEGORY)]
```

## Batasan yang jujur

- **Bukan pengganti review manual.** Ini memeriksa pola yang bisa dikenali dari berkas
  konfigurasi; salah paham konteks bisnis tetap mungkin.
- **Parser berbasis teks, bukan emulator.** Konfigurasi yang tidak lazim (tanpa indentasi,
  hasil `show run all`, template Jinja) bisa terbaca salah — parser menandai platform
  "unknown" dan melewati aturan alih-alih menebak.
- Aturan MikroTik memakai sintaks **hasil ekspor** (`/ip service`, `/snmp community`, …),
  bukan format perintah interaktif.
- Beberapa aturan bergantung kebijakan (CDP, banner, exec-timeout). Perlakukan temuan sebagai
  bahan pertimbangan.
- Tidak memeriksa isi password yang di-hash, dan tidak melakukan koneksi ke perangkat.

## Uji

```bash
python3 -m unittest discover -s tests -v     # 25 test
```

Fixture mencakup konfigurasi Cisco **baik & buruk**, RouterOS **baik & buruk** — memastikan
aturan benar-benar membedakan, bukan cuma "selalu lolos" atau "selalu gagal".

## Lisensi

MIT — lihat [LICENSE](LICENSE). Copyright (c) 2026 M Yusuf Chairul Saleh.

"""Aturan yang berlaku di kedua platform (membaca fakta ternormalisasi)."""
from __future__ import annotations

from ..model import Finding, Severity, Status
from . import Rule

CAT = "umum"
DEFAULT_COMMUNITIES = {"public", "private", "cisco", "admin"}


class SnmpDefaultCommunity(Rule):
    CODE = "umum.snmp_default"
    TITLE = "Tidak memakai community SNMP default"
    CATEGORY = CAT

    def run(self, dev):
        comms = dev.fact("snmp_communities") or []
        if not comms:
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "SNMP tidak dikonfigurasi", category=CAT)]
        bad = [c["name"] for c in comms if c["name"].lower() in DEFAULT_COMMUNITIES]
        if bad:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"community default: {', '.join(bad)}",
                            "Ganti dengan string acak panjang + ACL sumber, atau pakai SNMPv3 "
                            "(authPriv). Community default bisa ditebak siapa pun.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{len(comms)} community, tidak ada yang default", category=CAT)]


class SnmpVersion(Rule):
    CODE = "umum.snmp_version"
    TITLE = "SNMP memakai v3 bila tersedia"
    CATEGORY = CAT

    def run(self, dev):
        comms = dev.fact("snmp_communities") or []
        if not comms:
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "SNMP tidak dikonfigurasi", category=CAT)]
        if dev.fact("snmp_v3"):
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "SNMPv3 terkonfigurasi", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                        "hanya SNMPv1/v2c (community dikirim tanpa enkripsi)",
                        "Pindah ke SNMPv3 dengan authPriv.",
                        CAT)]


class NtpConfigured(Rule):
    CODE = "umum.ntp"
    TITLE = "Waktu tersinkron (NTP)"
    CATEGORY = CAT

    def run(self, dev):
        if dev.platform == "mikrotik-routeros":
            ok = bool(dev.fact("ntp_enabled"))
            detail = "NTP aktif" if ok else "NTP tidak aktif"
        else:
            servers = dev.fact("ntp_servers") or []
            ok = bool(servers)
            detail = (f"{len(servers)} server NTP: {', '.join(servers[:3])}"
                      if ok else "tidak ada server NTP")
        if ok:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            detail, category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM, detail,
                        "Sinkronkan waktu (NTP). Timestamp log yang salah menghancurkan "
                        "kemampuan korelasi saat insiden.",
                        CAT)]


class RemoteLogging(Rule):
    CODE = "umum.logging"
    TITLE = "Log dikirim ke syslog terpusat"
    CATEGORY = CAT

    def run(self, dev):
        hosts = dev.fact("logging_hosts") or dev.fact("logging_remote") or []
        if hosts:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            f"{len(hosts)} tujuan logging remote", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                        "tidak ada logging remote",
                        "Kirim log ke syslog server. Log yang hanya tersimpan di perangkat "
                        "hilang saat perangkat direset/dicuri.",
                        CAT)]


class BannerWarning(Rule):
    CODE = "umum.banner"
    TITLE = "Banner peringatan akses tersedia"
    CATEGORY = CAT
    PLATFORMS = {"cisco-ios"}

    def run(self, dev):
        if dev.fact("banner_login"):
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "banner terpasang", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.INFO,
                        "tidak ada banner login/MOTD",
                        "Pasang banner peringatan akses tanpa otorisasi — penting untuk "
                        "aspek legal bila ada akses tak sah.",
                        CAT)]

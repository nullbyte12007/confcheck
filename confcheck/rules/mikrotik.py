"""Aturan khusus MikroTik RouterOS."""
from __future__ import annotations

from ..model import Finding, Severity, Status
from . import Rule

PLAT = {"mikrotik-routeros"}
CAT = "mikrotik"
PLAINTEXT_SERVICES = {"telnet": Severity.HIGH, "ftp": Severity.MEDIUM,
                      "www": Severity.MEDIUM, "api": Severity.HIGH}


class InsecureServices(Rule):
    CODE = "mikrotik.services"
    TITLE = "Layanan tanpa enkripsi dimatikan (telnet/ftp/www/api)"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        out = []
        services = dev.fact("services") or {}
        # name -> Severity (bukan nilai boolean dari parser!)
        aktif = {k: PLAINTEXT_SERVICES[k] for k, v in services.items()
                 if v and k in PLAINTEXT_SERVICES}
        for name, sev in aktif.items():
            out.append(Finding(f"{self.CODE}:{name}", f"Layanan {name} aktif",
                               Status.FAIL, sev, f"`/ip service` {name} belum disabled",
                               f"Matikan: `/ip service disable {name}`. "
                               "Gunakan ssh / www-ssl / api-ssl.",
                               CAT))
        if not aktif:
            out.append(Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                               "tidak ada layanan plaintext yang aktif", category=CAT))
        return out


class SnmpDefault(Rule):
    CODE = "mikrotik.snmp_default"
    TITLE = "Community SNMP bukan nilai default"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        return _snmp_check(self, dev, CAT)


class FirewallInput(Rule):
    CODE = "mikrotik.firewall"
    TITLE = "Firewall filter punya aturan drop di chain input"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        n = dev.fact("firewall_filter_rules") or 0
        if n == 0:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            "tidak ada aturan `/ip firewall filter` sama sekali",
                            "Pasang aturan dasar: izinkan established/related, drop invalid, "
                            "batasi input dari LAN, lalu drop sisanya.",
                            CAT)]
        if not dev.fact("firewall_input_drop"):
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"{n} aturan filter tapi tidak ada `action=drop` di chain input/forward",
                            "Tambahkan aturan drop terakhir di chain input dan forward.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{n} aturan filter, ada drop di input/forward", category=CAT)]


class MacServer(Rule):
    CODE = "mikrotik.mac_server"
    TITLE = "MAC server (winbox via MAC) dimatikan"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        mac = dev.fact("mac_server") or {}
        if not mac.get("disabled"):
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            "MAC server masih aktif — Winbox bisa dijangkau lewat MAC "
                            "tanpa IP/routing",
                            "Matikan: `/tool mac-server set allowed-interface-list=none` "
                            "(dan mac-server winbox).",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "dimatikan", category=CAT)]


class BandwidthServer(Rule):
    CODE = "mikrotik.bandwidth_server"
    TITLE = "Bandwidth server dimatikan"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("bandwidth_server"):
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            "bandwidth-server aktif",
                            "Matikan bila tidak dipakai: `/tool bandwidth-server set enabled=no`.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "tidak aktif", category=CAT)]


class NtpClient(Rule):
    CODE = "mikrotik.ntp"
    TITLE = "Klien NTP aktif (waktu akurat untuk log)"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("ntp_enabled"):
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "NTP aktif", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                        "klien NTP tidak aktif",
                        "Aktifkan `/system ntp client set enabled=yes` — log dengan waktu salah "
                        "tidak berguna saat investigasi.",
                        CAT)]


class RemoteLogging(Rule):
    CODE = "mikrotik.logging"
    TITLE = "Log dikirim ke server terpusat"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("logging_remote"):
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            f"{len(dev.fact('logging_remote'))} aturan logging remote",
                            category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                        "tidak ada logging remote (log hanya lokal)",
                        "Kirim log ke syslog terpusat: `/system logging add action=remote`. "
                        "Kalau perangkat hilang/di-reset, log lokal ikut lenyap.",
                        CAT)]


class NeighborDiscovery(Rule):
    CODE = "mikrotik.discovery"
    TITLE = "Neighbor discovery tidak aktif di interface luar"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("discovery_enabled"):
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            "MNDP/LLDP aktif secara global",
                            "Nonaktifkan di interface menghadap ISP: "
                            "`/ip neighbor discovery-settings set discover-interface-list=none`.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "dimatikan", category=CAT)]


def _snmp_check(rule, dev, cat):
    comms = dev.fact("snmp_communities") or []
    default = [c["name"] for c in comms if c["name"].lower() in {"public", "private", "cisco"}]
    if default:
        return [Finding(rule.CODE, rule.TITLE, Status.FAIL, Severity.HIGH,
                        f"community default ditemukan: {', '.join(default)}",
                        "Ganti community dengan string acak panjang, batasi akses per "
                        "interface/address-list, atau pindah ke SNMPv3.",
                        cat)]
    return [Finding(rule.CODE, rule.TITLE, Status.PASS, Severity.INFO,
                    f"{len(comms)} community, tidak ada yang default", category=cat)]

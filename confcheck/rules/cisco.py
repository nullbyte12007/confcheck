"""Aturan khusus Cisco IOS."""
from __future__ import annotations

from ..model import Finding, Severity, Status
from . import Rule

PLAT = {"cisco-ios"}
CAT = "cisco"


class TelnetDisabled(Rule):
    CODE = "cisco.telnet"
    TITLE = "Telnet dimatikan pada line vty"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("telnet_input"):
            tr = ", ".join(dev.fact("vty_transport") or ["(default)"])
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"line vty menerima Telnet — transport input: {tr}",
                            "Batasi ke SSH saja: `line vty 0 15` → `transport input ssh`.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "hanya SSH", category=CAT)]


class PasswordEncryption(Rule):
    CODE = "cisco.password_encryption"
    TITLE = "Password tersimpan terenkripsi"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("password_encryption"):
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "service password-encryption aktif", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                        "service password-encryption tidak aktif — password terlihat plaintext "
                        "di running-config",
                        "Aktifkan `service password-encryption`. Catatan: ini hanya obfuscation, "
                        "tetap pakai `enable secret` untuk hashing kuat.",
                        CAT)]


class EnableSecret(Rule):
    CODE = "cisco.enable_secret"
    TITLE = "Privileged EXEC memakai enable secret"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("enable_password") and not dev.fact("enable_secret"):
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            "`enable password` dipakai tanpa `enable secret`",
                            "Ganti ke `enable secret <kuat>` (hash) dan hapus `enable password`.",
                            CAT)]
        if not dev.fact("enable_secret"):
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "tidak ada enable secret di konfigurasi ini", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "enable secret dipakai", category=CAT)]


class HttpServer(Rule):
    CODE = "cisco.http_server"
    TITLE = "Server HTTP tidak aktif"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("http_server"):
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            "`ip http server` aktif — antarmuka web tanpa TLS",
                            "Matikan bila tidak dipakai: `no ip http server`. "
                            "Bila perlu, pakai `ip http secure-server` + ACL.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "tidak aktif", category=CAT)]


class AaaNewModel(Rule):
    CODE = "cisco.aaa"
    TITLE = "AAA diaktifkan"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("aaa_new_model"):
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "aaa new-model aktif", category=CAT)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                        "aaa new-model tidak aktif — autentikasi hanya lokal",
                        "Aktifkan `aaa new-model` dan arahkan ke RADIUS/TACACS+ agar jejak "
                        "login terpusat.",
                        CAT)]


class ExecTimeout(Rule):
    CODE = "cisco.exec_timeout"
    TITLE = "Timeout sesi diatur (bukan 0 0)"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        val = dev.fact("exec_timeout")
        if val is None:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            "exec-timeout tidak diatur eksplisit (default 10 menit di vty)",
                            "Set eksplisit, mis. `line vty 0 15` → `exec-timeout 5 0`.",
                            CAT)]
        if val.strip().startswith("0 0") or val.strip() == "0":
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.MEDIUM,
                            f"exec-timeout {val} — sesi tidak pernah timeout",
                            "Set `exec-timeout 5 0` (atau sesuai kebijakan).",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"exec-timeout {val}", category=CAT)]


class UnusedInterfaces(Rule):
    CODE = "cisco.unused_interfaces"
    TITLE = "Port tidak terpakai di-shutdown"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        idle = [i["name"] for i in dev.interfaces
                if not i["shutdown"] and not i["ip"] and not i["description"]]
        if idle:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            f"{len(idle)} interface aktif tanpa IP/deskripsi: "
                            f"{', '.join(idle[:6])}",
                            "Shutdown port yang tidak dipakai dan beri deskripsi pada yang dipakai "
                            "— mencegah akses fisik tak terduga.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{len(dev.interfaces)} interface diperiksa", category=CAT)]


class CdpEnabled(Rule):
    CODE = "cisco.cdp"
    TITLE = "CDP tidak membocorkan info di tepi jaringan"
    CATEGORY = CAT
    PLATFORMS = PLAT

    def run(self, dev):
        if dev.fact("cdp_enabled"):
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            "CDP aktif secara global",
                            "Di interface menghadap luar, matikan: `no cdp enable`. "
                            "Informasi model/versi IOS bisa dipanen dari CDP.",
                            CAT)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "CDP dimatikan", category=CAT)]

"""Deteksi platform + parser konfigurasi (Cisco IOS & MikroTik RouterOS).

Parser menghasilkan 'facts' ternormalisasi supaya aturan (rules) tidak perlu tahu
sintaks vendor.
"""
from __future__ import annotations

import re
from pathlib import Path

from .model import Device

CISCO_MARKERS = ("service password-encryption", "interface GigabitEthernet",
                 "line vty", "ip http server", "enable secret", "hostname ")
ROUTEROS_MARKERS = ("/interface", "/ip service", "/system identity", "/snmp",
                    "/ip firewall", "/user ")


def detect_platform(text: str) -> str:
    low = text.lower()
    cisco = sum(1 for m in CISCO_MARKERS if m.lower() in low)
    routeros = sum(1 for m in ROUTEROS_MARKERS if m.lower() in low)
    if routeros > cisco:
        return "mikrotik-routeros"
    if cisco:
        return "cisco-ios"
    return "unknown"


def parse(path: str | Path) -> Device:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"berkas konfigurasi tidak ada: {p}")
    raw = p.read_text(errors="replace")
    lines = [ln.rstrip() for ln in raw.splitlines()]
    dev = Device(platform=detect_platform(raw), source=str(p), raw=raw, lines=lines)
    if dev.platform == "cisco-ios":
        _parse_cisco(dev)
    elif dev.platform == "mikrotik-routeros":
        _parse_routeros(dev)
    else:
        dev.warnings.append("platform tidak dikenali — aturan umum dilewati")
        dev.hostname = _guess_hostname(lines)
    return dev


def _guess_hostname(lines: list[str]) -> str:
    for ln in lines:
        s = ln.strip()
        if s.lower().startswith("hostname "):
            return s.split(None, 1)[1].strip()
        if "name=" in s and s.startswith("/system identity"):
            return s.split("name=", 1)[1].strip().strip('"')
    return ""


# ------------------------------------------------------------------ Cisco IOS

def _parse_cisco(dev: Device) -> None:
    """Parser Cisco IOS.

    Memakai aturan indentasi seperti output `show running-config`: baris yang
    menjorok ke dalam adalah atribut dari blok terakhir (`interface` / `line vty`).
    """
    f = dev.facts
    f.update({
        "telnet_input": False, "ssh_input": False, "http_server": False,
        "https_server": False, "password_encryption": False,
        "enable_secret": False, "enable_password": False,
        "snmp_communities": [], "snmp_v3": False,
        "logging_hosts": [], "ntp_servers": [], "aaa_new_model": False,
        "banner_login": False, "exec_timeout": None, "console_password": False,
        "cdp_enabled": True, "vty_transport": [],
    })

    section = None           # None | "interface" | "vty" | "console"
    iface = None
    rx_iface = re.compile(r"^interface\s+(\S+)", re.I)
    rx_line = re.compile(r"^line\s+(vty|con\w*)", re.I)

    for raw in dev.lines:
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("!") or s.startswith("#"):
            continue
        indented = line[:1].isspace()

        # ---------- atribut dari blok aktif ----------
        if indented and section:
            low = s.lower()
            if section == "interface" and iface is not None:
                if low == "shutdown":
                    iface["shutdown"] = True
                elif low.startswith("no shutdown"):
                    iface["shutdown"] = False
                elif low.startswith("ip address "):
                    parts = s.split()
                    iface["ip"] = " ".join(parts[2:4]) if len(parts) >= 4 else parts[2]
                elif low.startswith("switchport"):
                    iface["switchport"] = True
                elif low.startswith("description "):
                    iface["description"] = s.split(None, 1)[1].strip()
            elif section in ("vty", "console"):
                if low.startswith("transport input"):
                    tr = s.split(None, 2)[2].lower() if len(s.split()) > 2 else ""
                    f["vty_transport"].append(tr)
                    if "telnet" in tr or tr == "all":
                        f["telnet_input"] = True
                    if "ssh" in tr:
                        f["ssh_input"] = True
                elif low.startswith("exec-timeout"):
                    f["exec_timeout"] = s.split(None, 1)[1].strip()
                elif low.startswith("password ") and section == "console":
                    f["console_password"] = True
                elif low.startswith("no login"):
                    f["_vty_no_login"] = True
            continue

        # ---------- baris tingkat atas ----------
        low = s.lower()
        m = rx_iface.match(s)
        if m:
            iface = {"name": m.group(1), "shutdown": False, "ip": None,
                     "switchport": False, "description": ""}
            dev.interfaces.append(iface)
            section = "interface"
            continue
        m = rx_line.match(s)
        if m:
            section = "vty" if m.group(1).lower() == "vty" else "console"
            iface = None
            continue

        section = None
        iface = None

        if low.startswith("hostname "):
            dev.hostname = s.split(None, 1)[1].strip()
        elif low.startswith("service password-encryption"):
            f["password_encryption"] = True
        elif low.startswith("enable secret"):
            f["enable_secret"] = True
        elif low.startswith("enable password"):
            f["enable_password"] = True
        elif low.startswith("no ip http server"):
            f["http_server"] = False
        elif low.startswith("ip http server"):
            f["http_server"] = True
        elif low.startswith("no ip http secure-server"):
            f["https_server"] = False
        elif low.startswith("ip http secure-server"):
            f["https_server"] = True
        elif low.startswith("snmp-server community"):
            parts = s.split()
            if len(parts) >= 3:
                f["snmp_communities"].append({
                    "name": parts[2],
                    "access": parts[3] if len(parts) > 3 and not parts[3].isdigit() else "RO"})
        elif low.startswith(("snmp-server user", "snmp-server group")):
            f["snmp_v3"] = True
        elif low.startswith("logging host"):
            parts = s.split()
            if len(parts) >= 3:
                f["logging_hosts"].append(parts[2])
        elif low.startswith(("ntp server", "ntp peer")):
            parts = s.split()
            if len(parts) >= 3:
                f["ntp_servers"].append(parts[2])
        elif low.startswith("aaa new-model"):
            f["aaa_new_model"] = True
        elif low.startswith(("banner login", "banner motd")):
            f["banner_login"] = True
        elif low.startswith("no cdp run"):
            f["cdp_enabled"] = False

    if not f["vty_transport"]:
        # tanpa pernyataan transport input, Cisco mengizinkan telnet secara default
        f["telnet_input"] = True


# ------------------------------------------------------------------ MikroTik

def _parse_routeros(dev: Device) -> None:
    f = dev.facts
    f.update({
        "services": {}, "snmp_communities": [], "ntp_enabled": False,
        "logging_remote": [], "users": [], "mac_server": {}, "bandwidth_server": False,
        "firewall_filter_rules": 0, "firewall_input_drop": False,
        "discovery_enabled": None, "romon": False,
    })
    section = ""
    for ln in dev.lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("/"):
            section = s.lower()
            continue
        low = s.lower()

        if section.startswith("/system identity") and "name=" in low:
            dev.hostname = s.split("name=", 1)[1].strip().strip('"')
        elif section.startswith("/ip service"):
            # dua bentuk: `set telnet disabled=no`  atau  `add name=telnet disabled=no`
            toks = low.split()
            name = None
            if toks and toks[0] == "set" and len(toks) > 1:
                name = toks[1]
            elif toks and toks[0] == "add":
                m = re.search(r"(?:name|service)=(\S+)", low)
                if m:
                    name = m.group(1).strip('"')
            if name:
                f["services"][name] = "disabled=yes" not in low
        elif section.startswith("/snmp"):
            # bentuk ekspor: `/snmp community` lalu `add name=public`
            if "name=" in low:
                m = re.search(r"name=(\S+)", low)
                if m:
                    f["snmp_communities"].append({"name": m.group(1).strip('"'),
                                                  "access": "read-only"})
        elif section.startswith("/system ntp"):
            if "enabled=yes" in low:
                f["ntp_enabled"] = True
        elif section.startswith("/system logging"):
            if ("action=" in low and "remote" in low) or "remote=" in low:
                f["logging_remote"].append(s)
        elif section.startswith("/user"):
            m = re.search(r"add\s+name=(\S+)", low)
            if m:
                f["users"].append(m.group(1).strip('"'))
        elif section.startswith("/ip firewall filter"):
            if low.startswith("add"):
                f["firewall_filter_rules"] += 1
                if "action=drop" in low and ("chain=input" in low or "chain=forward" in low):
                    f["firewall_input_drop"] = True
        elif section.startswith("/tool mac-server"):
            # RouterOS menonaktifkan via allowed-interface-list=none, bukan disabled=yes
            if "disabled=yes" in low or "allowed-interface-list=none" in low:
                f["mac_server"]["disabled"] = True
        elif section.startswith("/tool bandwidth-server"):
            if "enabled=yes" in low:
                f["bandwidth_server"] = True
        elif section.startswith("/ip neighbor discovery") or section.startswith("/tool discovery"):
            f["discovery_enabled"] = "disabled=yes" not in low
        elif section.startswith("/tool romon"):
            if "enabled=yes" in low:
                f["romon"] = True

    f.pop("_current_line", None)

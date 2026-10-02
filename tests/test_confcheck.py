"""Uji confcheck: deteksi platform, parser, aturan, laporan, dan CLI."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from confcheck import cli, parser, report as report_mod          # noqa: E402
from confcheck.model import Status                                # noqa: E402
from confcheck.rules import load_all, select, describe, ALL_RULES  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def statuses(rep):
    return {f.code: f.status for f in rep.findings}


class TestParse(unittest.TestCase):
    def test_deteksi_platform(self):
        self.assertEqual(parser.parse(FIX / "cisco-good.cfg").platform, "cisco-ios")
        self.assertEqual(parser.parse(FIX / "cisco-bad.cfg").platform, "cisco-ios")
        self.assertEqual(parser.parse(FIX / "routeros-good.rsc").platform,
                         "mikrotik-routeros")
        self.assertEqual(parser.parse(FIX / "routeros-bad.rsc").platform,
                         "mikrotik-routeros")

    def test_cisco_good_facts(self):
        d = parser.parse(FIX / "cisco-good.cfg")
        self.assertEqual(d.hostname, "ROUTER-BAIK")
        self.assertFalse(d.fact("telnet_input"))
        self.assertTrue(d.fact("ssh_input"))
        self.assertTrue(d.fact("password_encryption"))
        self.assertTrue(d.fact("enable_secret"))
        self.assertFalse(d.fact("enable_password"))
        self.assertFalse(d.fact("http_server"))
        self.assertTrue(d.fact("snmp_v3"))
        self.assertEqual(d.fact("ntp_servers"), ["10.10.0.6", "10.10.0.7"])
        self.assertEqual(d.fact("logging_hosts"), ["10.10.0.5"])
        self.assertFalse(d.fact("cdp_enabled"))
        self.assertEqual(d.fact("exec_timeout"), "5 0")
        self.assertEqual(len(d.interfaces), 3)
        self.assertTrue(d.interfaces[2]["shutdown"])
        self.assertEqual(d.interfaces[0]["description"], "UPLINK-ISP")

    def test_cisco_bad_facts(self):
        d = parser.parse(FIX / "cisco-bad.cfg")
        self.assertTrue(d.fact("telnet_input"))
        self.assertFalse(d.fact("password_encryption"))
        self.assertTrue(d.fact("enable_password"))
        self.assertFalse(d.fact("enable_secret"))
        self.assertTrue(d.fact("http_server"))
        self.assertEqual(d.fact("snmp_communities")[0]["name"], "public")
        self.assertEqual(d.fact("exec_timeout"), "0 0")
        # interface tanpa shutdown dianggap belum diamankan
        self.assertFalse(any(i["shutdown"] for i in d.interfaces))

    def test_routeros_good_facts(self):
        d = parser.parse(FIX / "routeros-good.rsc")
        self.assertEqual(d.hostname, "MTK-BAIK")
        svc = d.fact("services")
        self.assertFalse(svc["telnet"])
        self.assertFalse(svc["api"])
        self.assertTrue(svc["ssh"])
        self.assertTrue(d.fact("firewall_input_drop"))
        self.assertTrue(d.fact("ntp_enabled"))
        self.assertTrue(d.fact("logging_remote"))
        self.assertFalse(d.fact("bandwidth_server"))
        self.assertTrue(d.fact("mac_server").get("disabled"))

    def test_routeros_bad_facts(self):
        d = parser.parse(FIX / "routeros-bad.rsc")
        svc = d.fact("services")
        self.assertTrue(svc["telnet"])
        self.assertTrue(svc["api"])
        self.assertFalse(d.fact("firewall_input_drop"))
        self.assertFalse(d.fact("ntp_enabled"))
        self.assertTrue(d.fact("bandwidth_server"))

    def test_berkas_tidak_ada(self):
        with self.assertRaises(FileNotFoundError):
            parser.parse(FIX / "tidak-ada.cfg")


class TestRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_all()

    def test_kode_unik(self):
        codes = [c.CODE for c in ALL_RULES]
        self.assertEqual(len(codes), len(set(codes)), "kode aturan duplikat")

    def test_filter_platform(self):
        cisco = select("cisco-ios", None, None)
        self.assertTrue(cisco)
        self.assertTrue(all("cisco-ios" in c.PLATFORMS for c in cisco))
        self.assertNotIn("mikrotik.services", [c.CODE for c in cisco])

    def test_only_dan_skip(self):
        satu = [c for c in select("cisco-ios", None, None)
                if c.CODE == "cisco.telnet"]
        self.assertEqual(len(satu), 1)
        self.assertEqual(select("cisco-ios", ["cisco.telnet"], None)[0].CODE, "cisco.telnet")
        self.assertEqual(select("cisco-ios", None, ["cisco"]), 
                         [c for c in select("cisco-ios", None, None) if c.CATEGORY != "cisco"])

    def test_cisco_bad_memicu_temuan(self):
        rep = cli.audit_file(FIX / "cisco-bad.cfg")
        st = statuses(rep)
        self.assertIs(st.get("cisco.telnet"), Status.FAIL)
        self.assertIs(st.get("cisco.enable_secret"), Status.FAIL)
        self.assertIs(st.get("cisco.http_server"), Status.WARN)
        self.assertIs(st.get("umum.snmp_default"), Status.FAIL)
        self.assertIs(st.get("cisco.password_encryption"), Status.WARN)
        self.assertGreater(rep.count(Status.FAIL), 3)
        self.assertLess(rep.score, 60)

    def test_cisco_good_lolos(self):
        rep = cli.audit_file(FIX / "cisco-good.cfg")
        st = statuses(rep)
        self.assertIs(st.get("cisco.telnet"), Status.PASS)
        self.assertIs(st.get("cisco.http_server"), Status.PASS)
        self.assertIs(st.get("umum.snmp_default"), Status.PASS)
        self.assertIs(st.get("umum.ntp"), Status.PASS)
        self.assertIs(st.get("umum.logging"), Status.PASS)
        self.assertEqual(rep.count(Status.FAIL), 0)

    def test_routeros_bad_memicu_temuan(self):
        rep = cli.audit_file(FIX / "routeros-bad.rsc")
        st = statuses(rep)
        self.assertIs(st.get("mikrotik.services:telnet"), Status.FAIL)
        self.assertIs(st.get("mikrotik.services:api"), Status.FAIL)
        self.assertIs(st.get("mikrotik.firewall"), Status.FAIL)
        self.assertIs(st.get("mikrotik.snmp_default"), Status.FAIL)
        self.assertIs(st.get("umum.ntp"), Status.WARN)
        self.assertGreater(rep.count(Status.FAIL), 4)

    def test_routeros_good_lolos(self):
        rep = cli.audit_file(FIX / "routeros-good.rsc")
        st = statuses(rep)
        self.assertIs(st.get("mikrotik.services"), Status.PASS)
        self.assertIs(st.get("mikrotik.firewall"), Status.PASS)
        self.assertIs(st.get("mikrotik.snmp_default"), Status.PASS)
        self.assertIs(st.get("umum.ntp"), Status.PASS)
        self.assertEqual(rep.count(Status.FAIL), 0)

    def test_skor_lebih_baik_pada_config_baik(self):
        baik = cli.audit_file(FIX / "cisco-good.cfg").score
        buruk = cli.audit_file(FIX / "cisco-bad.cfg").score
        self.assertGreater(baik, buruk)


class TestReport(unittest.TestCase):
    def _rep(self):
        return cli.audit_file(FIX / "cisco-bad.cfg")

    def test_text_memuat_temuan(self):
        t = report_mod.to_text(self._rep())
        self.assertIn("AUDIT KONFIGURASI", t)
        self.assertIn("cisco.telnet", t)

    def test_markdown_tabel(self):
        md = report_mod.to_markdown(self._rep())
        self.assertIn("| Prioritas |", md)

    def test_json_valid(self):
        d = json.loads(report_mod.to_json(self._rep()))
        self.assertEqual(d["device"]["platform"], "cisco-ios")
        self.assertIn("score", d)

    def test_write_semua_format(self):
        with tempfile.TemporaryDirectory() as td:
            files = report_mod.write(Path(td), self._rep(), ["text", "md", "json"])
            self.assertEqual(len(files), 3)
            for f in files:
                self.assertTrue(f.is_file() and f.stat().st_size > 0)


class TestCli(unittest.TestCase):
    def test_single_file_ke_stdout(self):
        code = cli.main([str(FIX / "cisco-bad.cfg")])
        self.assertEqual(code, 0)

    def test_out_folder_lengkap(self):
        with tempfile.TemporaryDirectory() as td:
            code = cli.main([str(FIX / "cisco-good.cfg"), str(FIX / "routeros-bad.rsc"),
                             "--out", td])
            self.assertEqual(code, 0)
            files = list(Path(td).iterdir())
            self.assertGreaterEqual(len(files), 6)          # 3 format x 2 perangkat
            summary = json.loads((Path(td) / "ringkasan.json").read_text())
            self.assertEqual(len(summary), 2)
            self.assertIn("score", summary[0])

    def test_rekursif_folder(self):
        with tempfile.TemporaryDirectory() as td:
            code = cli.main(["--dir", str(FIX), "--out", td, "--format", "json"])
            self.assertEqual(code, 0)
            summary = json.loads((Path(td) / "ringkasan.json").read_text())
            self.assertEqual(len(summary), 4)               # 4 fixture

    def test_fail_under(self):
        code = cli.main([str(FIX / "cisco-bad.cfg"), "--fail-under", "95"])
        self.assertEqual(code, 1)

    def test_list_aturan(self):
        self.assertEqual(cli.main(["--list"]), 0)

    def test_tanpa_argumen(self):
        self.assertEqual(cli.main([]), 2)

    def test_only_filter(self):
        with tempfile.TemporaryDirectory() as td:
            cli.main([str(FIX / "cisco-bad.cfg"), "--only", "cisco.telnet",
                      "--out", td, "--format", "json"])
            data = json.loads(next(Path(td).glob("confcheck-*.json")).read_text())
            self.assertEqual({f["code"] for f in data["findings"]}, {"cisco.telnet"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

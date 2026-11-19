from ipaddress import IPv4Address
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ps_bitrate_relay.config import Config


TOML_BASE = """\
interface = "en0"
host_ip = "10.10.10.16"
default_bitrate = 40000

[ps5]
ip = "10.10.10.65"
mac = "c8:4a:a0:44:a3:bf"
"""


def device(group, ip, mac, bitrate=None):
    section = f'\n[[clients.{group}]]\nip = "{ip}"\nmac = "{mac}"\n'
    if bitrate is not None:
        section += f"bitrate = {bitrate}\n"
    return section


class ConfigTests(unittest.TestCase):
    def load(self, content):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "config.toml"
            path.write_text(content)
            return Config.load(path)

    def test_example_and_optional_clients(self):
        example = Path(__file__).resolve().parents[1] / "config.example.toml"
        config = Config.load(example)
        self.assertEqual(config.mini, IPv4Address("10.10.10.16"))
        self.assertEqual(config.ps5, IPv4Address("10.10.10.65"))
        self.assertEqual(config.bitrates, {
            IPv4Address("10.10.10.213"): 40000,
            IPv4Address("10.10.10.214"): 65000,
        })
        self.assertEqual(self.load(TOML_BASE).clients, {})

    def test_requires_ps5_table(self):
        with self.assertRaisesRegex(ValueError, r"^ps5: expected a table$"):
            self.load(TOML_BASE.replace("[ps5]", "[playstation]"))

    def test_portal_accepts_its_original_bitrate(self):
        portal_ip = "10.10.10.214"
        portal_mac = "02:00:00:00:00:01"
        explicit = self.load(TOML_BASE + device("portal", portal_ip, portal_mac, 25000))
        inherited = self.load(TOML_BASE.replace("40000", "25000") + device("portal", portal_ip, portal_mac))
        self.assertEqual(explicit.bitrates[IPv4Address(portal_ip)], 25000)
        self.assertEqual(inherited.bitrates[IPv4Address(portal_ip)], 25000)

    def test_invalid_bitrate_errors_identify_device_or_default(self):
        for group, value in (
            ("remote_play", 15000), ("remote_play", "true"), ("portal", "80000.0"),
            ("portal", 9999), ("portal", 123456), ("portal", 201000),
        ):
            with self.subTest(group=group, value=value):
                with self.assertRaisesRegex(ValueError, rf"clients\.{group}\[1\]\.bitrate .*got "):
                    self.load(TOML_BASE + device(group, "10.10.10.214", "02:00:00:00:00:01", value))
        with self.assertRaisesRegex(ValueError, "default_bitrate:.*100000"):
            self.load(TOML_BASE.replace("40000", "100000"))

    def test_duplicate_and_invalid_addresses(self):
        mac = device("remote_play", "10.10.10.213", "02:00:00:00:00:01")
        for ip, address, field in (
            ("10.10.10.213", "02:00:00:00:00:02", "ip"),
            ("10.10.10.214", "02:0:0:0:0:1", "mac"),
            ("10.10.10.16", "02:00:00:00:00:02", "ip"),
        ):
            with self.subTest(ip=ip, address=address):
                with self.assertRaisesRegex(ValueError, rf"clients\.portal\[1\]\.{field}.*duplicate"):
                    self.load(TOML_BASE + mac + device("portal", ip, address, 65000))
        with self.assertRaisesRegex(ValueError, r"clients\.remote_play\[1\]\.ip"):
            self.load(TOML_BASE + device("remote_play", "::1", "02:00:00:00:00:01"))
        with self.assertRaisesRegex(ValueError, r"clients\.remote_play\[1\]\.mac"):
            self.load(TOML_BASE + device("remote_play", "10.10.10.213", "ff:ff:ff:ff:ff:ff"))

    def test_32_client_limit_applies_across_groups(self):
        content = TOML_BASE + "".join(
            device("remote_play" if index < 16 else "portal", f"10.10.10.{100 + index}",
                   f"02:00:00:00:00:{index:02x}", 65000)
            for index in range(32)
        )
        self.assertEqual(len(self.load(content).clients), 32)
        with self.assertRaisesRegex(ValueError, r"clients\.portal\[17\].*32 LAN clients"):
            self.load(content + device("portal", "10.10.10.200", "02:00:00:00:00:ff", 65000))

    def test_unknown_device_field_is_rejected(self):
        content = TOML_BASE + device("remote_play", "10.10.10.213", "02:00:00:00:00:01", 65000)
        with self.assertRaisesRegex(ValueError, r"clients\.remote_play\[1\]: unknown fields bandwidth"):
            self.load(content.replace("\nbitrate = 65000", "\nbandwidth = 65000"))

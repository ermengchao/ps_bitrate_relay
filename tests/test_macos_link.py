from ipaddress import IPv4Address, IPv4Network
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ps_bitrate_relay import macos

IFCONFIG = """en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    ether 18:4a:53:08:ff:14
    inet 10.10.10.16 netmask 0xffffff00 broadcast 10.10.10.255
    status: active
"""


class LinkTest(unittest.TestCase):
    def check(self, scoped_route, interface_info=IFCONFIG):
        def command(*args):
            if args == ("/sbin/ifconfig", "en0"):
                return SimpleNamespace(stdout=interface_info)
            if args == ("/sbin/route", "-n", "get", "-ifscope", "en0", "10.10.10.65"):
                return SimpleNamespace(stdout=scoped_route)
            # The default path is captured by a VIF; it is not the BPF interface.
            if args == ("/sbin/route", "-n", "get", "10.10.10.65"):
                return SimpleNamespace(stdout="interface: utun6\nflags: <UP,HOST,DONE>\n")
            raise AssertionError(args)
        with patch.object(macos, "command", side_effect=command):
            return macos.check_link("en0", IPv4Address("10.10.10.16"), IPv4Address("10.10.10.65"))

    def test_physical_link_is_valid_even_when_default_uses_vif(self):
        link = self.check("interface: en0\nflags: <UP,HOST,DONE,LLINFO,IFSCOPE>\n")
        self.assertEqual(link.own.hex(":"), "18:4a:53:08:ff:14")
        self.assertEqual(link.mtu, 1500)
        self.assertEqual(link.subnet, IPv4Network("10.10.10.0/24"))

    def test_gateway_route_is_still_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "must be directly connected"):
            self.check("interface: en0\nflags: <UP,GATEWAY,HOST,DONE,IFSCOPE>\n")

    def test_wrong_interface_is_still_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "must be directly connected"):
            self.check("interface: utun6\nflags: <UP,HOST,DONE,IFSCOPE>\n")

    def test_missing_host_address_is_still_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "host_ip"):
            self.check("interface: en0\nflags: <UP,HOST,DONE,IFSCOPE>\n",
                       IFCONFIG.replace("10.10.10.16", "192.168.3.132"))


if __name__ == "__main__":
    unittest.main()

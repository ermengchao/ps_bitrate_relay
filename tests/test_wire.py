import base64
from ipaddress import IPv4Address, IPv4Network
import struct
import unittest

from psrp import macos, wire
from psrp.__main__ import Config, Relay


def varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    return bytes(output) + bytes([value])


def byte_field(number, data):
    return varint(number * 8 + 2) + varint(len(data)) + data


def big(layout):
    cipher = bytearray(layout // 4 * 3)
    cipher[334:339] = b"15000"
    launchspec = base64.b64encode(cipher)
    body = b"\x08\x14" + byte_field(2, bytes(16)) + byte_field(3, launchspec)
    message = (b"\x08\x00\x12" + varint(len(body)) + body)[:1200]
    takion = bytearray(26)
    takion[15:17] = struct.pack("!H", len(message) + 13)
    return bytes(takion) + message, launchspec


def ipv4_udp(source, dest, payload):
    ip = bytearray(20)
    ip[0], ip[8], ip[9] = 0x45, 64, 17
    ip[12:20] = source.packed + dest.packed
    udp = struct.pack("!HHHH", 54001, 9296, len(payload) + 8, 0) + payload
    return wire.IPv4(bytes(ip), udp).with_udp(payload)


class Capture:
    def __init__(self):
        self.frames = []

    def send(self, data):
        self.frames.append(data)


class WireTests(unittest.TestCase):
    def test_partial_takion_protobuf_rewrites_only_bitrate(self):
        for layout in (1756, 1760):
            original, launchspec = big(layout)
            changed, size = wire.patch_big(original, 40000)
            self.assertEqual(size, layout)
            expected_cipher = bytearray(base64.b64decode(launchspec))
            expected_cipher[334:339] = b"40000"
            self.assertEqual(changed, original.replace(launchspec[:1100],
                                                      base64.b64encode(expected_cipher)[:1100]))
            truncated = original[:300]
            truncated = truncated[:15] + struct.pack("!H", len(truncated) - 13) + truncated[17:]
            self.assertIsNone(wire.patch_big(truncated, 40000))

    def test_both_ingress_paths_with_fragment_reassembly(self):
        mini, ps5, client = map(IPv4Address, ("10.10.10.16", "10.10.10.65", "10.10.10.213"))
        own, peer, other = map(macos.mac, ("02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"))
        cfg = Config("en0", mini, ps5, peer, 40000, {client: other})
        link = macos.Link(own, 1500, IPv4Network("10.10.10.0/24"))
        for address in (mini, client):
            tx = Capture()
            relay = Relay(cfg, link, tx, .5, False)
            original, _ = big(1756 if address == client else 1760)
            packet = ipv4_udp(address, ps5, original)
            for raw in reversed(packet.to_wire(700)):
                relay.incoming(wire.IPv4.parse(raw), 1)
            self.assertEqual(tx.frames, [])
            relay.tick(1.6)
            self.assertEqual(len(tx.frames), 1)
            self.assertEqual(tx.frames[0][:14], peer + own + b"\x08\x00")
            sent = wire.IPv4.parse(tx.frames[0][14:])
            self.assertEqual(sent.src, address)
            self.assertEqual(sent.udp()[2], wire.patch_big(original, 40000)[0])
            self.assertEqual(wire.checksum(sent.header), 0)
            pseudo = address.packed + ps5.packed + b"\0\x11" + struct.pack("!H", len(sent.payload))
            self.assertEqual(wire.checksum(pseudo + sent.payload), 0)

    def test_lan_arp_recovery_preserves_switch_learning(self):
        ps5, client = map(IPv4Address, ("10.10.10.65", "10.10.10.213"))
        own, peer, other = map(macos.mac, ("02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"))
        repair = wire.arp_reply(own, other, ps5, client, peer)
        self.assertEqual(repair[:12], other + own)
        self.assertEqual(repair[22:28], peer)
        self.assertEqual(repair[28:32], ps5.packed)


if __name__ == "__main__":
    unittest.main()

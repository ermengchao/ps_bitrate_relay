"""Parse and rewrite the observed IPv4/Takion handshake."""
import base64
from dataclasses import dataclass
from ipaddress import IPv4Address
import struct

STREAM_PORT = 9296
ORIGINAL = 15000
OFFSET = 334
LAYOUTS = {1756, 1760}


def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            break
        octet = data[pos]
        pos += 1
        value |= (octet & 127) << shift
        if not octet & 128:
            return value, pos
    raise ValueError("invalid varint")


def fields(data):
    result = {}
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, kind = divmod(key, 8)
        if not number or number in result:
            raise ValueError("invalid protobuf field")
        if kind == 0:
            value, pos = varint(data, pos)
        elif kind in (1, 2, 5):
            if kind == 2:
                size, pos = varint(data, pos)
            else:
                size = 8 if kind == 1 else 4
            if pos + size > len(data):
                raise ValueError("truncated protobuf field")
            value = data[pos:pos + size]
            pos += size
        else:
            raise ValueError("unexpected protobuf wire type")
        result[number] = value
    return result


def patch_big(data, target, layouts=LAYOUTS):
    if (len(data) < 32 or data[0] or data[13] or data[14] not in (0, 1)
            or any(data[5:9]) or any(data[21:26])
            or data[26:29] != b"\x08\x00\x12"
            or len(data) != int.from_bytes(data[15:17], "big") + 13):
        return None
    try:
        size, start = varint(data, 29)
        end = start + size
        tag, pos = varint(data, start)
        version, pos = varint(data, pos)
        if tag != 8 or version != 20:
            return None
        # The first Takion datagram can end before its protobuf message.
        # The bitrate window must be present entirely in that datagram.
        while pos < min(end, len(data)):
            tag, pos = varint(data, pos)
            size, pos = varint(data, pos)
            if tag & 7 != 2 or pos + size > end:
                return None
            if tag >> 3 == 3:
                if size not in layouts:
                    return None
                lo = OFFSET // 3 * 3
                hi = (OFFSET + 7) // 3 * 3
                left, right = pos + lo // 3 * 4, pos + hi // 3 * 4
                if right > min(pos + size, len(data)):
                    return None
                decoded = bytearray(base64.b64decode(data[left:right], validate=True))
                for i, (old, new) in enumerate(zip(str(ORIGINAL).encode(), str(target).encode())):
                    decoded[OFFSET - lo + i] ^= old ^ new
                return data[:left] + base64.b64encode(decoded) + data[right:], size
            pos += size
    except ValueError:
        return None
    return None


def ps5_event(data):
    if len(data) < 28 or data[0] & 15 or data[13:15] != b"\x00\x01":
        return None
    try:
        message = fields(data[26:])
        kind = message.get(1)
        if kind == 1:
            bang = fields(message[3])
            return "bang", bang.get(3) == bang.get(4) == 1
        if kind == 13:
            return "streaminfo", None
        if kind == 16:
            target = fields(message[17]).get(1)
            if isinstance(target, int):
                return "target_bps", target
        if kind == 8:
            return "disconnect", None
    except (ValueError, KeyError, TypeError):
        return None
    return None


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(word for (word,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


@dataclass(frozen=True)
class IPv4:
    header: bytes
    payload: bytes

    @classmethod
    def parse(cls, data):
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        start = (data[0] & 15) * 4
        end = int.from_bytes(data[2:4], "big")
        if not 20 <= start <= end <= len(data):
            return None
        return cls(data[:start], data[start:end])

    @property
    def src(self):
        return IPv4Address(self.header[12:16])

    @property
    def dst(self):
        return IPv4Address(self.header[16:20])

    @property
    def fragment(self):
        return int.from_bytes(self.header[6:8], "big") & 0x3fff

    def udp(self):
        if self.header[9] != 17 or self.fragment or len(self.payload) < 8:
            return None
        src, dst, size = struct.unpack("!HHH", self.payload[:6])
        if size != len(self.payload):
            return None
        return src, dst, self.payload[8:]

    def with_udp(self, data):
        payload = self.payload[:6] + b"\0\0" + data
        pseudo = self.header[12:20] + b"\0\x11" + struct.pack("!H", len(payload))
        value = checksum(pseudo + payload) or 65535
        return IPv4(self.header, payload[:6] + struct.pack("!H", value) + payload[8:])

    def to_wire(self, mtu):
        if len(self.header) + len(self.payload) <= mtu:
            return [self._encode(self.header, self.payload)]
        if len(self.header) != 20 or self.fragment or self.header[6] & 0x40:
            raise ValueError("cannot forward this oversized IPv4 packet")
        size = (mtu - 20) // 8 * 8
        frames = []
        for start in range(0, len(self.payload), size):
            part = self.payload[start:start + size]
            flags = (0x2000 if start + size < len(self.payload) else 0) | start // 8
            header = self.header[:6] + struct.pack("!H", flags) + self.header[8:]
            frames.append(self._encode(header, part))
        return frames

    @staticmethod
    def _encode(header, payload):
        header = bytearray(header)
        header[2:4] = struct.pack("!H", len(header) + len(payload))
        header[10:12] = b"\0\0"
        header[10:12] = struct.pack("!H", checksum(header))
        return bytes(header) + payload


class Fragments:
    """Hold a small window of startup fragments. Fall back to the original fragments."""

    def __init__(self):
        self.pending = {}

    def add(self, packet, now):
        field = packet.fragment
        key = packet.header[12:20] + packet.header[4:6] + packet.header[9:10]
        if key not in self.pending and len(self.pending) >= 128:
            return None, [packet]
        started, parts = self.pending.setdefault(key, (now, {}))
        offset = (field & 8191) * 8
        if offset in parts and parts[offset] == packet:
            return None, []
        if len(parts) >= 48 or any(
            start < offset + len(packet.payload) and offset < start + len(part.payload)
            for start, part in parts.items()
        ):
            del self.pending[key]
            return None, [*parts.values(), packet]
        parts[offset] = packet
        pos = 0
        for start, part in sorted(parts.items()):
            if start != pos:
                return None, []
            pos += len(part.payload)
            if not part.fragment & 0x2000:
                del self.pending[key]
                header = parts[0].header[:6] + b"\0\0" + parts[0].header[8:]
                return IPv4(header, b"".join(p.payload for _, p in sorted(parts.items()))), list(parts.values())
        return None, []

    def expire(self, now):
        expired = [k for k, (start, _) in self.pending.items() if now - start > .25]
        return [p for key in expired for p in self.pending.pop(key)[1].values()]


def arp_reply(own, client_mac, ps5_ip, client_ip, advertised):
    return (client_mac + own + b"\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02"
            + advertised + ps5_ip.packed + client_mac + client_ip.packed)

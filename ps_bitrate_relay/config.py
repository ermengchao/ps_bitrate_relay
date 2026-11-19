"""Read and validate the TOML relay settings."""

from dataclasses import dataclass, field
from ipaddress import IPv4Address
import re
import tomllib

from . import macos, wire


def _table(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name}: expected a table")
    return value


def _address(parse, value, name):
    try:
        return parse(value)
    except ValueError as exc:
        raise ValueError(f"{name}: {exc}") from exc


def _bitrate(value, name, *, portal=False):
    if portal:
        valid = wire.portal_bitrate_bytes(value) is not None
        expected = ("an integer in 10000..99999 kbps, "
                    "or a multiple of 1000 in 100000..200000 kbps")
    else:
        valid = type(value) is int and 10000 <= value <= 99999 and value != wire.REMOTE_PLAY_ORIGINAL
        expected = "an integer in 10000..99999 kbps other than 15000"
    if not valid:
        raise ValueError(f"{name}: expected {expected}, got {value!r}")
    return value


def _client_rows(groups, key):
    rows = groups.get(key, [])
    if not isinstance(rows, list):
        raise ValueError(f"clients.{key}: expected an array of tables")
    for number, row in enumerate(rows, 1):
        name = f"clients.{key}[{number}]"
        row = _table(row, name)
        unknown = row.keys() - {"ip", "mac", "bitrate"}
        if unknown:
            raise ValueError(f"{name}: unknown fields {', '.join(sorted(unknown))}")
        yield name, row


@dataclass(frozen=True)
class Config:
    interface: str
    mini: IPv4Address
    ps5: IPv4Address
    ps5_mac: bytes
    default_bitrate: int
    clients: dict[IPv4Address, bytes]
    portals: frozenset[IPv4Address] = frozenset()
    bitrates: dict[IPv4Address, int] = field(default_factory=dict)

    @classmethod
    def load(cls, path):
        with path.open("rb") as file:
            data = tomllib.load(file)
        console = _table(data.get("ps5"), "ps5")
        groups = _table(data.get("clients", {}), "clients")

        interface = data.get("interface")
        if not isinstance(interface, str) or not re.fullmatch(r"en\d+", interface):
            raise ValueError("interface: expected an Ethernet enN interface")
        host = _address(IPv4Address, data.get("host_ip"), "host_ip")
        ps5 = _address(IPv4Address, console.get("ip"), "ps5.ip")
        ps5_mac = _address(macos.mac, console.get("mac"), "ps5.mac")
        if host == ps5:
            raise ValueError(f"ps5.ip: {ps5} duplicates host_ip")
        default = _bitrate(data.get("default_bitrate"), "default_bitrate")

        clients, bitrates = {}, {}
        portals = set()
        ip_fields = {host: "host_ip", ps5: "ps5.ip"}
        mac_fields = {ps5_mac: "ps5.mac"}
        for key, portal in (("remote_play", False), ("portal", True)):
            for name, row in _client_rows(groups, key):
                if len(clients) == 32:
                    raise ValueError(f"{name}: at most 32 LAN clients are allowed in total")
                ip = _address(IPv4Address, row.get("ip"), f"{name}.ip")
                if ip in ip_fields:
                    raise ValueError(f"{name}.ip: duplicate {ip}, already used by {ip_fields[ip]}; "
                                     "register each client IP in only one client group")
                mac = _address(macos.mac, row.get("mac"), f"{name}.mac ({ip})")
                if mac in mac_fields:
                    raise ValueError(f"{name}.mac ({ip}): duplicate {mac.hex(':')}, "
                                     f"already used by {mac_fields[mac]}")
                bitrate_name = f"{name}.bitrate ({ip})"
                if "bitrate" not in row:
                    bitrate_name += f" inherits default_bitrate={default}"
                bitrates[ip] = _bitrate(row.get("bitrate", default), bitrate_name, portal=portal)
                clients[ip] = mac
                ip_fields[ip], mac_fields[mac] = f"{name}.ip", f"{name}.mac"
                if portal:
                    portals.add(ip)
        return cls(interface, host, ps5, ps5_mac, default, clients, frozenset(portals), bitrates)

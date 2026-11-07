"""macOS BPF sockets and the relay's own PF anchor."""
import ctypes as C
from dataclasses import dataclass
import ipaddress
import re
import subprocess


PF = "/sbin/pfctl"
ANCHOR = "com.apple/000.psrp-relay"


def command(*args, check=True, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=8)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args[:3])}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def mac(text):
    if not isinstance(text, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}", text):
        raise ValueError("expected a colon-separated MAC address")
    value = bytes(int(octet, 16) for octet in text.split(":"))
    if not any(value) or value[0] & 1:
        raise ValueError("expected a unicast MAC address")
    return value


@dataclass(frozen=True)
class Link:
    own: bytes
    mtu: int
    subnet: ipaddress.IPv4Network


def check_link(interface, mini, ps5):
    route = command("/sbin/route", "-n", "get", str(ps5)).stdout
    if not re.search(r"interface:\s+" + interface + r"\b", route) or re.search(r"flags:.*GATEWAY", route):
        raise RuntimeError("PS5 must be on the selected, directly connected interface")
    info = command("/sbin/ifconfig", interface).stdout
    address = re.search(r"\binet " + re.escape(str(mini)) + r" netmask (0x[0-9a-f]+)\b", info)
    if not address or "status: active" not in info:
        raise RuntimeError("configured Mini address is not active on the LAN interface")
    netmask = ipaddress.IPv4Address(int(address[1], 16))
    subnet = ipaddress.IPv4Network(f"{mini}/{netmask}", strict=False)
    own = mac(re.search(r"\bether ([0-9a-f:]+)", info)[1])
    mtu = int(re.search(r"\bmtu (\d+)", info)[1])
    return Link(own, mtu, subnet)


def verify_ps5(interface, mini, ps5, expected):
    def lookup():
        output = command("/usr/sbin/arp", "-n", "-i", interface, str(ps5), check=False).stdout
        match = re.search(r" at ([0-9a-f:]+) on " + interface + r"\b", output)
        return mac(match[1]) if match else None

    found = lookup()
    if found is None:
        command("/sbin/ping", "-S", str(mini), "-c", "1", "-W", "1000", str(ps5), check=False)
        found = lookup()
    if found != expected:
        raise RuntimeError("could not verify PS5 Ethernet address; wake the PS5 or check ps5_mac")


def rules(interface, mini, ps5, clients):
    result = [
        f"block drop in quick on lo0 inet proto udp from {mini} to {ps5} port 9296",
        f"pass in quick on {interface} inet proto udp from {ps5} port 9296 to {mini} no state",
        f"pass out quick on lo0 inet proto udp from {mini} to {ps5} port 9296 no state",
        f"pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto udp from {mini} to {ps5} port 9296 no state",
    ]
    if clients:
        sources = "{ " + ", ".join(str(ip) for ip in clients) + " }"
        result.insert(0, f"block drop in quick on {interface} inet from {sources} to {ps5}")
    return "\n".join(result) + "\n"


def check_pf(interface, rule_text):
    root = command(PF, "-s", "rules").stdout
    if not re.search(r'^anchor "com\.apple/\*"(?:\s|$)', root, re.M):
        raise RuntimeError("the main PF ruleset has no com.apple/* hook")
    for name in (interface, "lo0"):
        info = command(PF, "-s", "Interfaces", "-v", "-i", name).stdout
        if re.search(r"\bskip\b", info, re.I):
            raise RuntimeError(f"PF skips {name}")
    command(PF, "-n", "-a", ANCHOR, "-f", "-", data=rule_text)
    for line in command(PF, "-a", "com.apple", "-s", "Anchors").stdout.splitlines():
        name = line.strip().strip('"').removeprefix("com.apple/")
        if not name or "/" in name or name >= ANCHOR.split("/")[-1]:
            continue
        if any(command(PF, "-a", "com.apple/" + name, "-s", item).stdout.strip()
               for item in ("rules", "Anchors")):
            raise RuntimeError(f"earlier PF anchor contains rules: {name}")


def matching_state(mini, ps5, clients):
    for line in command(PF, "-s", "states").stdout.splitlines():
        if not re.search(r"(?<![\d.])" + re.escape(str(ps5)) + r"(?![\d.])", line):
            continue
        if any(re.search(r"(?<![\d.])" + re.escape(str(client)) + r"(?![\d.])", line)
               for client in clients):
            return True
        if f"{ps5}:9296" in line and f"{mini}:" in line:
            return True
    return False


class _Timeval(C.Structure):
    _fields_ = [("sec", C.c_long), ("usec", C.c_int)]


class _Header(C.Structure):
    _fields_ = [("time", _Timeval), ("caplen", C.c_uint), ("length", C.c_uint)]


class _Program(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


class Pcap:
    def __init__(self, interface, expression, linktypes=(1,)):
        lib = self.lib = C.CDLL("/usr/lib/libpcap.A.dylib")
        self.handle = None
        ptr, num, string = C.c_void_p, C.c_int, C.c_char_p
        signatures = [
            ("create", ptr, (string, string)), ("close", None, (ptr,)),
            ("set_snaplen", num, (ptr, num)), ("set_timeout", num, (ptr, num)),
            ("set_immediate_mode", num, (ptr, num)), ("set_buffer_size", num, (ptr, num)),
            ("activate", num, (ptr,)), ("datalink", num, (ptr,)),
            ("setnonblock", num, (ptr, num, string)), ("geterr", string, (ptr,)),
            ("compile", num, (ptr, C.POINTER(_Program), string, num, C.c_uint)),
            ("setfilter", num, (ptr, C.POINTER(_Program))), ("freecode", None, (C.POINTER(_Program),)),
            ("next_ex", num, (ptr, C.POINTER(C.POINTER(_Header)), C.POINTER(ptr))),
            ("inject", C.c_ssize_t, (ptr, ptr, C.c_size_t)),
        ]
        for name, result, args in signatures:
            function = getattr(lib, "pcap_" + name)
            function.restype, function.argtypes = result, args
        error = C.create_string_buffer(256)
        self.handle = lib.pcap_create(interface.encode(), error)
        if not self.handle:
            raise RuntimeError(error.value.decode())
        try:
            for name, value in (("snaplen", 65535), ("timeout", 10),
                                ("immediate_mode", 1), ("buffer_size", 4 * 1024 * 1024)):
                if getattr(lib, "pcap_set_" + name)(self.handle, value):
                    raise RuntimeError(f"pcap setup failed: {name}")
            if lib.pcap_activate(self.handle) < 0:
                raise self.error()
            if lib.pcap_datalink(self.handle) not in linktypes:
                raise RuntimeError(f"unexpected link type on {interface}")
            if lib.pcap_setnonblock(self.handle, 1, error):
                raise RuntimeError(error.value.decode())
            program = _Program()
            if lib.pcap_compile(self.handle, C.byref(program), expression.encode(), 1, 0xffffffff):
                raise self.error()
            try:
                if lib.pcap_setfilter(self.handle, C.byref(program)):
                    raise self.error()
            finally:
                lib.pcap_freecode(C.byref(program))
        except BaseException:
            self.close()
            raise

    def error(self):
        return RuntimeError(self.lib.pcap_geterr(self.handle).decode())

    def read(self):
        header = C.POINTER(_Header)()
        payload = C.c_void_p()
        result = self.lib.pcap_next_ex(self.handle, C.byref(header), C.byref(payload))
        if result == 1:
            return C.string_at(payload, header.contents.caplen)
        if result < 0:
            raise self.error()
        return None

    def send(self, data):
        if self.lib.pcap_inject(self.handle, data, len(data)) != len(data):
            raise self.error()

    def close(self):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

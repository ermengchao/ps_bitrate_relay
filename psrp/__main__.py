"""Run one bitrate relay for enrolled LAN clients and the native Tailscale router."""
import argparse
from collections import OrderedDict
from contextlib import ExitStack
from dataclasses import dataclass
import fcntl
import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import time

from . import macos, wire

RUNTIME = Path("/var/run/ps-remote-play-relay")
RECOVERY = RUNTIME / "recovery.json"
ETH_IPV4 = b"\x08\x00"


def log(event, **details):
    print(json.dumps({"event": event, **details}), flush=True)


@dataclass(frozen=True)
class Config:
    interface: str
    mini: IPv4Address
    ps5: IPv4Address
    ps5_mac: bytes
    target: int
    clients: dict

    @classmethod
    def load(cls, path):
        data = json.loads(path.read_text())
        interface = data["interface"]
        if not isinstance(interface, str) or not re.fullmatch(r"en\d+", interface):
            raise ValueError("interface must be an Ethernet enN interface")
        mini, ps5 = IPv4Address(data["mini_ip"]), IPv4Address(data["ps5_ip"])
        target = data["target_kbps"]
        if type(target) is not int or not 10000 <= target <= 99999 or target == wire.ORIGINAL:
            raise ValueError("target_kbps must be 10000..99999 and different from 15000")
        clients = {IPv4Address(ip): macos.mac(mac) for ip, mac in data.get("lan_clients", {}).items()}
        peer = macos.mac(data["ps5_mac"])
        if (mini == ps5 or mini in clients or ps5 in clients or len(clients) > 32
                or peer in clients.values() or len(set(clients.values())) != len(clients)):
            raise ValueError("expected distinct client and gateway addresses, with at most 32 LAN clients")
        return cls(interface, mini, ps5, peer, target, clients)


@dataclass
class Session:
    startup: wire.IPv4
    replacement: bytes
    layout: int
    release_at: float
    last_seen: float
    ingress: str
    released: bool = False
    accepted: bool = False
    streaming: bool = False
    reported: bool = False
    egress: bytes = b""


class Relay:
    def __init__(self, config, link, tx, hold, drop):
        self.config, self.link, self.tx = config, link, tx
        self.hold, self.drop = hold, drop
        self.fragments = wire.Fragments()
        self.sessions = OrderedDict()
        self.arp_retries = {}
        self.eth = config.ps5_mac + link.own + ETH_IPV4

    def announce(self):
        for ip in self.config.clients:
            self.announce_client(ip)

    def announce_client(self, ip):
        self.tx.send(wire.arp_reply(self.link.own, self.config.clients[ip], self.config.ps5,
                                    ip, self.link.own))

    def arp_request(self, frame, now):
        if (len(frame) < 42 or frame[12:22] != b"\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01"
                or frame[38:42] != self.config.ps5.packed):
            return
        ip = IPv4Address(frame[28:32])
        if self.config.clients.get(ip) == frame[22:28] == frame[6:12] and ip not in self.arp_retries:
            self.announce_client(ip)
            # The console can answer the same broadcast. Refresh after its response.
            self.arp_retries[ip] = now + .035

    def send(self, packet):
        packets = packet.to_wire(self.link.mtu)
        for ip in packets:
            self.tx.send(self.eth + ip)
        return fingerprint(wire.IPv4.parse(packets[0]))

    def emit(self, session, packet, port):
        session.egress = self.send(packet.with_udp(session.replacement))
        if not session.released:
            session.released = True
            log("patched", ingress=session.ingress, client=str(packet.src), client_port=port,
                target_kbps=self.config.target, launchspec_bytes=session.layout)

    def incoming(self, packet, now):
        if packet.dst != self.config.ps5:
            return
        ingress = "tailnet" if packet.src == self.config.mini else "lan"
        if ingress == "lan" and packet.src not in self.config.clients:
            return
        originals = [packet]
        if packet.fragment and packet.header[9] == 17:
            packet, originals = self.fragments.add(packet, now)
            if packet is None:
                for part in originals:
                    self.send(part)
                return
        udp = packet.udp()
        if not udp or udp[1] != wire.STREAM_PORT:
            for part in originals:
                self.send(part)
            return
        port, _, payload = udp
        patch = wire.patch_big(payload, self.config.target)
        if patch is None:
            if ingress == "tailnet" and len(originals) == 1:
                self.send(packet.with_udp(payload))
            else:
                for part in originals:
                    self.send(part)
            return
        key = (packet.src, port)
        session = self.sessions.get(key)
        if session is None or session.startup.payload[8:] != payload:
            session = Session(packet, *patch, now + self.hold, now, ingress)
            self.sessions[key] = session
            log("held_big", ingress=ingress, client=str(packet.src), client_port=port,
                launchspec_bytes=session.layout)
        session.last_seen = now
        self.sessions.move_to_end(key)
        if len(self.sessions) > 64:
            self.sessions.popitem(last=False)
        if session.released:
            self.emit(session, packet, port)

    def tick(self, now):
        for ip, deadline in list(self.arp_retries.items()):
            if now >= deadline:
                del self.arp_retries[ip]
                self.announce_client(ip)
        for part in self.fragments.expire(now):
            self.send(part)
        for (_, port), session in list(self.sessions.items()):
            if not self.drop and not session.released and now >= session.release_at:
                self.emit(session, session.startup, port)
        while self.sessions and now - next(iter(self.sessions.values())).last_seen > 180:
            self.sessions.popitem(last=False)

    def observed(self, frame):
        packet = wire.IPv4.parse(frame[14:])
        if packet is None:
            return
        udp = packet.udp()
        if frame[:12] == self.eth[:12] and len(packet.payload) >= 8 and packet.fragment & 8191 == 0:
            session = self.sessions.get((packet.src, struct.unpack("!H", packet.payload[:2])[0]))
            if session and session.egress and fingerprint(packet) == session.egress:
                session.egress = b""
                log("patched_egress", ingress=session.ingress, client=str(packet.src))
            return
        if packet.src != self.config.ps5 or not udp or udp[0] != wire.STREAM_PORT:
            return
        session = self.sessions.get((packet.dst, udp[1]))
        if not session or not (event := wire.ps5_event(udp[2])):
            return
        kind, value = event
        if kind == "bang" and value:
            if not session.released:
                raise RuntimeError(f"PS5 accepted a {session.ingress} session before release")
            session.accepted = True
        elif kind == "streaminfo":
            session.streaming = session.accepted
        elif kind == "target_bps" and session.streaming and not session.reported:
            session.reported = True
            log("ps5_target", ingress=session.ingress, client=str(packet.dst), target_bps=value)
        elif kind == "disconnect":
            self.sessions.pop((packet.dst, udp[1]), None)


def fingerprint(packet):
    return hashlib.blake2s(packet.payload, digest_size=16).digest()


def filters(config, own):
    src = " or ".join(f"src host {ip}" for ip in config.clients)
    lan = (f"(ip and ether dst {own.hex(':')} and dst host {config.ps5} and ({src}))"
           f" or (arp and arp[6:2] = 1 and arp[24:4] = {int(config.ps5)})")
    loop = (f"ip and src host {config.mini} and dst host {config.ps5} and ip proto 17"
            " and (udp dst port 9296 or (ip[6:2] & 8191 != 0))")
    witness = (f"ip and ((ether src {own.hex(':')} and dst host {config.ps5} and ip proto 17)"
               f" or (src host {config.ps5} and udp src port 9296 and (udp[8] & 15 = 0)))")
    return lan if src else None, loop, witness


def process(lan, loop, witness, relay, now):
    busy = False
    for _ in range(128):
        frame = lan.read() if lan else None
        if frame is None:
            break
        busy = True
        if frame[12:14] == b"\x08\x06":
            relay.arp_request(frame, now)
            continue
        packet = wire.IPv4.parse(frame[14:])
        if packet and relay.config.clients.get(packet.src) == frame[6:12]:
            relay.incoming(packet, now)
    for _ in range(128):
        frame = loop.read()
        if frame is None:
            break
        busy = True
        if frame[:4] in (struct.pack("=I", 2), struct.pack("!I", 2)):
            packet = wire.IPv4.parse(frame[4:])
            if packet and packet.src == relay.config.mini:
                relay.incoming(packet, now)
    for _ in range(256):
        frame = witness.read()
        if frame is None:
            break
        busy = True
        relay.observed(frame)
    relay.tick(now)
    return busy


def save_recovery(state):
    temporary = RECOVERY.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    temporary.replace(RECOVERY)


def restore(state):
    errors = []
    try:
        if state["armed"] and state["clients"]:
            own, ps5_mac = bytes.fromhex(state["own"]), bytes.fromhex(state["ps5_mac"])
            ps5 = IPv4Address(state["ps5"])
            with macos.Pcap(state["interface"], "ether proto 0x0000") as tx:
                for _ in range(5):
                    for ip, mac in state["clients"].items():
                        tx.send(wire.arp_reply(own, bytes.fromhex(mac), ps5, IPv4Address(ip), ps5_mac))
                    time.sleep(.1)
    except Exception as exc:
        errors.append(f"ARP: {exc}")
    try:
        macos.command(macos.PF, "-a", macos.ANCHOR, "-F", "rules")
        if macos.command(macos.PF, "-a", macos.ANCHOR, "-s", "rules").stdout.strip():
            raise RuntimeError("the relay PF anchor still has rules")
        token = state["token"]
        if token is not None:
            result = macos.command(macos.PF, "-X", token, check=False)
            if result.returncode:
                refs = macos.command(macos.PF, "-s", "References").stdout
                if re.search(rf"(?<!\d){token}(?!\d)", refs):
                    raise RuntimeError("PF reference still present")
    except Exception as exc:
        errors.append(f"PF: {exc}")
    log("restored", success=not errors, errors=errors)
    if not errors:
        RECOVERY.unlink(missing_ok=True)
    return not errors


def guardian():
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    state = json.loads(RECOVERY.read_text())
    with macos.Pcap(state["interface"], "ether proto 0x0000"):
        pass
    print("guardian_ready", flush=True)
    sys.stdin.buffer.read()
    return 0 if restore(json.loads(RECOVERY.read_text())) else 1


def open_lock():
    RUNTIME.mkdir(mode=0o700, exist_ok=True)
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode & 0o077:
        raise RuntimeError("expected private root-owned runtime directory")
    lock = (RUNTIME / "relay.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        raise RuntimeError("another relay instance is running")
    return lock


def run(args):
    config = Config.load(args.config)
    link = macos.check_link(config.interface, config.mini, config.ps5)
    if any(ip not in link.subnet for ip in (config.ps5, *config.clients)):
        raise RuntimeError("PS5 and enrolled clients must be on the Mini's Ethernet subnet")
    if link.own in (config.ps5_mac, *config.clients.values()):
        raise RuntimeError("PS5 and client MACs must differ from Mini's")
    rule_text = macos.rules(config.interface, config.mini, config.ps5, config.clients)
    lan_filter, loop_filter, witness_filter = filters(config, link.own)
    with ExitStack() as stack:
        if not args.check:
            lock = stack.enter_context(open_lock())
            if RECOVERY.exists() and not restore(json.loads(RECOVERY.read_text())):
                raise RuntimeError("previous relay recovery failed")
        macos.check_pf(config.interface, rule_text)
        macos.verify_ps5(config.interface, config.mini, config.ps5, config.ps5_mac)
        lan = stack.enter_context(macos.Pcap(config.interface, lan_filter)) if lan_filter else None
        loop = stack.enter_context(macos.Pcap("lo0", loop_filter, (0, 108)))
        witness = stack.enter_context(macos.Pcap(config.interface, witness_filter))
        tx = stack.enter_context(macos.Pcap(config.interface, "ether proto 0x0000"))
        if args.check:
            log("check_ok", interface=config.interface, lan_clients=len(config.clients))
            return 0
        if macos.command(macos.PF, "-a", macos.ANCHOR, "-s", "rules").stdout.strip():
            raise RuntimeError("the relay PF anchor is already in use")
        if macos.matching_state(config.mini, config.ps5, config.clients):
            raise RuntimeError("an existing PF state may bypass interception; disconnect Remote Play first")

        state = {"interface": config.interface, "ps5": str(config.ps5), "ps5_mac": config.ps5_mac.hex(),
                 "own": link.own.hex(), "clients": {str(ip): mac.hex() for ip, mac in config.clients.items()},
                 "token": None, "armed": False}
        save_recovery(state)
        guard = subprocess.Popen([sys.executable, "-E", "-s", "-B", "-m", "psrp", "--guardian"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                 start_new_session=True, pass_fds=(lock.fileno(),))
        stopping = False

        def stop(*_):
            nonlocal stopping
            stopping = True

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, stop)
        try:
            if not select.select([guard.stdout], [], [], 6)[0] or guard.stdout.readline().strip() != "guardian_ready":
                raise RuntimeError("recovery process failed to start")
            enabled = macos.command(macos.PF, "-E")
            token = re.search(r"Token\s*:\s*(\d+)", enabled.stdout + enabled.stderr)
            if not token:
                raise RuntimeError("PF did not report an enable-reference token")
            state["token"] = token[1]
            save_recovery(state)
            macos.command(macos.PF, "-a", macos.ANCHOR, "-f", "-", data=rule_text)
            loaded = macos.command(macos.PF, "-a", macos.ANCHOR, "-s", "rules").stdout
            if "route-to" not in loaded or "9296" not in loaded or (lan and "block drop in quick" not in loaded):
                raise RuntimeError("could not verify the installed PF rules")
            macos.check_pf(config.interface, rule_text)
            relay = Relay(config, link, tx, args.hold_seconds, args.drop_big)
            now = time.monotonic()
            deadline = now + args.seconds if args.seconds else float("inf")
            refresh = now
            state["armed"] = bool(lan)
            save_recovery(state)
            log("ready", interface=config.interface, ps5=str(config.ps5), lan_clients=len(config.clients),
                target_kbps=config.target, drop_big=args.drop_big)
            while not stopping and time.monotonic() < deadline:
                if guard.poll() is not None:
                    raise RuntimeError("recovery process stopped unexpectedly")
                now = time.monotonic()
                if lan and now >= refresh:
                    relay.announce()
                    refresh = now + 5
                if not process(lan, loop, witness, relay, now):
                    time.sleep(.001)
        finally:
            guard.stdin.close()
            result = guard.wait(timeout=25)
            output = guard.stdout.read()
            if output:
                print(output, end="", flush=True)
            if result and RECOVERY.exists():
                restore(json.loads(RECOVERY.read_text()))
        return 1 if RECOVERY.exists() else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config.json"))
    parser.add_argument("--check", action="store_true", help="validate route, PF and capture before activation")
    parser.add_argument("--seconds", type=int, default=0, help="stop and restore after this many seconds")
    parser.add_argument("--hold-seconds", type=float, default=.5)
    parser.add_argument("--drop-big", action="store_true", help="bounded negative control")
    parser.add_argument("--guardian", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.geteuid() != 0:
        parser.error("run on macOS with sudo")
    if args.seconds < 0 or not 0 <= args.hold_seconds <= 3 or (args.drop_big and not 0 < args.seconds <= 60):
        parser.error("invalid duration; --drop-big requires --seconds between 1 and 60")
    os.umask(0o077)
    try:
        return guardian() if args.guardian else run(args)
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        log("error", message=str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())

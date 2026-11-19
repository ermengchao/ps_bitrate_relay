# PS Bitrate Relay

Run the relay on a Mac mini on the PS5's home network. It rewrites IPv4 UDP/9296 handshakes from macOS PS Remote Play and local PlayStation Portal clients. The PS5 reports the actual encoder target.

- Local clients must share an IPv4 subnet with the PS5. Register Macs under `[[clients.remote_play]]` and Portals under `[[clients.portal]]`. Enter each device's fixed IPv4 address and the MAC address of its active network interface. Both groups share a limit of 32 devices. The Mac mini sends targeted ARP announcements to receive the IPv4 packets these clients send to the PS5. Video from the PS5 follows the original Layer 2 path back to the client. For a Tailscale-only setup, you can omit the entire `clients` section.
- Remote Macs use native Tailscale to reach the PS5 through a subnet route advertised by the Mac mini. The relay matches traffic that the Mini forwards to the PS5 with `host_ip` as the source address and uses `default_bitrate`. Because remote clients share the Mini's source address, the relay applies the same bitrate to all of them.

`default_bitrate` and per-device `bitrate` values are in kbps. Devices inherit `default_bitrate` when their `bitrate` is omitted. Mac and Tailscale connections accept integers from `10000` to `99999`, excluding `15000`. Portal accepts integers from `10000` to `99999` and multiples of `1000` from `100000` to `200000`. The `200000` setting is experimental.

Under `[[clients.portal]]`, you can set `bitrate = 80000` or `bitrate = 125000`. The relay encodes `125000` as the five-byte JSON number `125e3`. Configuration validation rejects `123456` because its exact representation requires more than five bytes. Test new bitrate settings on a Portal to see which values it accepts.

## Handshake Matching and Rewriting

1. The relay inspects IPv4 UDP packets destined for port `9296` on the PS5 when they come from a registered LAN client or are forwarded through Tailscale with `host_ip` as the source address.
2. It checks the initial Takion header, the zero GMAC, and the BIG message prefix, and requires `client_version == 20`. It then parses the length-delimited protobuf field 3 (`launch_spec`) in `BigPayload` and checks the field boundaries.
3. The total Base64 length of LaunchSpec can vary. The eight Base64 characters covering decoded offsets `334–338` must all be present in the field within the current UDP datagram and decode to six bytes. The relay rewrites that portion of the ciphertext and recomputes the UDP checksum. If the window is absent or invalid, it forwards the original UDP payload. [Matching and rewrite code](ps_bitrate_relay/wire.py)
4. The XOR mask depends on the client type. The Mac and Tailscale paths assume an original value of `15000` kbps, and the Portal path assumes `25000` kbps. The rewrite also assumes that ciphertext offset `334` corresponds to the plaintext `bwKbpsSent` field. If a client moves the field or changes its original value, the packet can still match and be rewritten incorrectly.

### How Related Projects Handle Bitrate

- **Chiaki-ng** is a streaming client. It reads the bitrate from its video settings and writes it to `bwKbpsSent` in LaunchSpec before encryption. It then Base64-encodes the ciphertext and adds it to the BIG message. PS5 streaming uses Takion v12. The Senkusha network test uses a v9 BIG with an empty `launch_spec`. The client generates both messages directly. [Streaming protocol version](https://github.com/streetpea/chiaki-ng/blob/main/lib/src/streamconnection.c#L134-L155) · [Streaming BIG](https://github.com/streetpea/chiaki-ng/blob/main/lib/src/streamconnection.c#L925-L1035) · [Network test BIG](https://github.com/streetpea/chiaki-ng/blob/main/lib/src/senkusha.c#L745-L770)
- **The original `ps5-portal-high-bitrate`** is a network relay for the Portal. It filters unfragmented IPv4 packets from the configured Portal to the PS5 on UDP port `9296` and checks the initial Takion header, zero GMAC, v20 BIG, and `launch_spec` field. It requires a declared field length of exactly `2296` Base64 characters before applying XOR to the portion of ciphertext containing offset `334`. [Original matching and rewrite code](https://github.com/atameric/ps5-portal-high-bitrate/blob/main/portal_active_probe.py#L18-L74) · [Observed Portal results](https://github.com/atameric/ps5-portal-high-bitrate#observed-results)

## Validation and Installation

The service requires Python 3.11 or newer, an Ethernet interface on the Mac mini, a PS5 on the same IPv4 subnet, and root privileges. Copy the [TOML example](config.example.toml), adjust it for your network, and replace or remove the sample Portal entry.

Set the console's `ip` and `mac` under `[ps5]`.

```fish
cp config.example.toml config.toml
uv sync --python 3.11 --locked
uv run --python 3.11 --locked python -m unittest discover -s tests -v
```

The service defaults to `/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11` from the python.org macOS installer. If the Mac mini uses a different system-level installation of Python 3.11 or newer, set `relay_python` below to its absolute path. The installer checks the Python version, validates the setup with that interpreter, and writes the same path into the LaunchDaemon.

```fish
set -l relay_python /Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11
"$relay_python" --version
sudo "$relay_python" -E -s -B -m ps_bitrate_relay --config config.toml --check
sudo /bin/sh deploy/install.sh config.toml "$relay_python"
sudo launchctl print system/local.ps-bitrate-relay
tail -f /Library/Logs/PSBitrateRelay/relay.log
```

`--check` validates the configuration, routing, PF, and packet capture interfaces. Reconnect Remote Play after installation. The `patched` log entry shows the client type and the requested bitrate for the session. On the LAN, video usually bypasses the Mac mini on its way back to the client. Capture packets on the client to verify the encoder target reported by the PS5 for that session.

## Reloading the Service

The installed configuration is at `/Library/Application Support/PSBitrateRelay/config.toml`. After editing it, run `--check` from the installation directory with the service's Python interpreter. Then unload and reload the LaunchDaemon and start a new streaming session.

```fish
sudo /bin/sh -c 'cd "/Library/Application Support/PSBitrateRelay" && exec "$1" -E -s -B -m ps_bitrate_relay --config config.toml --check' sh "$relay_python"; and \
    sudo launchctl bootout system/local.ps-bitrate-relay; and \
    sudo launchctl bootstrap system /Library/LaunchDaemons/local.ps-bitrate-relay.plist
```

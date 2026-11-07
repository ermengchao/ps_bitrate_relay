# PS Remote Play Relay

在 PS5 所在家庭网络的 Mac mini 上运行一个进程，为官方 PS Remote Play 客户端修改 IPv4 UDP/9296 握手里的 LaunchSpec 码率。当前适配已经捕获并验证过的 macOS Remote Play 9.5.0、Takion v20、1756 或 1760 字节 Base64 布局，默认把请求从 15 Mbps 改为 40 Mbps。实际编码目标以 PS5 回报为准，视频吞吐另计。

- 家中客户端与 PS5 同网段。填写 `lan_clients` 中每台客户端的固定 IPv4 地址和当前网卡 MAC。Mini 定向通告 ARP，接收这些客户端发往 PS5 的 IPv4 报文。PS5 发回客户端的视频仍走原来的二层路径。PS5 保持现有接线。
- 外网客户端通过**原生 Tailscale** 使用 Mini 广播的 PS5 子网路由。客户端需要允许接收该路由，并能访问 PS5 私网地址。当前实现匹配 Mini 向 PS5 发出的、源地址为 `mini_ip` 的流量，也就是已验证的 macOS Tailscale 子网转发形态。通过 PSN 公网打洞、非 SNAT 路由和 IPv6 不在当前适配范围。

服务需要 Mini 的有线网口、同一 IPv4 子网里的 PS5，以及 root 权限。程序用一个独立 PF anchor 拦截，停止时移除自己的规则并恢复已登记客户端的 ARP。系统仍需允许 Mini 和客户端直接交换局域网报文。登记 Wi-Fi 客户端时应使用它在该 Wi-Fi 网络上的实际 MAC。部署前断开当前串流，重新连接才会发送新的启动握手。

```fish
cp config.example.json config.json
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
sudo /usr/bin/python3 -E -s -B -m psrp --config config.json --check
sudo /usr/bin/python3 -E -s -B -m psrp --config config.json --seconds 90
```

`target_kbps` 支持五位十进制整数 `10000–99999`，排除原值 `15000`。当前使用同长度的 XOR 改写，其他码率能否被 PS5 接受需要分别测试。只使用 Tailscale 时把 `lan_clients` 设成空对象。

限时测试后，可安装为随 Mini 启动的系统服务。安装器把运行代码和配置复制到 root 所有的目录。项目由 uv 管理，目前无第三方依赖，所以常驻进程使用系统 Python。

```fish
sudo /bin/sh deploy/install.sh config.json
sudo launchctl print system/local.ps-remote-play-relay
tail -f /Library/Logs/PSRemotePlayRelay/relay.log
```

`held_big` 表示接管了启动握手，`patched_egress` 表示独立的网口捕获看到了改写后的报文，`ps5_target` 是 PS5 回报的编码目标。局域网视频回程通常绕过 Mini，需在客户端抓包才能独立读取其 PS5 回报。

停用服务并恢复网络时运行以下命令。调整配置后可再次加载同一个 plist。已安装的配置位于 `/Library/Application Support/PSRemotePlayRelay/config.json`。

```fish
sudo launchctl bootout system/local.ps-remote-play-relay
sudo launchctl bootstrap system /Library/LaunchDaemons/local.ps-remote-play-relay.plist
```

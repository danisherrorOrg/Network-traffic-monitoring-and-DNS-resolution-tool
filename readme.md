# NetScope 🌐
### Real-Time Network Traffic Monitor with Intelligent IP Enrichment

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat)](https://github.com)
[![Requires root](https://img.shields.io/badge/Requires-root%2Fsudo-critical?style=flat)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-scapy%20%7C%20rich-blueviolet?style=flat)](https://github.com)

> **"Who is my computer talking to — and why?"**
>
> NetScope captures live network traffic without storing a single packet, resolves every
> IP address into a human-readable service name, and renders it all in a live terminal
> dashboard. Works correctly on modern dual-stack (IPv4 + IPv6) networks where most
> tools show nothing but raw addresses.

---

## The Problem

Standard tools like `netstat` and `ss` show open connections, but they can't answer:

- What is sending traffic **right now** in the background?
- Which server is behind `2a04:4e42:9::684`?
- Is that 7 MB of traffic going to YouTube or somewhere unknown?

NetScope was built to answer exactly these questions.

---

## How It Works

Every IP address passes through a **5-layer enrichment pipeline** — the first match wins:

```
Layer 1 → Special IP table       192.168.x / 10.x / fe80: / ff02: → "Private LAN / Link-local"
Layer 2 → DNS sniff cache        Intercepts DNS responses in real-time → ip already has a name
Layer 3 → Async PTR lookup       Reverse DNS in background threads — never blocks capture
Layer 4 → Friendly name mapping  "pnmaaa-av-in-x08.1e100.net" → "Google"  (60+ service rules)
Layer 5 → IPv6 prefix table      2a04:4e42 → "Fastly CDN"  (instant, no network call needed)
```

The result: addresses like `2405:201:d033:615c::1` resolve to `Jio / Reliance (India)`
before the dashboard even refreshes.

---

## Features

- **Zero packet storage** — scapy's `store=False` ensures nothing is buffered to memory or disk
- **5-layer IP enrichment** — resolves addresses even when reverse DNS is absent or slow
- **60+ service fingerprints** — Google, YouTube, Cloudflare, AWS, Azure, Apple, Netflix, Jio, Airtel, BSNL, Tata, Zoom, Slack, GitHub, Spotify and more
- **Full protocol detection** — TCP, UDP, ICMP, ICMPv6, IGMP, SCTP, GRE, ESP, AH, OSPF, EIGRP, VRRP, PIM
- **IPv4 + IPv6 dual-stack** — handles modern networks where most traffic is IPv6
- **Inbound / outbound classification** — per-host sent and received byte counters
- **Live Rich TUI** — colour-coded hosts table, live packet feed, protocol legend, real-time stats
- **JSON export on exit** — full session snapshot for offline analysis
- **Companion HTML dashboard** — drag-and-drop the JSON export for visual charts and host breakdown

---

## Demo

```
⬡  NETWORK TRAFFIC MONITOR  ⬡   packets: 14,302  │  data: 47.2 MB  │  uptime: 00:04:11  │  hosts: 18

 Service / Host              Address / PTR                    Pkts    Total    ↑ Out    ↓ In    Proto    Seen
 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Google — YouTube/Video      2404:6800:4003:c05::5e           2,847    9.1 MB   244 KB   8.9 MB  TCP      14:22:01
 Fastly CDN                  2a04:4e42:9::684                 1,203    7.6 MB    18 KB   7.6 MB  TCP      14:21:58
 Jio / Reliance (India)      2405:201:d033:615c:5411:...        891    1.6 MB   512 KB   1.1 MB  TCP UDP  14:22:03
 Microsoft Azure             2620:1ec:50::12                    344  650.3 KB    32 KB  618 KB  TCP      14:21:47
 Cloudflare DNS              1.1.1.1                             87    12.4 KB   6.2 KB   6.2 KB  UDP      14:22:00
 Private LAN (192.168.x)     192.168.1.1                        412    84.1 KB  42.0 KB  42.1 KB  UDP      14:22:04
```

---

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/netscope.git
cd netscope

# Install dependencies
pip install scapy rich

# Run (root required for raw packet capture)
sudo python3 network_monitor.py
```

---

## Usage

```bash
# Monitor all interfaces (default)
sudo python3 network_monitor.py

# Monitor a specific interface
sudo python3 network_monitor.py --interface eth0
sudo python3 network_monitor.py --interface wlan0

# Show top 20 hosts, refresh every 0.5s
sudo python3 network_monitor.py --top 20 --refresh 0.5
```

On `Ctrl+C`, the session is exported as `netscope_<timestamp>.json`.
Open `netscope_dashboard.html` in any browser and drag the JSON file in for visual analysis.

---

## Architecture

```
Packet capture (scapy, store=False)
        │
        ├── DNS response interceptor ──► ip→domain cache (Layer 2)
        │
        └── IP extractor (IPv4 + IPv6)
                │
                ▼
        TrafficState (thread-safe, in-memory)
         ├── per-host byte / packet counters
         └── recent packet ring buffer (capped)
                │
                ▼
        Enrichment pipeline (5 layers)
                │
                ▼
        Rich Live dashboard  ◄── refreshes every N seconds
```

All enrichment happens on read (dashboard refresh), not on write (packet capture),
so the capture thread is never blocked by DNS lookups or pattern matching.

---

## Tech Stack

| Component | Library | Why |
|---|---|---|
| Packet capture | `scapy` | Cross-platform, `store=False` prevents any buffering |
| Terminal UI | `rich` | Live rendering, colour markup, table layout |
| Async DNS | `threading` | Non-blocking PTR lookups without asyncio overhead |
| Web dashboard | Vanilla JS | Zero dependencies, works offline |

---

## Roadmap

- [ ] Flow aggregation (5-tuple: src/dst IP + port + protocol)
- [ ] Port → service name mapping (443 → HTTPS, 22 → SSH)
- [ ] Traffic rate (bytes/sec per host)
- [ ] Periodic beacon detection (interval-based background traffic flagging)
- [ ] ASN + GeoIP enrichment via MaxMind GeoLite2 (offline)
- [ ] BPF pre-filters (`--filter "tcp port 443"`)
- [ ] Prometheus metrics endpoint for Grafana integration

---

## Requirements

- Python 3.10+
- Linux or macOS
- `root` / `sudo` (raw packet capture requires elevated privileges)
- `pip install scapy rich`

> **Windows:** Install [Npcap](https://npcap.com) first, then scapy should work.

---

## License

MIT — free to use, modify, and distribute.
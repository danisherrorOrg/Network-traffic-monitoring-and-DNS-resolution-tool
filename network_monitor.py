#!/usr/bin/env python3
"""
Network Traffic Monitor-
-----------------------
Captures packets in real-time (no storage), enriches every IP through a
multi-layer pipeline, and displays a live dashboard showing WHO your
computer is talking to in plain English.

Enrichment pipeline (in order, first match wins):
  1. Special/reserved IP detection  (loopback, multicast, broadcast …)
  2. In-memory DNS sniff cache       (built from port-53 traffic you generate)
  3. Reverse PTR lookup              (async, never blocks sniffing)
  4. PTR → friendly name cleanup     (1e100.net → Google, akamaitechnologies → Akamai CDN …)
  5. Hardcoded well-known IPv6 prefix table  (2a04:4e42 → Fastly CDN …)
  6. Raw IP as last resort

Requirements:
    pip install scapy rich

Run with:
    sudo python3 network_monitor.py
    sudo python3 network_monitor.py --interface eth0
    sudo python3 network_monitor.py --top 20 --refresh 2
"""

import argparse
import ipaddress
import json
import re
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────
#  Scapy imports
# ─────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, GRE, ESP, AH, SCTP, DNS, DNSQR
    try:
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
    except ImportError:
        ICMPv6EchoRequest = ICMPv6EchoReply = None
    try:
        from scapy.layers.l2 import IGMP
    except ImportError:
        IGMP = None
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─────────────────────────────────────────────
#  Rich imports
# ─────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ─────────────────────────────────────────────
#  Protocol Registry
# ─────────────────────────────────────────────
PROTOCOL_META: dict[str, tuple[str, str]] = {
    "TCP":    ("cyan",    "Reliable stream — HTTP/S, SSH, SMTP …"),
    "UDP":    ("yellow",  "Fast datagram — DNS, QUIC, video, games"),
    "ICMP":   ("green",   "Diagnostics — ping, traceroute, errors"),
    "ICMPv6": ("green",   "IPv6 control — NDP, ping6, router discovery"),
    "IGMP":   ("magenta", "Multicast group management (LAN only)"),
    "SCTP":   ("blue",    "Multi-stream reliable transport — VoIP/SS7"),
    "GRE":    ("red",     "Generic tunnel — wraps VPN/overlay packets"),
    "ESP":    ("red",     "IPsec encrypted payload"),
    "AH":     ("red",     "IPsec authentication (unencrypted)"),
    "OSPF":   ("white",   "Link-state routing protocol (routers only)"),
    "EIGRP":  ("white",   "Cisco distance-vector routing (routers only)"),
    "VRRP":   ("white",   "Virtual Router Redundancy (gateway failover)"),
    "PIM":    ("white",   "Protocol-Independent Multicast"),
    "OTHER":  ("dim",     "Unrecognised IP protocol number"),
}

_PROTO_NUM_MAP: dict[int, str] = {
    2: "IGMP", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP",
}


# ═══════════════════════════════════════════════════════════════════════
#  ENRICHMENT LAYER 1 — Special / reserved address table
# ═══════════════════════════════════════════════════════════════════════

_SPECIAL_PREFIXES: list[tuple[str, str]] = [
    ("127.",            "Loopback (this machine)"),
    ("0.0.0.0",         "Unspecified address"),
    ("255.255.255.255", "Broadcast"),
    ("224.",            "Multicast (IPv4)"),
    ("239.",            "Multicast — local scope"),
    ("169.254.",        "Link-local (no DHCP / APIPA)"),
    ("10.",             "Private LAN (10.x)"),
    ("192.168.",        "Private LAN (192.168.x)"),
    ("::1",             "Loopback (this machine)"),
    ("fe80:",           "Link-local (IPv6)"),
    ("ff02:",           "Multicast — link-scope (IPv6)"),
    ("ff05:",           "Multicast — site-scope (IPv6)"),
    ("fc",              "Unique local — IPv6 private (fc)"),
    ("fd",              "Unique local — IPv6 private (fd)"),
]

def _is_172_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("172.16.0.0/12")
    except ValueError:
        return False

def special_label(ip: str) -> Optional[str]:
    ip_lower = ip.lower()
    for prefix, label in _SPECIAL_PREFIXES:
        if ip_lower.startswith(prefix.lower()):
            return label
    if _is_172_private(ip):
        return "Private LAN (172.16.x)"
    return None


# ═══════════════════════════════════════════════════════════════════════
#  ENRICHMENT LAYER 2 — DNS sniff cache
#  Intercepts DNS responses your machine receives and maps ip → domain
# ═══════════════════════════════════════════════════════════════════════

_dns_query_cache: dict[str, str] = {}
_dns_query_lock  = threading.Lock()


def record_dns_answer(pkt) -> None:
    """Parse DNS response packets and populate ip→domain map."""
    try:
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 1:   # responses only
            return
        for i in range(dns.ancount):
            ans  = dns.an[i]
            name = ans.rrname
            if isinstance(name, bytes):
                name = name.decode(errors="replace").rstrip(".")
            rdata = getattr(ans, "rdata", None)
            if not rdata or not isinstance(rdata, str):
                continue
            with _dns_query_lock:
                existing = _dns_query_cache.get(rdata)
                if not existing or len(name) < len(existing):
                    _dns_query_cache[rdata] = name
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
#  ENRICHMENT LAYER 3 — Async reverse PTR lookup
# ═══════════════════════════════════════════════════════════════════════

_ptr_cache:   dict[str, str] = {}
_ptr_lock     = threading.Lock()
_ptr_pending: set[str] = set()
_ptr_pending_lock = threading.Lock()


def _do_ptr(ip: str) -> None:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ""
    with _ptr_lock:
        _ptr_cache[ip] = hostname
    with _ptr_pending_lock:
        _ptr_pending.discard(ip)


def async_ptr(ip: str) -> None:
    with _ptr_pending_lock:
        if ip in _ptr_pending:
            return
        _ptr_pending.add(ip)
    threading.Thread(target=_do_ptr, args=(ip,), daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════
#  ENRICHMENT LAYER 4 — PTR hostname → friendly service name
#  Maps raw PTR strings like "pnmaaa-av-in-x08.1e100.net" → "Google"
# ═══════════════════════════════════════════════════════════════════════

_PTR_FRIENDLY: list[tuple[re.Pattern, str]] = [
    (re.compile(r"1e100\.net",               re.I), "Google"),
    (re.compile(r"googlevideo\.com",          re.I), "Google — YouTube/Video"),
    (re.compile(r"googleapis\.com",           re.I), "Google APIs"),
    (re.compile(r"google\.com",               re.I), "Google"),
    (re.compile(r"gstatic\.com",              re.I), "Google Static CDN"),
    (re.compile(r"googleusercontent",         re.I), "Google User Content"),
    (re.compile(r"ggpht\.com",                re.I), "Google"),
    (re.compile(r"akamaitechnologies\.com",   re.I), "Akamai CDN"),
    (re.compile(r"akamai\.net",               re.I), "Akamai CDN"),
    (re.compile(r"akamaiedge\.net",           re.I), "Akamai CDN"),
    (re.compile(r"akamaihd\.net",             re.I), "Akamai CDN"),
    (re.compile(r"fastly\.net",               re.I), "Fastly CDN"),
    (re.compile(r"fastlylb\.net",             re.I), "Fastly CDN"),
    (re.compile(r"cloudflare\.com",           re.I), "Cloudflare"),
    (re.compile(r"cloudflare-dns",            re.I), "Cloudflare DNS"),
    (re.compile(r"amazonaws\.com",            re.I), "Amazon AWS"),
    (re.compile(r"cloudfront\.net",           re.I), "Amazon CloudFront CDN"),
    (re.compile(r"awsglobalaccelerator",      re.I), "Amazon AWS"),
    (re.compile(r"azure(websites|edge|fd)",   re.I), "Microsoft Azure"),
    (re.compile(r"microsoft\.com",            re.I), "Microsoft"),
    (re.compile(r"msftconnecttest",           re.I), "Microsoft Connectivity Check"),
    (re.compile(r"windows\.net",              re.I), "Microsoft Azure"),
    (re.compile(r"office365\.com",            re.I), "Microsoft Office 365"),
    (re.compile(r"msecnd\.net",               re.I), "Microsoft CDN"),
    (re.compile(r"skype\.com",                re.I), "Microsoft Skype"),
    (re.compile(r"teams\.microsoft",          re.I), "Microsoft Teams"),
    (re.compile(r"apple\.com",                re.I), "Apple"),
    (re.compile(r"apple-dns\.net",            re.I), "Apple DNS"),
    (re.compile(r"icloud\.com",               re.I), "Apple iCloud"),
    (re.compile(r"mzstatic\.com",             re.I), "Apple App Store CDN"),
    (re.compile(r"facebook\.com",             re.I), "Meta / Facebook"),
    (re.compile(r"fbcdn\.net",                re.I), "Meta / Facebook CDN"),
    (re.compile(r"instagram\.com",            re.I), "Meta / Instagram"),
    (re.compile(r"whatsapp\.net",             re.I), "Meta / WhatsApp"),
    (re.compile(r"twitter\.com",              re.I), "X / Twitter"),
    (re.compile(r"twimg\.com",                re.I), "X / Twitter CDN"),
    (re.compile(r"netflix\.com",              re.I), "Netflix"),
    (re.compile(r"nflxvideo\.net",            re.I), "Netflix CDN"),
    (re.compile(r"nflximg\.net",              re.I), "Netflix CDN"),
    (re.compile(r"spotify\.com",              re.I), "Spotify"),
    (re.compile(r"scdn\.co",                  re.I), "Spotify CDN"),
    (re.compile(r"zoom\.us",                  re.I), "Zoom"),
    (re.compile(r"slack\.com",                re.I), "Slack"),
    (re.compile(r"slack-edge\.com",           re.I), "Slack CDN"),
    (re.compile(r"github\.com",               re.I), "GitHub"),
    (re.compile(r"githubcopilot\.com",        re.I), "GitHub Copilot"),
    (re.compile(r"githubusercontent",         re.I), "GitHub CDN"),
    (re.compile(r"ubuntu\.com",               re.I), "Ubuntu"),
    (re.compile(r"snapcraft\.io",             re.I), "Snap / Ubuntu"),
    (re.compile(r"debian\.org",               re.I), "Debian"),
    (re.compile(r"ntp\.org",                  re.I), "NTP Time Server"),
    (re.compile(r"pool\.ntp",                 re.I), "NTP Time Server"),
    (re.compile(r"time\.google",              re.I), "Google NTP"),
    (re.compile(r"time\.apple",               re.I), "Apple NTP"),
    (re.compile(r"time\.windows",             re.I), "Windows NTP"),
    (re.compile(r"time\.cloudflare",          re.I), "Cloudflare NTP"),
    (re.compile(r"ocsp\.",                    re.I), "Certificate Status (OCSP)"),
    (re.compile(r"crl\.",                     re.I), "Certificate Revocation (CRL)"),
    (re.compile(r"telemetry",                 re.I), "Telemetry / Analytics"),
    (re.compile(r"analytics",                 re.I), "Analytics Service"),
    (re.compile(r"crashlytics",               re.I), "Firebase Crashlytics"),
    (re.compile(r"firebase",                  re.I), "Google Firebase"),
    (re.compile(r"jio",                       re.I), "Jio / Reliance (India)"),
    (re.compile(r"airtel",                    re.I), "Airtel (India)"),
    (re.compile(r"bsnl",                      re.I), "BSNL (India)"),
    (re.compile(r"tata",                      re.I), "Tata Communications"),
    (re.compile(r"cdn\.",                     re.I), "CDN (generic)"),
    (re.compile(r"\.cdn\.",                   re.I), "CDN (generic)"),
]

def ptr_to_friendly(ptr: str) -> Optional[str]:
    if not ptr:
        return None
    for pattern, name in _PTR_FRIENDLY:
        if pattern.search(ptr):
            return name
    return None


# ═══════════════════════════════════════════════════════════════════════
#  ENRICHMENT LAYER 5 — IPv6 prefix → provider
#  PTR lookup is often absent or slow for IPv6 addresses.
#  Match against published IPv6 allocations of major providers.
# ═══════════════════════════════════════════════════════════════════════

_IPV6_PREFIXES: list[tuple[str, str]] = [
    ("2a04:4e42",   "Fastly CDN"),
    ("2a04:4e40",   "Fastly CDN"),
    ("2606:4700",   "Cloudflare"),
    ("2606:2800",   "Akamai CDN"),
    ("2600:1400",   "Akamai CDN"),
    ("2600:1401",   "Akamai CDN"),
    ("2600:1402",   "Akamai CDN"),
    ("2600:1403",   "Akamai CDN"),
    ("2a00:1450",   "Google"),
    ("2404:6800",   "Google"),
    ("2607:f8b0",   "Google"),
    ("2620:0:1c00", "Google"),
    ("2001:4860",   "Google"),
    ("2620:1ec:50", "Microsoft Azure"),
    ("2620:1ec:21", "Microsoft Azure"),
    ("2a01:111",    "Microsoft Azure"),
    ("2600:9000",   "Amazon AWS / CloudFront"),
    ("2620:108",    "Amazon AWS"),
    ("2405:200",    "Jio / Reliance (India)"),
    ("2405:201",    "Jio / Reliance (India)"),
    ("2401:4900",   "Airtel (India)"),
    ("2402:3a80",   "Airtel (India)"),
    ("2404:a800",   "BSNL (India)"),
    ("2001:e68",    "Tata Communications"),
    ("2620:fe",     "APNIC / Research"),
    ("2001:4998",   "Yahoo / Verizon Media"),
    ("2a03:2880",   "Meta / Facebook"),
    ("2620:10d",    "Meta / Facebook"),
    ("2400:cb00",   "Cloudflare"),
]

def ipv6_prefix_lookup(ip: str) -> Optional[str]:
    ip_l = ip.lower()
    for prefix, name in _IPV6_PREFIXES:
        if ip_l.startswith(prefix.lower()):
            return name
    return None


# ═══════════════════════════════════════════════════════════════════════
#  Master enrichment — runs all 5 layers, returns (display, detail)
# ═══════════════════════════════════════════════════════════════════════

def enrich_ip(ip: str) -> tuple[str, str]:
    """
    Returns:
        display  — best human-readable name  (e.g. "Google", "Fastly CDN")
        detail   — PTR or raw IP shown as subtitle
    """
    # Layer 1
    s = special_label(ip)
    if s:
        return s, ip

    # Layer 2 — did we see this IP in a DNS answer?
    with _dns_query_lock:
        queried = _dns_query_cache.get(ip)
    if queried:
        friendly = ptr_to_friendly(queried)
        return (friendly or queried), ip

    # Layer 3 + 4 — PTR + friendly mapping
    with _ptr_lock:
        ptr = _ptr_cache.get(ip)
    if ptr:
        friendly = ptr_to_friendly(ptr)
        if friendly:
            return friendly, ptr
        return ptr, ip           # show raw PTR if no pattern matched

    # Layer 5 — IPv6 prefix table (instant, no network call)
    if ":" in ip:
        pname = ipv6_prefix_lookup(ip)
        if pname:
            return pname, ip

    # Schedule PTR if not yet attempted
    with _ptr_lock:
        if ip not in _ptr_cache:
            async_ptr(ip)

    return "resolving…", ip


# ─────────────────────────────────────────────
#  In-Memory Traffic State  (no disk writes)
# ─────────────────────────────────────────────

class TrafficState:
    def __init__(self):
        self._lock       = threading.Lock()
        self.packet_count: int   = 0
        self.byte_count:   int   = 0
        self.start_time:   float = time.time()
        self.hosts: dict[str, dict] = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "sent": 0, "received": 0,
            "protocols": set(), "last_seen": None,
        })
        self.recent:    list[dict] = []
        self.MAX_RECENT = 60
        self.local_ips  = self._get_local_ips()

    @staticmethod
    def _get_local_ips() -> set[str]:
        ips = {"127.0.0.1", "::1"}
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(info[4][0])
        except Exception:
            pass
        return ips

    def record(self, src: str, dst: str, proto: str, size: int) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.packet_count += 1
            self.byte_count   += size
            if src in self.local_ips:
                remote, direction = dst, "OUT →"
            elif dst in self.local_ips:
                remote, direction = src, "IN  ←"
            else:
                remote, direction = src, "PASS"
            h = self.hosts[remote]
            h["packets"]  += 1
            h["bytes"]    += size
            h["protocols"].add(proto)
            h["last_seen"]  = now
            if direction == "OUT →":
                h["sent"]     += size
            else:
                h["received"] += size
            self.recent.append({
                "time": now, "src": src, "dst": dst,
                "protocol": proto, "size": size, "direction": direction,
            })
            if len(self.recent) > self.MAX_RECENT:
                self.recent.pop(0)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "packet_count": self.packet_count,
                "byte_count":   self.byte_count,
                "hosts": {ip: {**d, "protocols": set(d["protocols"])}
                          for ip, d in self.hosts.items()},
                "recent": list(self.recent),
                "uptime": time.time() - self.start_time,
            }


state = TrafficState()


# ─────────────────────────────────────────────
#  Protocol detection
# ─────────────────────────────────────────────

def detect_protocol(pkt) -> str:
    if pkt.haslayer(TCP):  return "TCP"
    if pkt.haslayer(UDP):  return "UDP"
    if pkt.haslayer(SCTP): return "SCTP"
    if pkt.haslayer(ICMP): return "ICMP"
    if ICMPv6EchoRequest and (
        pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply)
    ):
        return "ICMPv6"
    if pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
        return "ICMPv6"
    if pkt.haslayer(GRE): return "GRE"
    if pkt.haslayer(ESP): return "ESP"
    if pkt.haslayer(AH):  return "AH"
    if IGMP and pkt.haslayer(IGMP): return "IGMP"
    for layer in (IP, IPv6):
        if pkt.haslayer(layer):
            n = pkt[layer].proto if layer is IP else pkt[layer].nh
            if n in _PROTO_NUM_MAP:
                return _PROTO_NUM_MAP[n]
    return "OTHER"


# ─────────────────────────────────────────────
#  Packet handler
# ─────────────────────────────────────────────

def packet_handler(pkt) -> None:
    if pkt.haslayer(DNS):
        record_dns_answer(pkt)
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return
    state.record(src, dst, detect_protocol(pkt), len(pkt))


# ─────────────────────────────────────────────
#  Dashboard
# ─────────────────────────────────────────────

def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def build_dashboard(snap: dict, top_n: int) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="legend", size=len(PROTOCOL_META) // 2 + 3),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="hosts",  ratio=3),
        Layout(name="recent", ratio=2),
    )

    # ── Header ──────────────────────────────────────────────
    uptime = int(snap["uptime"])
    hh, mm, ss = uptime // 3600, (uptime % 3600) // 60, uptime % 60
    hdr = Text(justify="center")
    hdr.append("⬡  NETWORK TRAFFIC MONITOR  ⬡", style="bold cyan")
    hdr.append(
        f"   packets: {snap['packet_count']:,}  │  data: {fmt_bytes(snap['byte_count'])}"
        f"  │  uptime: {hh:02d}:{mm:02d}:{ss:02d}  │  hosts: {len(snap['hosts'])}",
        style="dim",
    )
    layout["header"].update(Panel(hdr, style="bold blue"))

    # ── Hosts table ─────────────────────────────────────────
    tbl = Table(
        title=f"Top {top_n} Remote Hosts",
        box=box.SIMPLE_HEAD, style="cyan",
        header_style="bold magenta", expand=True,
    )
    tbl.add_column("Service / Host",  style="bold white", no_wrap=True, min_width=22)
    tbl.add_column("Address / PTR",   style="dim",        no_wrap=True, max_width=38)
    tbl.add_column("Pkts",  justify="right", style="yellow")
    tbl.add_column("Total", justify="right", style="green")
    tbl.add_column("↑ Out", justify="right", style="red")
    tbl.add_column("↓ In",  justify="right", style="blue")
    tbl.add_column("Proto", style="cyan")
    tbl.add_column("Seen",  style="dim", width=8)

    sorted_hosts = sorted(
        snap["hosts"].items(), key=lambda x: x[1]["bytes"], reverse=True
    )[:top_n]

    for ip, data in sorted_hosts:
        display, detail = enrich_ip(ip)
        name_cell = Text(display, style="dim italic" if display == "resolving…" else "bold white")
        addr_cell = (detail[:36] + "…") if len(detail) > 37 else detail

        protos = " ".join(
            f"[{PROTOCOL_META.get(p, ('dim',''))[0]}]{p}[/{PROTOCOL_META.get(p, ('dim',''))[0]}]"
            for p in sorted(data["protocols"])
        ) or "-"

        tbl.add_row(
            name_cell, addr_cell,
            str(data["packets"]),
            fmt_bytes(data["bytes"]),
            fmt_bytes(data["sent"]),
            fmt_bytes(data["received"]),
            protos,
            data["last_seen"] or "-",
        )

    layout["hosts"].update(Panel(tbl, title="[bold]🌐 Hosts", border_style="cyan"))

    # ── Recent feed ─────────────────────────────────────────
    rt = Table(
        title="Recent Packets",
        box=box.SIMPLE_HEAD, style="green",
        header_style="bold green", expand=True,
    )
    rt.add_column("Time",      style="dim",   width=8)
    rt.add_column("Dir",       width=5)
    rt.add_column("Proto",     width=6)
    rt.add_column("From → To", style="white", no_wrap=True)
    rt.add_column("Size",      justify="right", style="yellow")

    for entry in reversed(snap["recent"][-20:]):
        is_out = "OUT" in entry["direction"]
        src_name, _ = enrich_ip(entry["src"])
        dst_name, _ = enrich_ip(entry["dst"])
        src_disp = entry["src"] if src_name == "resolving…" else src_name
        dst_disp = entry["dst"] if dst_name == "resolving…" else dst_name
        rt.add_row(
            entry["time"],
            Text(entry["direction"].strip(), style="red" if is_out else "blue"),
            entry["protocol"],
            f"{src_disp} → {dst_disp}",
            fmt_bytes(entry["size"]),
        )

    layout["recent"].update(Panel(rt, title="[bold]📡 Live Feed", border_style="green"))

    # ── Protocol legend ──────────────────────────────────────
    lt = Table(box=box.SIMPLE_HEAD, style="dim",
               header_style="bold white", expand=True)
    lt.add_column("Protocol", style="bold", width=10)
    lt.add_column("What it is")
    lt.add_column("Protocol", style="bold", width=10)
    lt.add_column("What it is")
    items = list(PROTOCOL_META.items())
    half  = (len(items) + 1) // 2
    for i in range(half):
        ln, (lc, ld) = items[i]
        if i + half < len(items):
            rn, (rc, rd) = items[i + half]
            lt.add_row(f"[{lc}]{ln}[/{lc}]", ld, f"[{rc}]{rn}[/{rc}]", rd)
        else:
            lt.add_row(f"[{lc}]{ln}[/{lc}]", ld, "", "")
    layout["legend"].update(Panel(lt, title="[bold]📖 Protocol Reference", border_style="dim"))

    # ── Footer ──────────────────────────────────────────────
    ft = Text(justify="center")
    ft.append("Press ", style="dim")
    ft.append("Ctrl+C", style="bold yellow")
    ft.append(" to stop  │  All data processed in-memory — nothing written to disk", style="dim")
    layout["footer"].update(Panel(ft, style="dim"))

    return layout


# ─────────────────────────────────────────────
#  Sniff thread
# ─────────────────────────────────────────────

def start_sniffing(interface: Optional[str] = None) -> None:
    kwargs: dict = dict(prn=packet_handler, store=False)
    if interface:
        kwargs["iface"] = interface
    try:
        sniff(**kwargs)
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")



# ─────────────────────────────────────────────
#  Shared stop-event  (used by ALL modes)
#  Handles: Ctrl+C · --duration timeout · SIGHUP · SIGTERM
# ─────────────────────────────────────────────

import signal as _signal
import sys as _sys

_stop_event = threading.Event()   # global — set by any stop trigger


def _setup_stop_event(duration: Optional[int]) -> None:
    """
    Wire up every possible stop trigger to _stop_event.
    Call this once in main() before launching any mode.
    """

    # SIGHUP — SSH session closed / terminal hung up
    def _on_sighup(signum, frame):
        _stop_event.set()
    try:
        _signal.signal(_signal.SIGHUP, _on_sighup)
    except (OSError, AttributeError):
        pass  # Windows has no SIGHUP

    # SIGTERM — system shutdown or `kill <pid>`
    def _on_sigterm(signum, frame):
        _stop_event.set()
    try:
        _signal.signal(_signal.SIGTERM, _on_sigterm)
    except (OSError, AttributeError):
        pass

    # --duration countdown
    if duration:
        def _timer():
            _stop_event.wait(timeout=duration)
            _stop_event.set()
        threading.Thread(target=_timer, daemon=True).start()


# ─────────────────────────────────────────────
#  JSON export helper  (shared by all modes)
# ─────────────────────────────────────────────

def export_session(no_export: bool) -> Optional[str]:
    """Serialize current state to a timestamped JSON file. Returns path or None."""
    if no_export:
        return None
    snap = state.snapshot()
    data = {
        "packet_count": snap["packet_count"],
        "byte_count":   snap["byte_count"],
        "hosts": {
            ip: {
                **{k: list(v) if isinstance(v, set) else v for k, v in d.items()},
                "hostname": enrich_ip(ip)[0],
                "ptr":      _ptr_cache.get(ip, ""),
            }
            for ip, d in snap["hosts"].items()
        },
        "recent": snap["recent"],
    }
    out = f"netscope_{int(time.time())}.json"
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    return out


# ─────────────────────────────────────────────
#  MODE 1 — dashboard  (Rich live TUI)
# ─────────────────────────────────────────────

def run_dashboard(args) -> None:
    """
    Full-screen Rich TUI. Best for local terminals.
    Stops on Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    """
    console = Console()
    try:
        with Live(console=console, refresh_per_second=1/args.refresh, screen=True) as live:
            while not _stop_event.is_set():
                live.update(build_dashboard(state.snapshot(), args.top))
                time.sleep(args.refresh)
    except KeyboardInterrupt:
        pass
    console.print("\n[bold yellow]Capture stopped.[/bold yellow]")
    path = export_session(args.no_export)
    if path:
        console.print(
            f"[green]✓ Session saved → [bold]{path}[/bold]  "
            f"(drag into netscope_dashboard.html)[/green]"
        )


# ─────────────────────────────────────────────
#  MODE 2 — log  (plain scrolling text)
# ─────────────────────────────────────────────

# Direction symbols for plain text
_DIR_SYMBOL = {"OUT →": "↑", "IN  ←": "↓", "PASS": "↔"}

def run_log(args) -> None:
    """
    Scrolling plain-text output — one line per packet.
    SSH-safe, pipeable, works in any terminal.

    Format:
        HH:MM:SS  ↑/↓  PROTO  Service/IP → Service/IP  (NNN B)
    """
    # Register a per-packet callback that prints immediately
    original_record = state.record

    def record_and_print(src: str, dst: str, proto: str, size: int) -> None:
        original_record(src, dst, proto, size)
        # Resolve names for display (non-blocking — uses whatever is cached)
        src_name, _ = enrich_ip(src)
        dst_name, _ = enrich_ip(dst)
        src_disp = src if src_name == "resolving…" else src_name
        dst_disp = dst if dst_name == "resolving…" else dst_name

        # Determine direction symbol from perspective of local machine
        if src in state.local_ips:
            sym = "↑"
        elif dst in state.local_ips:
            sym = "↓"
        else:
            sym = "↔"

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{ts}  {sym}  {proto:<6}  {src_disp} → {dst_disp}  ({fmt_bytes(size)})",
              flush=True)

    state.record = record_and_print  # monkey-patch for this mode

    dur_hint = f"  |  stops in {args.duration}s" if args.duration else "  |  Ctrl+C to stop"
    print(f"NetScope — log mode  |  interface: {args.interface or 'all'}{dur_hint}")
    print(f"{'─' * 72}")

    try:
        while not _stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    print(f"\n{'─' * 72}")
    snap = state.snapshot()
    print(f"Captured {snap['packet_count']:,} packets  |  {fmt_bytes(snap['byte_count'])}  |  "
          f"{len(snap['hosts'])} hosts seen")
    path = export_session(args.no_export)
    if path:
        print(f"Session saved → {path}")


# ─────────────────────────────────────────────
#  MODE 3 — quiet  (silent capture)
# ─────────────────────────────────────────────

def run_quiet(args) -> None:
    """
    Silent capture — no output while running.
    Stops via Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    Always exports JSON before exiting.

    SSH usage:
        nohup sudo python3 network_monitor.py --mode quiet --duration 300 &
        echo $! > netscope.pid

        # Or use screen/tmux:
        screen -dmS netscope sudo python3 network_monitor.py --mode quiet
    """
    # All stop triggers (duration, SIGHUP, SIGTERM) are already wired via
    # _setup_stop_event() called in main() — just wait on the shared event.
    try:
        while not _stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass  # Ctrl+C — fall through to export

    path = export_session(args.no_export)
    snap = state.snapshot()

    # Summary → stderr so stdout stays clean for scripting
    print(
        f"netscope: {snap['packet_count']:,} packets  "
        f"{fmt_bytes(snap['byte_count'])}  "
        f"{len(snap['hosts'])} hosts seen",
        file=_sys.stderr,
    )
    if path:
        # Path → stdout so scripts can capture it:
        # json=$(sudo python3 network_monitor.py --mode quiet --duration 60)
        print(path)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

_MODES = {
    "dashboard": run_dashboard,
    "log":       run_log,
    "quiet":     run_quiet,
}

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetScope — real-time network monitor showing WHO your machine talks to",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output modes:
  dashboard   Full-screen Rich TUI with live tables  (default)
  log         Scrolling plain text — SSH / pipe friendly
  quiet       Silent capture; prints JSON path on exit

Examples:
  sudo python3 network_monitor.py
  sudo python3 network_monitor.py --mode log
  sudo python3 network_monitor.py --mode log --interface wlan0 | grep Google
  sudo python3 network_monitor.py --mode quiet
  sudo python3 network_monitor.py --duration 300
  sudo python3 network_monitor.py --mode log --duration 120
  sudo python3 network_monitor.py --mode quiet --duration 600
  sudo python3 network_monitor.py --mode dashboard --top 20 --refresh 0.5

SSH / headless usage:
  # Capture for 10 minutes in background, survive disconnect:
  nohup sudo python3 network_monitor.py --mode quiet --duration 600 &

  # Capture until you manually stop it (SIGHUP-safe):
  nohup sudo python3 network_monitor.py --mode quiet &
  kill $(cat netscope.pid)    # to stop it later

  # Capture and immediately load in the HTML dashboard:
  json=$(sudo python3 network_monitor.py --mode quiet --duration 60)
  echo "Open netscope_dashboard.html and load: $json"

  # Use screen so you can detach/reattach:
  screen -dmS netscope sudo python3 network_monitor.py --mode quiet
  screen -r netscope   # reattach later
        """,
    )

    parser.add_argument(
        "--mode", "-m",
        choices=list(_MODES.keys()),
        default="dashboard",
        help="Output mode: dashboard | log | quiet  (default: dashboard)",
    )
    parser.add_argument("--interface", "-i", default=None,
                        help="Network interface to capture on (default: all)")
    parser.add_argument("--top",       "-t", type=int,   default=15,
                        help="[dashboard] Top N hosts shown (default: 15)")
    parser.add_argument("--refresh",   "-r", type=float, default=1.0,
                        help="[dashboard] Refresh interval in seconds (default: 1.0)")
    parser.add_argument("--no-export", action="store_true",
                        help="Skip JSON export on exit")
    parser.add_argument(
        "--duration", "-d", type=int, default=None,
        metavar="SECONDS",
        help="Auto-stop after N seconds — works with all modes (e.g. --duration 300)",
    )

    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print("❌  scapy not found.  Run:  pip install scapy"); return
    if args.mode == "dashboard" and not RICH_AVAILABLE:
        print("❌  rich not found.   Run:  pip install rich");  return

    iface = args.interface or "all interfaces"
    if args.mode != "quiet":
        print(f"[netscope] mode={args.mode}  interface={iface}  "
              f"enrichment=5-layer  storage=none")

    _setup_stop_event(args.duration)
    threading.Thread(target=start_sniffing, args=(args.interface,), daemon=True).start()

    _MODES[args.mode](args)


if __name__ == "__main__":
    main()
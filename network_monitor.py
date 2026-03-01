#!/usr/bin/env python3
"""
Network Traffic Monitor
-----------------------
Captures packets in real-time (no storage), performs reverse DNS lookups,
and displays a live dashboard of who is communicating with your machine.

Requirements:
    pip install scapy rich dnspython

Run with:
    sudo python3 network_monitor.py
    sudo python3 network_monitor.py --interface eth0
    sudo python3 network_monitor.py --top 20 --refresh 2
"""

import argparse
import socket
import threading
import time
from typing import Optional
from collections import defaultdict
from datetime import datetime

# --- Gracefully handle missing dependencies ---
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

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
#  DNS Cache & Resolver
# ─────────────────────────────────────────────

_dns_cache: dict[str, str] = {}
_dns_lock = threading.Lock()


def reverse_dns(ip: str) -> str:
    """Reverse-DNS lookup with in-memory cache (never written to disk)."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = ip  # Fall back to raw IP if no PTR record

    with _dns_lock:
        _dns_cache[ip] = hostname

    return hostname


def async_reverse_dns(ip: str) -> None:
    """Trigger a DNS lookup in a background thread so sniffing isn't blocked."""
    t = threading.Thread(target=reverse_dns, args=(ip,), daemon=True)
    t.start()


# ─────────────────────────────────────────────
#  In-Memory Traffic State  (no disk writes)
# ─────────────────────────────────────────────

class TrafficState:
    """Thread-safe, in-memory only traffic tracker."""

    def __init__(self):
        self._lock = threading.Lock()
        self.packet_count: int = 0
        self.byte_count: int = 0
        self.start_time: float = time.time()

        # Per-IP counters  {ip: {"packets": int, "bytes": int, "direction": str, "protocol": str}}
        self.hosts: dict[str, dict] = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "sent": 0, "received": 0,
            "protocols": set(), "last_seen": None
        })

        # Recent connections log (capped at 50 entries to avoid unbounded growth)
        self.recent: list[dict] = []
        self.MAX_RECENT = 50

        # Get local IPs once
        self.local_ips = self._get_local_ips()

    @staticmethod
    def _get_local_ips() -> set[str]:
        ips = {"127.0.0.1", "::1"}
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                ips.add(info[4][0])
        except Exception:
            pass
        return ips

    def record(self, src: str, dst: str, protocol: str, size: int) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.packet_count += 1
            self.byte_count += size

            # Determine the remote IP
            if src in self.local_ips:
                remote, direction = dst, "OUT →"
            elif dst in self.local_ips:
                remote, direction = src, "IN  ←"
            else:
                remote, direction = src, "PASS"

            h = self.hosts[remote]
            h["packets"] += 1
            h["bytes"] += size
            h["protocols"].add(protocol)
            h["last_seen"] = now
            if direction == "OUT →":
                h["sent"] += size
            else:
                h["received"] += size

            # Kick off async DNS if not yet cached
            if remote not in _dns_cache:
                async_reverse_dns(remote)

            # Append to recent log (ring buffer)
            self.recent.append({
                "time": now, "src": src, "dst": dst,
                "protocol": protocol, "size": size, "direction": direction
            })
            if len(self.recent) > self.MAX_RECENT:
                self.recent.pop(0)

    def snapshot(self) -> dict:
        """Return a safe copy for the UI thread."""
        with self._lock:
            hosts_copy = {
                ip: {**data, "protocols": set(data["protocols"])}
                for ip, data in self.hosts.items()
            }
            return {
                "packet_count": self.packet_count,
                "byte_count": self.byte_count,
                "hosts": hosts_copy,
                "recent": list(self.recent),
                "uptime": time.time() - self.start_time,
            }


# ─────────────────────────────────────────────
#  Packet Handler
# ─────────────────────────────────────────────

state = TrafficState()


def packet_handler(pkt) -> None:
    """Called for every captured packet – extract IPs and protocol only."""
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)

    if pkt.haslayer(TCP):
        proto = "TCP"
    elif pkt.haslayer(UDP):
        proto = "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    else:
        proto = "OTHER"

    state.record(src, dst, proto, size)


# ─────────────────────────────────────────────
#  Rich Dashboard
# ─────────────────────────────────────────────

def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def build_dashboard(snap: dict, top_n: int) -> Layout:
    """Build the Rich layout from a state snapshot."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="hosts", ratio=3),
        Layout(name="recent", ratio=2),
    )

    # ── Header ──
    uptime = int(snap["uptime"])
    h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
    header_text = Text(justify="center")
    header_text.append("⬡  NETWORK TRAFFIC MONITOR  ⬡", style="bold cyan")
    header_text.append(
        f"   packets: {snap['packet_count']:,}  │  "
        f"data: {fmt_bytes(snap['byte_count'])}  │  "
        f"uptime: {h:02d}:{m:02d}:{s:02d}  │  "
        f"hosts seen: {len(snap['hosts'])}",
        style="dim"
    )
    layout["header"].update(Panel(header_text, style="bold blue"))

    # ── Hosts Table ──
    hosts_table = Table(
        title=f"Top {top_n} Remote Hosts",
        box=box.SIMPLE_HEAD,
        style="cyan",
        header_style="bold magenta",
        show_footer=False,
        expand=True,
    )
    hosts_table.add_column("Hostname / IP", style="bold white", no_wrap=True)
    hosts_table.add_column("Raw IP", style="dim")
    hosts_table.add_column("Pkts", justify="right", style="yellow")
    hosts_table.add_column("Total", justify="right", style="green")
    hosts_table.add_column("↑ Sent", justify="right", style="red")
    hosts_table.add_column("↓ Recv", justify="right", style="blue")
    hosts_table.add_column("Proto", style="cyan")
    hosts_table.add_column("Last Seen", style="dim")

    sorted_hosts = sorted(
        snap["hosts"].items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )[:top_n]

    for ip, data in sorted_hosts:
        hostname = _dns_cache.get(ip, "resolving…")
        display = hostname if hostname != ip else ip
        raw_ip = ip if hostname != ip else ""
        protocols = ", ".join(sorted(data["protocols"]))
        hosts_table.add_row(
            display, raw_ip,
            str(data["packets"]),
            fmt_bytes(data["bytes"]),
            fmt_bytes(data["sent"]),
            fmt_bytes(data["received"]),
            protocols,
            data["last_seen"] or "-",
        )

    layout["hosts"].update(Panel(hosts_table, title="[bold]🌐 Hosts", border_style="cyan"))

    # ── Recent Activity ──
    recent_table = Table(
        title="Recent Packets",
        box=box.SIMPLE_HEAD,
        style="green",
        header_style="bold green",
        expand=True,
    )
    recent_table.add_column("Time", style="dim", width=8)
    recent_table.add_column("Dir", width=5)
    recent_table.add_column("Proto", width=5)
    recent_table.add_column("Src → Dst", style="white", no_wrap=True)
    recent_table.add_column("Size", justify="right", style="yellow")

    for entry in reversed(snap["recent"][-20:]):
        dir_style = "red" if "OUT" in entry["direction"] else "blue"
        recent_table.add_row(
            entry["time"],
            Text(entry["direction"].strip(), style=dir_style),
            entry["protocol"],
            f"{entry['src']} → {entry['dst']}",
            fmt_bytes(entry["size"]),
        )

    layout["recent"].update(Panel(recent_table, title="[bold]📡 Live Feed", border_style="green"))

    # ── Footer ──
    footer = Text(justify="center")
    footer.append("Press ", style="dim")
    footer.append("Ctrl+C", style="bold yellow")
    footer.append(" to stop  │  Data is processed in-memory only — nothing is written to disk", style="dim")
    layout["footer"].update(Panel(footer, style="dim"))

    return layout


# ─────────────────────────────────────────────
#  Sniff Thread
# ─────────────────────────────────────────────

def start_sniffing(interface: Optional[str] = None) -> None:
    kwargs = dict(prn=packet_handler, store=False)  # store=False = no packet storage!
    if interface:
        kwargs["iface"] = interface
    try:
        sniff(**kwargs)
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Real-time network traffic monitor with DNS resolution")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff (default: all)")
    parser.add_argument("--top", "-t", type=int, default=15, help="Number of top hosts to display (default: 15)")
    parser.add_argument("--refresh", "-r", type=float, default=1.0, help="Dashboard refresh interval in seconds (default: 1.0)")
    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print("❌  scapy is not installed. Run:  pip install scapy")
        return
    if not RICH_AVAILABLE:
        print("❌  rich is not installed. Run:  pip install rich")
        return

    iface_msg = args.interface or "all interfaces"
    print(f"[*] Starting packet capture on {iface_msg}  (requires root/sudo)")
    print(f"[*] Packets are processed in-memory only — nothing written to disk\n")

    # Start sniffing in a background daemon thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(args.interface,), daemon=True)
    sniff_thread.start()

    console = Console()

    try:
        with Live(console=console, refresh_per_second=1 / args.refresh, screen=True) as live:
            while True:
                snap = state.snapshot()
                live.update(build_dashboard(snap, args.top))
                time.sleep(args.refresh)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Capture stopped.[/bold yellow]")

        # Offer JSON export for the HTML dashboard
        snap = state.snapshot()
        # Make protocols serializable and add resolved hostnames
        export = {
            "packet_count": snap["packet_count"],
            "byte_count": snap["byte_count"],
            "hosts": {
                ip: {
                    **{k: list(v) if isinstance(v, set) else v for k, v in data.items()},
                    "hostname": _dns_cache.get(ip, ip),
                }
                for ip, data in snap["hosts"].items()
            },
            "recent": snap["recent"],
        }
        import json
        out_path = f"netscope_{int(time.time())}.json"
        with open(out_path, "w") as f:
            json.dump(export, f, indent=2)
        console.print(f"[green]✓ Session saved to [bold]{out_path}[/bold] — drag it into netscope_dashboard.html[/green]")


if __name__ == "__main__":
    main()

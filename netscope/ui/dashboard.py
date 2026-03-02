# netscope/ui/dashboard.py
# ─────────────────────────────────────────────────────────────────────
# Rich TUI dashboard builder.
# Takes a state snapshot dict and returns a Rich Layout ready to render.
# No I/O, no threading — pure layout construction.
# ─────────────────────────────────────────────────────────────────────

from netscope.enrichment import enrich_ip
from netscope.enrichment.ptr import get_cache as get_ptr_cache
from netscope.protocols import PROTOCOL_META

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def fmt_bytes(n: int) -> str:
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def build_dashboard(snap: dict, top_n: int) -> "Layout":
    """
    Build the full Rich Layout from a TrafficState snapshot.
    Called every refresh cycle by run_dashboard().
    """
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

    # ── Header ───────────────────────────────────────────────────────
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

    # ── Hosts table ──────────────────────────────────────────────────
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
        name_cell = Text(
            display,
            style="dim italic" if display == "resolving\u2026" else "bold white",
        )
        addr_cell = (detail[:36] + "\u2026") if len(detail) > 37 else detail
        protos = " ".join(
            f"[{PROTOCOL_META.get(p, ('dim', ''))[0]}]{p}"
            f"[/{PROTOCOL_META.get(p, ('dim', ''))[0]}]"
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

    # ── Recent feed ──────────────────────────────────────────────────
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
        src_disp = entry["src"] if src_name == "resolving\u2026" else src_name
        dst_disp = entry["dst"] if dst_name == "resolving\u2026" else dst_name
        rt.add_row(
            entry["time"],
            Text(entry["direction"].strip(), style="red" if is_out else "blue"),
            entry["protocol"],
            f"{src_disp} \u2192 {dst_disp}",
            fmt_bytes(entry["size"]),
        )

    layout["recent"].update(Panel(rt, title="[bold]📡 Live Feed", border_style="green"))

    # ── Protocol legend ───────────────────────────────────────────────
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
    layout["legend"].update(
        Panel(lt, title="[bold]📖 Protocol Reference", border_style="dim")
    )

    # ── Footer ───────────────────────────────────────────────────────
    ft = Text(justify="center")
    ft.append("Press ", style="dim")
    ft.append("Ctrl+C", style="bold yellow")
    ft.append(
        " to stop  │  All data processed in-memory — nothing written to disk",
        style="dim",
    )
    layout["footer"].update(Panel(ft, style="dim"))

    return layout
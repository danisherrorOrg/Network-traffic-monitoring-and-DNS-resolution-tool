# netscope/modes/runner.py
# ─────────────────────────────────────────────────────────────────────
# Output modes — dashboard, log, quiet.
# Each mode runs until _stop_event is set, then exports and exits.
#
# To add a new mode:
#   1. Write run_<name>(args) below
#   2. Add it to MODES at the bottom
#   3. argparse in cli.py picks it up automatically
# ─────────────────────────────────────────────────────────────────────

import sys
import time
from datetime import datetime

from netscope.state import state
from netscope.flows import flow_table
from netscope.enrichment import enrich_ip
from netscope.ui import build_dashboard, fmt_bytes, RICH_AVAILABLE
from netscope.modes.stop import _stop_event
from netscope.modes.export import export_session


# ── MODE 1 — dashboard  (Rich live TUI) ─────────────────────────────

def run_dashboard(args) -> None:
    """
    Full-screen Rich TUI with live-updating tables.
    Stops on Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    """
    from rich.console import Console
    from rich.live import Live

    console = Console()
    try:
        with Live(console=console, refresh_per_second=1 / args.refresh, screen=True) as live:
            while not _stop_event.is_set():
                # Expire idle flows on every UI refresh cycle
                flow_table.expire_idle()

                snap = state.snapshot()
                snap["flow_stats"] = flow_table.stats()
                flows = flow_table.snapshot(top_n=args.top)

                live.update(build_dashboard(snap, args.top, flows))
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


# ── MODE 2 — log  (plain scrolling text) ────────────────────────────

def run_log(args) -> None:
    """
    One line per packet, plain text — SSH-safe and pipeable.

    Format:
        HH:MM:SS  ↑/↓  PROTO  src:port → dst:port  Service  (size)

    Stops on Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    """
    from netscope.flows import port_service

    _original_record = state.record

    def _record_and_print(
        src: str, src_port: int,
        dst: str, dst_port: int,
        proto: str, size: int,
    ) -> None:
        _original_record(src, src_port, dst, dst_port, proto, size)

        src_name, _ = enrich_ip(src)
        dst_name, _ = enrich_ip(dst)
        src_disp = src if src_name == "resolving\u2026" else src_name
        dst_disp = dst if dst_name == "resolving\u2026" else dst_name

        # Append port if known service or non-ephemeral
        def with_port(name: str, port: int) -> str:
            if port == 0:
                return name
            svc = port_service(port)
            # Only annotate if it adds useful info (known service or low port)
            if svc != str(port) or port < 1024:
                return f"{name}:{svc}"
            return name

        sym = "\u2191" if src in state.local_ips else "\u2193"
        ts  = datetime.now().strftime("%H:%M:%S")
        print(
            f"{ts}  {sym}  {proto:<6}  "
            f"{with_port(src_disp, src_port)} \u2192 {with_port(dst_disp, dst_port)}"
            f"  ({fmt_bytes(size)})",
            flush=True,
        )

    state.record = _record_and_print

    dur_hint = f"  |  stops in {args.duration}s" if args.duration else "  |  Ctrl+C to stop"
    print(f"NetScope — log mode  |  interface: {args.interface or 'all'}{dur_hint}")
    print("\u2500" * 80)

    try:
        while not _stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    line = '\u2500' * 80
    print(f"\n{line}")
    snap  = state.snapshot()
    stats = flow_table.stats()
    print(
        f"Captured {snap['packet_count']:,} packets  |  "
        f"{fmt_bytes(snap['byte_count'])}  |  "
        f"{len(snap['hosts'])} hosts  |  "
        f"{stats['total']} flows ({stats['active']} active)"
    )
    path = export_session(args.no_export)
    if path:
        print(f"Session saved \u2192 {path}")


# ── MODE 3 — quiet  (silent capture) ────────────────────────────────

def run_quiet(args) -> None:
    """
    Silent capture — no output while running.
    Stops via Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    Always exports JSON before exiting.

    SSH usage:
        nohup sudo python3 main.py --mode quiet --duration 300 &
        echo $! > netscope.pid

        json=$(sudo python3 main.py --mode quiet --duration 60)
    """
    try:
        while not _stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    path  = export_session(args.no_export)
    snap  = state.snapshot()
    stats = flow_table.stats()

    print(
        f"netscope: {snap['packet_count']:,} packets  "
        f"{fmt_bytes(snap['byte_count'])}  "
        f"{len(snap['hosts'])} hosts  "
        f"{stats['total']} flows",
        file=sys.stderr,
    )
    if path:
        print(path)


# ── Mode registry ────────────────────────────────────────────────────

MODES: dict[str, callable] = {
    "dashboard": run_dashboard,
    "log":       run_log,
    "quiet":     run_quiet,
}
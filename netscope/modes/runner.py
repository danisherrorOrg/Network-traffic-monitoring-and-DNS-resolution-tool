# netscope/modes/runner.py
# ─────────────────────────────────────────────────────────────────────
# Output modes — dashboard, log, quiet.
# Each mode is a self-contained function that runs until _stop_event
# is set, then triggers a JSON export and exits cleanly.
#
# To add a new mode:
#   1. Write a run_<name>(args) function below
#   2. Add it to MODES at the bottom of this file
#   3. That's it — argparse in main.py picks it up automatically
# ─────────────────────────────────────────────────────────────────────

import sys
import time
from datetime import datetime

from netscope.state import state
from netscope.enrichment import enrich_ip
from netscope.ui import build_dashboard, fmt_bytes, RICH_AVAILABLE
from netscope.modes.stop import _stop_event
from netscope.modes.export import export_session


# ── MODE 1 — dashboard  (Rich live TUI) ─────────────────────────────

def run_dashboard(args) -> None:
    """
    Full-screen Rich TUI with live-updating tables.
    Best for local terminals with a modern terminal emulator.
    Stops on Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    """
    from rich.console import Console
    from rich.live import Live

    console = Console()
    try:
        with Live(console=console, refresh_per_second=1 / args.refresh, screen=True) as live:
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


# ── MODE 2 — log  (plain scrolling text) ────────────────────────────

def run_log(args) -> None:
    """
    One line per packet, plain text — SSH-safe and pipeable.

    Format:
        HH:MM:SS  ↑/↓  PROTO   Service → Service  (size)

    Works inside tmux, screen, over SSH, and with grep/tee/awk.
    Stops on Ctrl+C, --duration timeout, SIGHUP, or SIGTERM.
    """
    # Monkey-patch state.record so every packet prints immediately
    _original_record = state.record

    def _record_and_print(src: str, dst: str, proto: str, size: int) -> None:
        _original_record(src, dst, proto, size)

        src_name, _ = enrich_ip(src)
        dst_name, _ = enrich_ip(dst)
        src_disp = src if src_name == "resolving\u2026" else src_name
        dst_disp = dst if dst_name == "resolving\u2026" else dst_name
        sym = "\u2191" if src in state.local_ips else "\u2193"

        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"{ts}  {sym}  {proto:<6}  {src_disp} \u2192 {dst_disp}  ({fmt_bytes(size)})",
            flush=True,
        )

    state.record = _record_and_print

    dur_hint = f"  |  stops in {args.duration}s" if args.duration else "  |  Ctrl+C to stop"
    print(f"NetScope — log mode  |  interface: {args.interface or 'all'}{dur_hint}")
    print("\u2500" * 72)

    try:
        while not _stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    print(f"\n{'\u2500' * 72}")
    snap = state.snapshot()
    print(
        f"Captured {snap['packet_count']:,} packets  |  "
        f"{fmt_bytes(snap['byte_count'])}  |  "
        f"{len(snap['hosts'])} hosts seen"
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
        # Run for 5 minutes in background, survive disconnect:
        nohup sudo python3 main.py --mode quiet --duration 300 &
        echo $! > netscope.pid

        # Use screen/tmux for interactive use:
        screen -dmS netscope sudo python3 main.py --mode quiet
        screen -r netscope

        # Capture result path in a variable:
        json=$(sudo python3 main.py --mode quiet --duration 60)
    """
    # All stop triggers are wired in setup_stop_event() called from main.py
    try:
        while not _stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    path = export_session(args.no_export)
    snap = state.snapshot()

    # Summary → stderr so stdout stays clean for scripting
    print(
        f"netscope: {snap['packet_count']:,} packets  "
        f"{fmt_bytes(snap['byte_count'])}  "
        f"{len(snap['hosts'])} hosts seen",
        file=sys.stderr,
    )
    if path:
        print(path)   # path → stdout for script capture


# ── Mode registry ────────────────────────────────────────────────────
# Add new modes here — main.py reads this dict for --mode choices.

MODES: dict[str, callable] = {
    "dashboard": run_dashboard,
    "log":       run_log,
    "quiet":     run_quiet,
}
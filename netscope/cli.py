#!/usr/bin/env python3
# main.py
# ─────────────────────────────────────────────────────────────────────
# NetScope entry point.
# Parses CLI arguments, validates dependencies, then hands off to
# the chosen output mode. No logic lives here — just wiring.
#
# Run with:
#   sudo python3 main.py
#   sudo python3 main.py --mode log --duration 120
#   sudo python3 main.py --mode quiet --duration 300
# ─────────────────────────────────────────────────────────────────────

import argparse

from netscope.capture import SCAPY_AVAILABLE, start as start_capture
from netscope.modes import MODES, setup_stop_event
from netscope.ui import RICH_AVAILABLE


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
  sudo python3 main.py
  sudo python3 main.py --mode log
  sudo python3 main.py --mode log --interface wlan0 | grep Google
  sudo python3 main.py --mode quiet
  sudo python3 main.py --duration 300
  sudo python3 main.py --mode log --duration 120
  sudo python3 main.py --mode quiet --duration 600
  sudo python3 main.py --mode dashboard --top 20 --refresh 0.5

SSH / headless usage:
  # Capture for 10 minutes in background, survive disconnect:
  nohup sudo python3 main.py --mode quiet --duration 600 &
  echo $! > netscope.pid

  # Capture result path in a shell variable:
  json=$(sudo python3 main.py --mode quiet --duration 60)
  echo "Load $json into netscope_dashboard.html"

  # Use screen to detach/reattach freely:
  screen -dmS netscope sudo python3 main.py --mode quiet
  screen -r netscope
        """,
    )

    parser.add_argument(
        "--mode", "-m",
        choices=list(MODES.keys()),
        default="dashboard",
        help="Output mode: dashboard | log | quiet  (default: dashboard)",
    )
    parser.add_argument(
        "--interface", "-i", default=None,
        help="Network interface to capture on (default: all)",
    )
    parser.add_argument(
        "--top", "-t", type=int, default=15,
        help="[dashboard] Top N hosts to display (default: 15)",
    )
    parser.add_argument(
        "--refresh", "-r", type=float, default=1.0,
        help="[dashboard] Refresh interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=None, metavar="SECONDS",
        help="Auto-stop after N seconds — works with all modes (e.g. --duration 300)",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="Skip JSON export on exit",
    )

    args = parser.parse_args()

    # ── Dependency checks ─────────────────────────────────────────────
    if not SCAPY_AVAILABLE:
        print("❌  scapy not found.  Run:  pip install scapy")
        return
    if args.mode == "dashboard" and not RICH_AVAILABLE:
        print("❌  rich not found.   Run:  pip install rich")
        return

    # ── Startup info ──────────────────────────────────────────────────
    iface = args.interface or "all interfaces"
    if args.mode != "quiet":
        print(
            f"[netscope] mode={args.mode}  interface={iface}  "
            f"enrichment=5-layer  storage=none"
        )

    # ── Wire stop triggers, start capture, run mode ───────────────────
    setup_stop_event(args.duration)
    start_capture(args.interface)
    MODES[args.mode](args)


if __name__ == "__main__":
    main()
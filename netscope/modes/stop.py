# netscope/modes/stop.py
# ─────────────────────────────────────────────────────────────────────
# Shared stop event — wires every possible stop trigger to a single
# threading.Event that all output modes watch.
#
# Stop triggers handled:
#   - Ctrl+C       (KeyboardInterrupt — caught inside each mode)
#   - --duration   (countdown timer thread)
#   - SIGHUP       (SSH disconnect / terminal closed)
#   - SIGTERM      (system shutdown / kill <pid>)
# ─────────────────────────────────────────────────────────────────────

import signal
import threading
from typing import Optional

# Global event — set by any stop trigger, watched by all modes
_stop_event = threading.Event()


def setup_stop_event(duration: Optional[int]) -> None:
    """
    Register signal handlers and start the optional duration timer.
    Call once from main() before launching any output mode.
    """

    def _on_signal(signum, frame):
        _stop_event.set()

    # SIGHUP — SSH session closed or terminal hung up
    try:
        signal.signal(signal.SIGHUP, _on_signal)
    except (OSError, AttributeError):
        pass   # Windows has no SIGHUP

    # SIGTERM — system shutdown or `kill <pid>`
    try:
        signal.signal(signal.SIGTERM, _on_signal)
    except (OSError, AttributeError):
        pass

    # --duration countdown
    if duration:
        def _timer():
            _stop_event.wait(timeout=duration)
            _stop_event.set()
        threading.Thread(target=_timer, daemon=True, name="netscope-timer").start()
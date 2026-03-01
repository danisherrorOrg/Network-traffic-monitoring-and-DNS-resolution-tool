# netscope/state.py
# ─────────────────────────────────────────────────────────────────────
# TrafficState — the single source of truth for all captured traffic.
# Thread-safe, in-memory only. Nothing is ever written to disk here.
#
# All other modules (capture, modes, ui) read from the global `state`
# object at the bottom of this file. Nobody creates their own instance.
# ─────────────────────────────────────────────────────────────────────

import socket
import threading
import time
from collections import defaultdict
from datetime import datetime


class TrafficState:
    """Thread-safe, in-memory traffic accumulator."""

    def __init__(self) -> None:
        self._lock         = threading.Lock()
        self.packet_count: int   = 0
        self.byte_count:   int   = 0
        self.start_time:   float = time.time()

        # Per-remote-IP counters
        self.hosts: dict[str, dict] = defaultdict(lambda: {
            "packets":   0,
            "bytes":     0,
            "sent":      0,
            "received":  0,
            "protocols": set(),
            "last_seen": None,
        })

        # Recent packet ring buffer — capped to avoid unbounded growth
        self.recent:     list[dict] = []
        self.MAX_RECENT: int        = 60

        # Computed once at startup — used to classify IN / OUT direction
        self.local_ips: set[str] = self._get_local_ips()

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _get_local_ips() -> set[str]:
        ips = {"127.0.0.1", "::1"}
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(info[4][0])
        except Exception:
            pass
        return ips

    # ── Write (called from capture thread) ───────────────────────────

    def record(self, src: str, dst: str, proto: str, size: int) -> None:
        """Record one packet. Called from the sniff thread — must be fast."""
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
                "time":      now,
                "src":       src,
                "dst":       dst,
                "protocol":  proto,
                "size":      size,
                "direction": direction,
            })
            if len(self.recent) > self.MAX_RECENT:
                self.recent.pop(0)

    # ── Read (called from UI / export threads) ────────────────────────

    def snapshot(self) -> dict:
        """Return a safe deep-copy for the UI thread to render."""
        with self._lock:
            return {
                "packet_count": self.packet_count,
                "byte_count":   self.byte_count,
                "uptime":       time.time() - self.start_time,
                "hosts": {
                    ip: {**d, "protocols": set(d["protocols"])}
                    for ip, d in self.hosts.items()
                },
                "recent": list(self.recent),
            }


# ── Global singleton ─────────────────────────────────────────────────
# Import this object, never instantiate TrafficState yourself:
#   from netscope.state import state
state = TrafficState()
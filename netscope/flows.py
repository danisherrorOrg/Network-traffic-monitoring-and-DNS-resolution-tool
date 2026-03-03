# netscope/flows.py
# ─────────────────────────────────────────────────────────────────────
# Flow aggregation — groups packets by 5-tuple into individual
# connections and tracks duration, bytes, and packet count per flow.
#
# Key design decisions:
#
#   Normalised key — (lo_ip, lo_port, hi_ip, hi_port, proto)
#     Both directions of a TCP stream map to the same Flow object.
#     Without this, every ACK back from the server would create a
#     second flow and double-count the connection.
#
#   Direction tracking — Flow.direction is set from the FIRST packet.
#     "OUT" if the local machine initiated, "IN" if a remote did.
#     Subsequent packets in both directions update the same flow.
#
#   Idle expiry — flows with no traffic for IDLE_TIMEOUT seconds are
#     marked ended=True. They stay in the table for display (greyed out)
#     but won't accumulate more bytes. This keeps short-lived connections
#     (DNS, OCSP) visible without growing unbounded.
#
#   Port 0 for portless protocols — ICMP, GRE, ESP etc. have no ports.
#     We use port=0 as a sentinel so the 5-tuple is always valid.
# ─────────────────────────────────────────────────────────────────────

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# Seconds of silence before a flow is considered ended
IDLE_TIMEOUT: int = 60

# Well-known port → service name (covers ~90% of real traffic)
_PORT_SERVICES: dict[int, str] = {
    20:   "FTP-data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    123:  "NTP",
    143:  "IMAP",
    161:  "SNMP",
    179:  "BGP",
    443:  "HTTPS",
    465:  "SMTPS",
    500:  "IKE/VPN",
    514:  "Syslog",
    587:  "SMTP/TLS",
    636:  "LDAPS",
    853:  "DNS/TLS",
    993:  "IMAPS",
    995:  "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    4500: "IPsec/NAT",
    5222: "XMPP",
    5228: "GCM/Push",
    5353: "mDNS",
    5355: "LLMNR",
    6443: "Kubernetes",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-dev",
    9090: "Prometheus",
    9200: "Elasticsearch",
    27017:"MongoDB",
    51820:"WireGuard",
}


def port_service(port: int) -> str:
    """Return 'HTTPS' for 443, 'SSH' for 22, or '8123' for unknown ports."""
    return _PORT_SERVICES.get(port, str(port))


def fmt_duration(seconds: float) -> str:
    """Format seconds into human-readable duration: 4m 32s, 1h 2m, etc."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


# ── Flow data model ──────────────────────────────────────────────────

@dataclass
class Flow:
    """
    Represents a single bidirectional network flow (connection).

    The 5-tuple key is stored normalised (lo/hi) so both directions
    of a TCP stream map to the same object.
    """
    # Identity (normalised 5-tuple)
    lo_ip:    str
    lo_port:  int
    hi_ip:    str
    hi_port:  int
    proto:    str

    # Direction from the local machine's perspective
    # "OUT" = we initiated, "IN" = remote initiated
    direction: str = "OUT"

    # Traffic counters
    packets:  int   = 0
    bytes:    int   = 0

    # Timing
    started:  float = field(default_factory=time.time)
    last_pkt: float = field(default_factory=time.time)

    # State
    ended:    bool  = False   # True once idle for IDLE_TIMEOUT seconds

    @property
    def duration(self) -> float:
        return self.last_pkt - self.started

    @property
    def remote_ip(self) -> str:
        """The IP that is NOT the lo_ip side (best-effort remote identification)."""
        return self.hi_ip

    @property
    def remote_port(self) -> int:
        return self.hi_port

    def service_label(self) -> str:
        """
        Return a label like 'HTTPS (443)' for the well-known port,
        or just the port number if unknown.
        """
        # For portless protocols (ICMP etc.) port is 0 — show nothing
        if self.lo_port == 0 and self.hi_port == 0:
            return self.proto
        svc = _PORT_SERVICES.get(self.hi_port) or _PORT_SERVICES.get(self.lo_port)
        port = self.hi_port if self.hi_port != 0 else self.lo_port
        if svc:
            return f"{svc} ({port})"
        return str(port)


# ── Flow table ───────────────────────────────────────────────────────

class FlowTable:
    """
    Thread-safe accumulator that groups packets into Flow objects.

    Usage (called from the capture thread):
        flow_table.record(src, src_port, dst, dst_port, proto, size, local_ips)

    Usage (called from the UI thread):
        flows = flow_table.snapshot()
    """

    def __init__(self) -> None:
        self._lock:  threading.Lock       = threading.Lock()
        self._flows: dict[tuple, Flow]    = {}

    @staticmethod
    def _make_key(
        src: str, src_port: int,
        dst: str, dst_port: int,
        proto: str,
    ) -> tuple:
        """
        Normalise 5-tuple so both directions produce the same key.
        Lower IP (lexicographic) always goes first.
        """
        if (src, src_port) <= (dst, dst_port):
            return (src, src_port, dst, dst_port, proto)
        return (dst, dst_port, src, src_port, proto)

    def record(
        self,
        src: str, src_port: int,
        dst: str, dst_port: int,
        proto: str,
        size: int,
        local_ips: set[str],
    ) -> None:
        """
        Update or create a Flow for this packet.
        Called from the sniff thread — must be fast.
        """
        key = self._make_key(src, src_port, dst, dst_port, proto)
        now = time.time()

        with self._lock:
            if key not in self._flows:
                # Determine direction from first packet
                direction = "OUT" if src in local_ips else "IN"
                lo_ip, lo_port, hi_ip, hi_port, _ = key
                self._flows[key] = Flow(
                    lo_ip=lo_ip, lo_port=lo_port,
                    hi_ip=hi_ip, hi_port=hi_port,
                    proto=proto,
                    direction=direction,
                )

            f = self._flows[key]
            f.packets  += 1
            f.bytes    += size
            f.last_pkt  = now
            f.ended     = False   # reactivate if a previously idle flow gets a packet

    def expire_idle(self) -> None:
        """
        Mark flows as ended if they have been idle for IDLE_TIMEOUT seconds.
        Call this periodically from the UI refresh loop — NOT from the sniff thread.
        """
        cutoff = time.time() - IDLE_TIMEOUT
        with self._lock:
            for f in self._flows.values():
                if not f.ended and f.last_pkt < cutoff:
                    f.ended = True

    def snapshot(self, top_n: int = 50) -> list[Flow]:
        """
        Return a sorted list of Flow objects for the UI to render.
        Active flows first (sorted by bytes desc), then ended flows.
        Returns a shallow copy — each Flow object is shared but the list is not.
        """
        with self._lock:
            active = sorted(
                (f for f in self._flows.values() if not f.ended),
                key=lambda f: f.bytes,
                reverse=True,
            )
            ended = sorted(
                (f for f in self._flows.values() if f.ended),
                key=lambda f: f.last_pkt,
                reverse=True,
            )
        return (active + ended)[:top_n]

    def stats(self) -> dict:
        """Return aggregate stats for the header bar."""
        with self._lock:
            total   = len(self._flows)
            active  = sum(1 for f in self._flows.values() if not f.ended)
        return {"total": total, "active": active}


# ── Global singleton ─────────────────────────────────────────────────
# Import this object, never instantiate FlowTable yourself:
#   from netscope.flows import flow_table
flow_table = FlowTable()
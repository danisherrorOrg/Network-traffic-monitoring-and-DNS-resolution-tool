# netscope/capture/sniffer.py
# ─────────────────────────────────────────────────────────────────────
# Packet capture and protocol detection.
# Runs in a background daemon thread — never blocks the UI.
#
# Two responsibilities:
#   1. detect_protocol(pkt)  — identify what protocol a packet uses
#   2. packet_handler(pkt)   — extract IPs, record to state, feed DNS cache
#   3. start()               — launch the sniff thread
# ─────────────────────────────────────────────────────────────────────

import threading
from typing import Optional

from netscope.protocols import PROTO_NUM_MAP
from netscope.state import state
from netscope.enrichment import dns_cache

# ── Scapy imports (optional — checked at runtime) ────────────────────
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, GRE, ESP, AH, SCTP
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


# ── Protocol detection ───────────────────────────────────────────────

def detect_protocol(pkt) -> str:
    """
    Identify the transport protocol of a packet.
    Order matters — check specific layers before raw proto number fallback.
    """
    if pkt.haslayer(TCP):   return "TCP"
    if pkt.haslayer(UDP):   return "UDP"
    if pkt.haslayer(SCTP):  return "SCTP"
    if pkt.haslayer(ICMP):  return "ICMP"

    # ICMPv6
    if ICMPv6EchoRequest and (
        pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply)
    ):
        return "ICMPv6"
    if pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
        return "ICMPv6"

    # Tunnelling / VPN
    if pkt.haslayer(GRE):  return "GRE"
    if pkt.haslayer(ESP):  return "ESP"
    if pkt.haslayer(AH):   return "AH"

    # IGMP
    if IGMP and pkt.haslayer(IGMP):
        return "IGMP"

    # Raw IP protocol number fallback
    for layer in (IP, IPv6):
        if pkt.haslayer(layer):
            n = pkt[layer].proto if layer is IP else pkt[layer].nh
            if n in PROTO_NUM_MAP:
                return PROTO_NUM_MAP[n]

    return "OTHER"


# ── Port extraction ────────────────────────────────────────────

def extract_ports(pkt) -> tuple[int, int]:
    """
    Return (src_port, dst_port) for the packet.
    Returns (0, 0) for portless protocols (ICMP, GRE, ESP, etc.)
    so the flow 5-tuple is always valid.
    """
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    if pkt.haslayer(SCTP):
        return pkt[SCTP].sport, pkt[SCTP].dport
    return 0, 0


# ── Packet handler ────────────────────────────────────────────

def packet_handler(pkt) -> None:
    """
    Called for every captured packet.
    Feeds the DNS cache, extracts IPs + ports, and records to state.
    Never stores the packet itself.
    """
    # Feed DNS sniff cache (Layer 2 enrichment)
    dns_cache.record_dns_answer(pkt)

    # Extract IP addresses
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return   # Not an IP packet (ARP, 802.1Q …) — skip

    src_port, dst_port = extract_ports(pkt)
    state.record(src, src_port, dst, dst_port, detect_protocol(pkt), len(pkt))


# ── Sniff thread ─────────────────────────────────────────────────────

def _sniff_loop(interface: Optional[str]) -> None:
    """Background worker — runs until process exits."""
    kwargs: dict = dict(prn=packet_handler, store=False)
    if interface:
        kwargs["iface"] = interface
    try:
        sniff(**kwargs)
    except Exception as e:
        print(f"[netscope capture] ERROR: {e}")


def start(interface: Optional[str]) -> None:
    """
    Launch packet capture in a background daemon thread.
    Call once from main() before starting any output mode.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is not installed. Run: pip install scapy")
    threading.Thread(
        target=_sniff_loop,
        args=(interface,),
        daemon=True,
        name="netscope-sniffer",
    ).start()
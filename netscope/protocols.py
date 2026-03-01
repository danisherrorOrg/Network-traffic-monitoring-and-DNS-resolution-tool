# netscope/protocols.py
# ─────────────────────────────────────────────────────────────────────
# Protocol registry — name → (rich_colour, one-line description)
# Used by the capture layer (detect_protocol) and the UI (dashboard/log)
# Add new protocols here without touching anything else.
# ─────────────────────────────────────────────────────────────────────

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

# Raw IP protocol numbers for protocols scapy has no dedicated layer for.
# Used as fallback in detect_protocol().
PROTO_NUM_MAP: dict[int, str] = {
    2:   "IGMP",
    88:  "EIGRP",
    89:  "OSPF",
    103: "PIM",
    112: "VRRP",
}
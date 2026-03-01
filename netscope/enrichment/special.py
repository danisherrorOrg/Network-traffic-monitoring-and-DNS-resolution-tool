# netscope/enrichment/special.py
# ─────────────────────────────────────────────────────────────────────
# Layer 1 — Special / reserved address detection.
# Identifies loopback, private LAN, multicast, link-local, etc.
# instantly with no network calls.
#
# To add a new special prefix, just append to _SPECIAL_PREFIXES below.
# ─────────────────────────────────────────────────────────────────────

import ipaddress

_SPECIAL_PREFIXES: list[tuple[str, str]] = [
    # IPv4
    ("127.",             "Loopback (this machine)"),
    ("0.0.0.0",          "Unspecified address"),
    ("255.255.255.255",  "Broadcast"),
    ("224.",             "Multicast (IPv4)"),
    ("239.",             "Multicast — local scope"),
    ("169.254.",         "Link-local (no DHCP / APIPA)"),
    ("10.",              "Private LAN (10.x)"),
    ("192.168.",         "Private LAN (192.168.x)"),
    # IPv6
    ("::1",              "Loopback (this machine)"),
    ("fe80:",            "Link-local (IPv6)"),
    ("ff02:",            "Multicast — link-scope (IPv6)"),
    ("ff05:",            "Multicast — site-scope (IPv6)"),
    ("fc",               "Unique local — IPv6 private (fc)"),
    ("fd",               "Unique local — IPv6 private (fd)"),
]

_172_NETWORK = ipaddress.ip_network("172.16.0.0/12")


def _is_172_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in _172_NETWORK
    except ValueError:
        return False


def special_label(ip: str) -> str | None:
    """
    Return a human label if the IP is a reserved or special address.
    Returns None if the IP should proceed through the enrichment pipeline.
    """
    ip_lower = ip.lower()
    for prefix, label in _SPECIAL_PREFIXES:
        if ip_lower.startswith(prefix.lower()):
            return label
    if _is_172_private(ip):
        return "Private LAN (172.16.x)"
    return None
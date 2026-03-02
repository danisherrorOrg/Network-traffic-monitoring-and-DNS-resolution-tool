# netscope/enrichment/dns_cache.py
# ─────────────────────────────────────────────────────────────────────
# Layer 2 — DNS sniff cache.
# Intercepts DNS responses your machine receives in real-time and
# builds an ip → queried_domain map.
#
# This means by the time an IP shows up as traffic, we often already
# know its name — without needing a PTR lookup at all.
# ─────────────────────────────────────────────────────────────────────

import threading
from typing import Optional

# ip → domain name seen in a DNS answer
_cache: dict[str, str] = {}
_lock  = threading.Lock()


def record_dns_answer(pkt) -> None:
    """
    Parse a DNS response packet and store ip → domain mappings.
    Called from the packet handler for every packet — must not raise.
    Requires scapy DNS layer to be available (checked by caller).
    """
    try:
        from scapy.all import DNS
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 1:      # responses only, skip queries
            return
        for i in range(dns.ancount):
            ans   = dns.an[i]
            name  = ans.rrname
            if isinstance(name, bytes):
                name = name.decode(errors="replace").rstrip(".")
            rdata = getattr(ans, "rdata", None)
            if not rdata or not isinstance(rdata, str):
                continue
            with _lock:
                # Keep the shortest (most meaningful) domain per IP
                existing = _cache.get(rdata)
                if not existing or len(name) < len(existing):
                    _cache[rdata] = name
    except Exception:
        pass


def lookup(ip: str) -> Optional[str]:
    """Return the domain name we saw in a DNS answer for this IP, or None."""
    with _lock:
        return _cache.get(ip)
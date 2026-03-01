# netscope/enrichment/__init__.py
# ─────────────────────────────────────────────────────────────────────
# Public API for the enrichment package.
# Every other module should only import from here — not from the
# individual layer files directly.
#
# Usage:
#   from netscope.enrichment import enrich_ip
#   display, detail = enrich_ip("2a04:4e42:9::684")
#   # → ("Fastly CDN", "2a04:4e42:9::684")
# ─────────────────────────────────────────────────────────────────────

from netscope.enrichment import dns_cache, friendly, ipv6_prefixes, ptr, special


def enrich_ip(ip: str) -> tuple[str, str]:
    """
    Resolve an IP to the most human-readable name available.

    Runs 5 layers in order — first match wins:
      1. Special/reserved  (loopback, private LAN, multicast …)
      2. DNS sniff cache   (domain seen in a live DNS response)
      3. PTR lookup        (reverse DNS, async)
      4. Friendly mapping  (PTR → "Google", "Akamai CDN" …)
      5. IPv6 prefix table (instant CDN/ISP match for IPv6)

    Returns:
        (display, detail)
        display — best human-readable name, e.g. "Google", "Fastly CDN"
        detail  — PTR hostname or raw IP shown as secondary info
    """
    # Layer 1
    label = special.special_label(ip)
    if label:
        return label, ip

    # Layer 2
    queried = dns_cache.lookup(ip)
    if queried:
        name = friendly.ptr_to_friendly(queried)
        return (name or queried), ip

    # Layer 3 + 4
    ptr_host = ptr.lookup(ip)
    if ptr_host:
        name = friendly.ptr_to_friendly(ptr_host)
        if name:
            return name, ptr_host
        return ptr_host, ip

    # Layer 5
    if ":" in ip:
        name = ipv6_prefixes.lookup(ip)
        if name:
            return name, ip

    return "resolving\u2026", ip


__all__ = ["enrich_ip"]
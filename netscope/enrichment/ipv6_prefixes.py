# netscope/enrichment/ipv6_prefixes.py
# ─────────────────────────────────────────────────────────────────────
# Layer 5 — IPv6 prefix → provider name.
# PTR lookup is often absent or slow for IPv6. This table catches the
# major CDNs and ISPs directly from their published IPv6 allocations,
# with zero network calls.
#
# To add a new provider, append a (prefix, "Name") tuple below.
# Prefixes are matched case-insensitively from the start of the address.
# ─────────────────────────────────────────────────────────────────────

_PREFIXES: list[tuple[str, str]] = [
    # ── CDNs ──────────────────────────────────────────────────────────
    ("2a04:4e42",   "Fastly CDN"),
    ("2a04:4e40",   "Fastly CDN"),
    ("2606:4700",   "Cloudflare"),
    ("2400:cb00",   "Cloudflare"),
    ("2606:2800",   "Akamai CDN"),
    ("2600:1400",   "Akamai CDN"),
    ("2600:1401",   "Akamai CDN"),
    ("2600:1402",   "Akamai CDN"),
    ("2600:1403",   "Akamai CDN"),

    # ── Google ────────────────────────────────────────────────────────
    ("2a00:1450",   "Google"),
    ("2404:6800",   "Google"),
    ("2607:f8b0",   "Google"),
    ("2620:0:1c00", "Google"),
    ("2001:4860",   "Google"),

    # ── Microsoft ─────────────────────────────────────────────────────
    ("2620:1ec:50", "Microsoft Azure"),
    ("2620:1ec:21", "Microsoft Azure"),
    ("2a01:111",    "Microsoft Azure"),

    # ── Amazon ────────────────────────────────────────────────────────
    ("2600:9000",   "Amazon AWS / CloudFront"),
    ("2620:108",    "Amazon AWS"),

    # ── Meta ──────────────────────────────────────────────────────────
    ("2a03:2880",   "Meta / Facebook"),
    ("2620:10d",    "Meta / Facebook"),

    # ── Indian ISPs ───────────────────────────────────────────────────
    ("2405:200",    "Jio / Reliance (India)"),
    ("2405:201",    "Jio / Reliance (India)"),
    ("2401:4900",   "Airtel (India)"),
    ("2402:3a80",   "Airtel (India)"),
    ("2404:a800",   "BSNL (India)"),
    ("2001:e68",    "Tata Communications"),

    # ── Other ─────────────────────────────────────────────────────────
    ("2620:fe",     "APNIC / Research"),
    ("2001:4998",   "Yahoo / Verizon Media"),
]


def lookup(ip: str) -> str | None:
    """
    Match an IPv6 address against known provider prefixes.
    Returns the provider name or None if no match.
    """
    ip_lower = ip.lower()
    for prefix, name in _PREFIXES:
        if ip_lower.startswith(prefix.lower()):
            return name
    return None
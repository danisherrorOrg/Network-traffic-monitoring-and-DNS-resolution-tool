# netscope/enrichment/friendly.py
# ─────────────────────────────────────────────────────────────────────
# Layer 4 — PTR hostname → friendly service name.
# Maps raw PTR strings to human-readable names.
#
# Examples:
#   "pnmaaa-av-in-x08.1e100.net"        → "Google"
#   "g2600-akamaitechnologies.com"       → "Akamai CDN"
#   "server-13-225-103-9.mia3.r.cf.net" → "Cloudflare"
#
# To add a new service, append a (compiled_regex, "Name") tuple below.
# Order matters — first match wins.
# ─────────────────────────────────────────────────────────────────────

import re
from typing import Optional

# (regex_pattern, friendly_name) — first match wins
_RULES: list[tuple[re.Pattern, str]] = [
    # ── Google ────────────────────────────────────────────────────────
    (re.compile(r"1e100\.net",               re.I), "Google"),
    (re.compile(r"googlevideo\.com",          re.I), "Google — YouTube/Video"),
    (re.compile(r"googleapis\.com",           re.I), "Google APIs"),
    (re.compile(r"google\.com",               re.I), "Google"),
    (re.compile(r"gstatic\.com",              re.I), "Google Static CDN"),
    (re.compile(r"googleusercontent",         re.I), "Google User Content"),
    (re.compile(r"ggpht\.com",                re.I), "Google"),

    # ── Akamai ────────────────────────────────────────────────────────
    (re.compile(r"akamaitechnologies\.com",   re.I), "Akamai CDN"),
    (re.compile(r"akamai\.net",               re.I), "Akamai CDN"),
    (re.compile(r"akamaiedge\.net",           re.I), "Akamai CDN"),
    (re.compile(r"akamaihd\.net",             re.I), "Akamai CDN"),

    # ── Fastly ────────────────────────────────────────────────────────
    (re.compile(r"fastly\.net",               re.I), "Fastly CDN"),
    (re.compile(r"fastlylb\.net",             re.I), "Fastly CDN"),

    # ── Cloudflare ────────────────────────────────────────────────────
    (re.compile(r"cloudflare\.com",           re.I), "Cloudflare"),
    (re.compile(r"cloudflare-dns",            re.I), "Cloudflare DNS"),
    (re.compile(r"\.cf\.net",                 re.I), "Cloudflare"),

    # ── Amazon ────────────────────────────────────────────────────────
    (re.compile(r"amazonaws\.com",            re.I), "Amazon AWS"),
    (re.compile(r"cloudfront\.net",           re.I), "Amazon CloudFront CDN"),
    (re.compile(r"awsglobalaccelerator",      re.I), "Amazon AWS"),

    # ── Microsoft ─────────────────────────────────────────────────────
    (re.compile(r"azure(websites|edge|fd)",   re.I), "Microsoft Azure"),
    (re.compile(r"microsoft\.com",            re.I), "Microsoft"),
    (re.compile(r"msftconnecttest",           re.I), "Microsoft Connectivity Check"),
    (re.compile(r"windows\.net",              re.I), "Microsoft Azure"),
    (re.compile(r"office365\.com",            re.I), "Microsoft Office 365"),
    (re.compile(r"msecnd\.net",               re.I), "Microsoft CDN"),
    (re.compile(r"skype\.com",                re.I), "Microsoft Skype"),
    (re.compile(r"teams\.microsoft",          re.I), "Microsoft Teams"),

    # ── Apple ─────────────────────────────────────────────────────────
    (re.compile(r"apple\.com",                re.I), "Apple"),
    (re.compile(r"apple-dns\.net",            re.I), "Apple DNS"),
    (re.compile(r"icloud\.com",               re.I), "Apple iCloud"),
    (re.compile(r"mzstatic\.com",             re.I), "Apple App Store CDN"),

    # ── Meta ──────────────────────────────────────────────────────────
    (re.compile(r"facebook\.com",             re.I), "Meta / Facebook"),
    (re.compile(r"fbcdn\.net",                re.I), "Meta / Facebook CDN"),
    (re.compile(r"instagram\.com",            re.I), "Meta / Instagram"),
    (re.compile(r"whatsapp\.net",             re.I), "Meta / WhatsApp"),

    # ── Twitter / X ───────────────────────────────────────────────────
    (re.compile(r"twitter\.com",              re.I), "X / Twitter"),
    (re.compile(r"twimg\.com",                re.I), "X / Twitter CDN"),

    # ── Streaming ─────────────────────────────────────────────────────
    (re.compile(r"netflix\.com",              re.I), "Netflix"),
    (re.compile(r"nflxvideo\.net",            re.I), "Netflix CDN"),
    (re.compile(r"nflximg\.net",              re.I), "Netflix CDN"),
    (re.compile(r"spotify\.com",              re.I), "Spotify"),
    (re.compile(r"scdn\.co",                  re.I), "Spotify CDN"),

    # ── Productivity ──────────────────────────────────────────────────
    (re.compile(r"zoom\.us",                  re.I), "Zoom"),
    (re.compile(r"slack\.com",                re.I), "Slack"),
    (re.compile(r"slack-edge\.com",           re.I), "Slack CDN"),
    (re.compile(r"github\.com",               re.I), "GitHub"),
    (re.compile(r"githubcopilot\.com",        re.I), "GitHub Copilot"),
    (re.compile(r"githubusercontent",         re.I), "GitHub CDN"),

    # ── Linux / OS updates ────────────────────────────────────────────
    (re.compile(r"ubuntu\.com",               re.I), "Ubuntu"),
    (re.compile(r"snapcraft\.io",             re.I), "Snap / Ubuntu"),
    (re.compile(r"debian\.org",               re.I), "Debian"),

    # ── Time servers ──────────────────────────────────────────────────
    (re.compile(r"ntp\.org",                  re.I), "NTP Time Server"),
    (re.compile(r"pool\.ntp",                 re.I), "NTP Time Server"),
    (re.compile(r"time\.google",              re.I), "Google NTP"),
    (re.compile(r"time\.apple",               re.I), "Apple NTP"),
    (re.compile(r"time\.windows",             re.I), "Windows NTP"),
    (re.compile(r"time\.cloudflare",          re.I), "Cloudflare NTP"),

    # ── Security / PKI ────────────────────────────────────────────────
    (re.compile(r"ocsp\.",                    re.I), "Certificate Status (OCSP)"),
    (re.compile(r"crl\.",                     re.I), "Certificate Revocation (CRL)"),

    # ── Telemetry / Analytics ─────────────────────────────────────────
    (re.compile(r"telemetry",                 re.I), "Telemetry / Analytics"),
    (re.compile(r"analytics",                 re.I), "Analytics Service"),
    (re.compile(r"crashlytics",               re.I), "Firebase Crashlytics"),
    (re.compile(r"firebase",                  re.I), "Google Firebase"),

    # ── Indian ISPs ───────────────────────────────────────────────────
    (re.compile(r"jio",                       re.I), "Jio / Reliance (India)"),
    (re.compile(r"airtel",                    re.I), "Airtel (India)"),
    (re.compile(r"bsnl",                      re.I), "BSNL (India)"),
    (re.compile(r"tata",                      re.I), "Tata Communications"),

    # ── Generic CDN (catch-all, keep last) ────────────────────────────
    (re.compile(r"cdn\.",                     re.I), "CDN (generic)"),
    (re.compile(r"\.cdn\.",                   re.I), "CDN (generic)"),
]


def ptr_to_friendly(ptr: str) -> Optional[str]:
    """
    Map a raw PTR hostname to a human-readable service name.
    Returns None if no rule matches — the raw PTR will be shown instead.
    """
    if not ptr:
        return None
    for pattern, name in _RULES:
        if pattern.search(ptr):
            return name
    return None
# tests/test_enrichment.py
# ─────────────────────────────────────────────────────────────────────
# Unit tests for the enrichment pipeline.
# These tests require NO network access and NO root privileges.
# Run with:  pytest tests/test_enrichment.py
# ─────────────────────────────────────────────────────────────────────

import pytest
from netscope.enrichment import enrich_ip
from netscope.enrichment.special       import special_label
from netscope.enrichment.friendly      import ptr_to_friendly
from netscope.enrichment.ipv6_prefixes import lookup as ipv6_lookup


# ── Layer 1: special_label ───────────────────────────────────────────

class TestSpecialLabel:
    def test_loopback_ipv4(self):
        assert special_label("127.0.0.1") == "Loopback (this machine)"

    def test_loopback_ipv6(self):
        assert special_label("::1") == "Loopback (this machine)"

    def test_private_10(self):
        assert "Private LAN" in special_label("10.0.0.1")

    def test_private_192(self):
        assert "Private LAN" in special_label("192.168.1.100")

    def test_private_172(self):
        assert "Private LAN" in special_label("172.16.0.1")
        assert "Private LAN" in special_label("172.31.255.255")

    def test_172_boundary_not_private(self):
        # 172.15.x is NOT in the 172.16/12 range
        assert special_label("172.15.0.1") is None

    def test_multicast_ipv4(self):
        assert "Multicast" in special_label("224.0.0.1")

    def test_link_local_ipv6(self):
        assert "Link-local" in special_label("fe80::1")

    def test_multicast_ipv6(self):
        assert "Multicast" in special_label("ff02::1")

    def test_public_ip_not_special(self):
        assert special_label("8.8.8.8") is None
        assert special_label("142.250.80.46") is None


# ── Layer 4: ptr_to_friendly ─────────────────────────────────────────

class TestPtrToFriendly:
    def test_google_1e100(self):
        assert ptr_to_friendly("pnmaaa-av-in-x08.1e100.net") == "Google"

    def test_google_youtube(self):
        assert ptr_to_friendly("cache.googlevideo.com") == "Google — YouTube/Video"

    def test_akamai(self):
        assert ptr_to_friendly("a1.akamaitechnologies.com") == "Akamai CDN"
        assert ptr_to_friendly("e1234.akamaiedge.net") == "Akamai CDN"

    def test_cloudflare(self):
        assert ptr_to_friendly("one.one.one.one.cloudflare.com") == "Cloudflare"

    def test_aws(self):
        assert ptr_to_friendly("ec2-1-2-3-4.eu-west-1.compute.amazonaws.com") == "Amazon AWS"

    def test_microsoft(self):
        assert ptr_to_friendly("mail.microsoft.com") == "Microsoft"

    def test_apple(self):
        assert ptr_to_friendly("gateway.icloud.com") == "Apple iCloud"

    def test_ntp(self):
        assert ptr_to_friendly("0.pool.ntp.org") == "NTP Time Server"

    def test_no_match_returns_none(self):
        assert ptr_to_friendly("someunknown.example.xyz") is None

    def test_empty_string_returns_none(self):
        assert ptr_to_friendly("") is None


# ── Layer 5: ipv6_prefix_lookup ──────────────────────────────────────

class TestIPv6PrefixLookup:
    # These are the exact IPs from the user's real traffic output
    def test_fastly(self):
        assert ipv6_lookup("2a04:4e42:9::684") == "Fastly CDN"

    def test_jio_1(self):
        assert ipv6_lookup("2405:201:d033:615c:5411:973a:8162:e870") == "Jio / Reliance (India)"

    def test_jio_2(self):
        assert ipv6_lookup("2405:200:1608:1731::b854:e856") == "Jio / Reliance (India)"

    def test_microsoft_azure(self):
        assert ipv6_lookup("2620:1ec:50::12") == "Microsoft Azure"

    def test_google(self):
        assert ipv6_lookup("2404:6800:4007::200e") == "Google"

    def test_cloudflare(self):
        assert ipv6_lookup("2606:4700::1111") == "Cloudflare"

    def test_unknown_returns_none(self):
        assert ipv6_lookup("2001:db8::1") is None   # documentation range

    def test_case_insensitive(self):
        assert ipv6_lookup("2A04:4E42:9::684") == "Fastly CDN"


# ── Full pipeline: enrich_ip ─────────────────────────────────────────

class TestEnrichIp:
    def test_loopback_short_circuits_at_layer1(self):
        display, detail = enrich_ip("127.0.0.1")
        assert display == "Loopback (this machine)"
        assert detail  == "127.0.0.1"

    def test_ipv6_fastly_resolved_at_layer5(self):
        display, detail = enrich_ip("2a04:4e42:9::684")
        assert display == "Fastly CDN"

    def test_ipv6_jio_resolved_at_layer5(self):
        display, _ = enrich_ip("2405:201:d033:615c::1")
        assert display == "Jio / Reliance (India)"

    def test_unknown_ip_returns_resolving(self):
        # An IP that won't match any layer returns "resolving…"
        display, detail = enrich_ip("203.0.113.1")   # documentation range, no PTR
        assert display in ("resolving\u2026", "resolving...")
        assert detail == "203.0.113.1"

    def test_dns_cache_takes_priority_over_layer5(self):
        """Layer 2 (DNS sniff cache) should win over Layer 5 (prefix table)."""
        from netscope.enrichment import dns_cache
        # Manually seed the DNS cache as if we sniffed a DNS answer
        dns_cache._cache["2606:4700::1111"] = "api.myapp.com"
        display, _ = enrich_ip("2606:4700::1111")
        # Should show the specific domain, not the generic "Cloudflare"
        assert display == "api.myapp.com"
        # Cleanup
        del dns_cache._cache["2606:4700::1111"]
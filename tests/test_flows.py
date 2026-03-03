# tests/test_flows.py
# ─────────────────────────────────────────────────────────────────────
# Unit tests for flow aggregation.
# No network, no root, no scapy required.
# Run with: pytest tests/test_flows.py
# ─────────────────────────────────────────────────────────────────────

import time
import pytest
from netscope.flows import FlowTable, Flow, fmt_duration, port_service, IDLE_TIMEOUT


LOCAL = {"10.0.0.1"}
REMOTE = "8.8.8.8"


@pytest.fixture
def ft():
    return FlowTable()


# ── fmt_duration ─────────────────────────────────────────────────────

class TestFmtDuration:
    def test_seconds(self):
        assert fmt_duration(45) == "45s"

    def test_minutes_and_seconds(self):
        assert fmt_duration(272) == "4m 32s"

    def test_exactly_one_hour(self):
        assert fmt_duration(3600) == "1h 0m"

    def test_hours_and_minutes(self):
        assert fmt_duration(3720) == "1h 2m"

    def test_zero(self):
        assert fmt_duration(0) == "0s"


# ── port_service ─────────────────────────────────────────────────────

class TestPortService:
    def test_https(self):
        assert port_service(443) == "HTTPS"

    def test_ssh(self):
        assert port_service(22) == "SSH"

    def test_dns(self):
        assert port_service(53) == "DNS"

    def test_unknown_returns_port_string(self):
        assert port_service(54321) == "54321"


# ── FlowTable.record ─────────────────────────────────────────────────

class TestFlowTableRecord:
    def test_new_flow_created(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        assert len(ft._flows) == 1

    def test_same_flow_both_directions(self, ft):
        """Both directions of a TCP stream must map to the same flow."""
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        ft.record("8.8.8.8",  443,   "10.0.0.1", 54321, "TCP", 200, LOCAL)
        assert len(ft._flows) == 1

    def test_bytes_accumulate_bidirectionally(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        ft.record("8.8.8.8",  443,   "10.0.0.1", 54321, "TCP", 200, LOCAL)
        flow = list(ft._flows.values())[0]
        assert flow.bytes == 300

    def test_packets_accumulate(self, ft):
        for _ in range(5):
            ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 64, LOCAL)
        flow = list(ft._flows.values())[0]
        assert flow.packets == 5

    def test_direction_out_when_local_initiates(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        flow = list(ft._flows.values())[0]
        assert flow.direction == "OUT"

    def test_direction_in_when_remote_initiates(self, ft):
        ft.record("8.8.8.8", 443, "10.0.0.1", 54321, "TCP", 100, LOCAL)
        flow = list(ft._flows.values())[0]
        assert flow.direction == "IN"

    def test_different_ports_create_different_flows(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443,  "TCP", 100, LOCAL)
        ft.record("10.0.0.1", 54322, "8.8.8.8", 8080, "TCP", 100, LOCAL)
        assert len(ft._flows) == 2

    def test_different_protocols_create_different_flows(self, ft):
        ft.record("10.0.0.1", 5353, "224.0.0.251", 5353, "UDP",  100, LOCAL)
        ft.record("10.0.0.1", 5353, "224.0.0.251", 5353, "TCP",  100, LOCAL)
        assert len(ft._flows) == 2

    def test_portless_protocol_uses_zero(self, ft):
        ft.record("10.0.0.1", 0, "8.8.8.8", 0, "ICMP", 64, LOCAL)
        assert len(ft._flows) == 1
        flow = list(ft._flows.values())[0]
        assert flow.lo_port == 0 and flow.hi_port == 0

    def test_idle_flow_reactivated(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        flow = list(ft._flows.values())[0]
        flow.ended = True   # manually mark ended
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        assert flow.ended is False   # should be reactivated


# ── FlowTable.expire_idle ────────────────────────────────────────────

class TestExpireIdle:
    def test_fresh_flow_not_expired(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        ft.expire_idle()
        flow = list(ft._flows.values())[0]
        assert flow.ended is False

    def test_old_flow_gets_expired(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        flow = list(ft._flows.values())[0]
        # Wind back last_pkt to simulate idleness
        flow.last_pkt = time.time() - IDLE_TIMEOUT - 1
        ft.expire_idle()
        assert flow.ended is True

    def test_already_ended_flow_unchanged(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        flow = list(ft._flows.values())[0]
        flow.ended    = True
        flow.last_pkt = time.time() - IDLE_TIMEOUT - 1
        ft.expire_idle()
        assert flow.ended is True   # still ended, not double-processed


# ── FlowTable.snapshot ───────────────────────────────────────────────

class TestSnapshot:
    def test_active_flows_before_ended(self, ft):
        """Active flows must come before ended flows in snapshot output."""
        ft.record("10.0.0.1", 1111, "1.1.1.1", 443, "TCP", 500, LOCAL)
        ft.record("10.0.0.1", 2222, "2.2.2.2", 80,  "TCP", 100, LOCAL)

        # Mark the larger flow as ended
        flows_list = list(ft._flows.values())
        big = max(flows_list, key=lambda f: f.bytes)
        big.ended = True

        snap = ft.snapshot()
        assert snap[0].ended is False   # active flow first

    def test_active_sorted_by_bytes_desc(self, ft):
        ft.record("10.0.0.1", 1111, "1.1.1.1", 443, "TCP", 100, LOCAL)
        ft.record("10.0.0.1", 2222, "2.2.2.2", 80,  "TCP", 900, LOCAL)
        snap = ft.snapshot()
        assert snap[0].bytes >= snap[1].bytes

    def test_top_n_limits_results(self, ft):
        for port in range(20):
            ft.record("10.0.0.1", 50000 + port, "8.8.8.8", 443, "TCP", 64, LOCAL)
        snap = ft.snapshot(top_n=5)
        assert len(snap) == 5

    def test_snapshot_returns_list(self, ft):
        ft.record("10.0.0.1", 54321, "8.8.8.8", 443, "TCP", 100, LOCAL)
        assert isinstance(ft.snapshot(), list)


# ── Flow.service_label ───────────────────────────────────────────────

class TestFlowServiceLabel:
    def _flow(self, lo_port, hi_port, proto="TCP"):
        return Flow(
            lo_ip="10.0.0.1", lo_port=lo_port,
            hi_ip="8.8.8.8",  hi_port=hi_port,
            proto=proto,
        )

    def test_known_hi_port(self):
        f = self._flow(54321, 443)
        assert "HTTPS" in f.service_label()
        assert "443"   in f.service_label()

    def test_known_lo_port_fallback(self):
        # When hi_port is unknown, should fall back to lo_port
        f = self._flow(22, 54321)
        assert "SSH" in f.service_label()

    def test_unknown_both_ports(self):
        f = self._flow(54321, 54322)
        # Should return the hi_port number as string
        assert "54322" in f.service_label()

    def test_portless_protocol(self):
        f = self._flow(0, 0, proto="ICMP")
        assert f.service_label() == "ICMP"


# ── Flow.duration ────────────────────────────────────────────────────

class TestFlowDuration:
    def test_duration_increases_over_time(self):
        f = Flow(lo_ip="a", lo_port=1, hi_ip="b", hi_port=2, proto="TCP")
        f.started  = time.time() - 10
        f.last_pkt = time.time()
        assert f.duration >= 10


# ── FlowTable.stats ──────────────────────────────────────────────────

class TestFlowTableStats:
    def test_counts_active_and_total(self, ft):
        ft.record("10.0.0.1", 1111, "1.1.1.1", 443, "TCP", 100, LOCAL)
        ft.record("10.0.0.1", 2222, "2.2.2.2", 80,  "TCP", 100, LOCAL)
        # Mark one as ended
        list(ft._flows.values())[0].ended = True
        stats = ft.stats()
        assert stats["total"]  == 2
        assert stats["active"] == 1
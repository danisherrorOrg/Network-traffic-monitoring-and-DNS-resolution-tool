# tests/test_state.py
# ─────────────────────────────────────────────────────────────────────
# Unit tests for TrafficState.
# No network access, no root, no scapy required.
# ─────────────────────────────────────────────────────────────────────

import pytest
from netscope.state import TrafficState


@pytest.fixture
def fresh_state():
    """Return a clean TrafficState for each test."""
    return TrafficState()


class TestTrafficStateRecord:
    def test_packet_count_increments(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("10.0.0.1", "8.8.8.8", "UDP", 64)
        assert fresh_state.packet_count == 1

    def test_byte_count_accumulates(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("10.0.0.1", "8.8.8.8", "UDP", 100)
        fresh_state.record("10.0.0.1", "8.8.8.8", "UDP", 200)
        assert fresh_state.byte_count == 300

    def test_outbound_classified_correctly(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("10.0.0.1", "8.8.8.8", "TCP", 512)
        host = fresh_state.hosts["8.8.8.8"]
        assert host["sent"]     == 512
        assert host["received"] == 0

    def test_inbound_classified_correctly(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("8.8.8.8", "10.0.0.1", "TCP", 1024)
        host = fresh_state.hosts["8.8.8.8"]
        assert host["received"] == 1024
        assert host["sent"]     == 0

    def test_protocol_set_grows(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("10.0.0.1", "1.1.1.1", "TCP", 100)
        fresh_state.record("10.0.0.1", "1.1.1.1", "UDP", 100)
        assert fresh_state.hosts["1.1.1.1"]["protocols"] == {"TCP", "UDP"}

    def test_recent_ring_buffer_capped(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        for i in range(fresh_state.MAX_RECENT + 10):
            fresh_state.record("10.0.0.1", f"1.2.3.{i % 256}", "UDP", 64)
        assert len(fresh_state.recent) == fresh_state.MAX_RECENT


class TestTrafficStateSnapshot:
    def test_snapshot_is_independent_copy(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("10.0.0.1", "8.8.8.8", "UDP", 64)
        snap = fresh_state.snapshot()
        # Mutating the snapshot must not affect state
        snap["hosts"]["8.8.8.8"]["bytes"] = 0
        assert fresh_state.hosts["8.8.8.8"]["bytes"] == 64

    def test_protocols_serialized_as_set(self, fresh_state):
        fresh_state.local_ips = {"10.0.0.1"}
        fresh_state.record("10.0.0.1", "8.8.8.8", "TCP", 64)
        snap = fresh_state.snapshot()
        assert isinstance(snap["hosts"]["8.8.8.8"]["protocols"], set)

    def test_uptime_is_positive(self, fresh_state):
        snap = fresh_state.snapshot()
        assert snap["uptime"] >= 0
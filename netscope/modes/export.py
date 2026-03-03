# netscope/modes/export.py
# ─────────────────────────────────────────────────────────────────────
# Session export — serializes TrafficState + FlowTable to JSON on exit.
# Shared by all output modes so the export format is always consistent.
# ─────────────────────────────────────────────────────────────────────

import json
import time
from typing import Optional

from netscope.state import state
from netscope.flows import flow_table
from netscope.enrichment import enrich_ip
from netscope.enrichment.ptr import get_cache as get_ptr_cache


def export_session(no_export: bool = False) -> Optional[str]:
    """
    Write the current session to a timestamped JSON file.

    Args:
        no_export: if True, skip writing and return None

    Returns:
        File path of the written JSON, or None if skipped.
    """
    if no_export:
        return None

    snap      = state.snapshot()
    ptr_cache = get_ptr_cache()
    flows     = flow_table.snapshot(top_n=10_000)   # export all flows

    data = {
        "packet_count": snap["packet_count"],
        "byte_count":   snap["byte_count"],
        "hosts": {
            ip: {
                **{k: list(v) if isinstance(v, set) else v for k, v in d.items()},
                "hostname": enrich_ip(ip)[0],
                "ptr":      ptr_cache.get(ip, ""),
            }
            for ip, d in snap["hosts"].items()
        },
        "flows": [
            {
                "src":       f.lo_ip,
                "src_port":  f.lo_port,
                "dst":       f.hi_ip,
                "dst_port":  f.hi_port,
                "proto":     f.proto,
                "direction": f.direction,
                "bytes":     f.bytes,
                "packets":   f.packets,
                "duration":  round(f.duration, 2),
                "ended":     f.ended,
                "service":   f.service_label(),
            }
            for f in flows
        ],
        "recent": snap["recent"],
    }

    path = f"netscope_{int(time.time())}.json"
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)

    return path
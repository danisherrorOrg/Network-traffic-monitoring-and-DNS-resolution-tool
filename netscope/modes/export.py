# netscope/modes/export.py
# ─────────────────────────────────────────────────────────────────────
# Session export — serializes TrafficState to a JSON file on exit.
# Shared by all output modes so the export format is always consistent.
# ─────────────────────────────────────────────────────────────────────

import json
import time
from typing import Optional

from netscope.state import state
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

    snap = state.snapshot()
    ptr_cache = get_ptr_cache()

    data = {
        "packet_count": snap["packet_count"],
        "byte_count":   snap["byte_count"],
        "hosts": {
            ip: {
                # Serialize sets to lists for JSON compatibility
                **{k: list(v) if isinstance(v, set) else v for k, v in d.items()},
                "hostname": enrich_ip(ip)[0],
                "ptr":      ptr_cache.get(ip, ""),
            }
            for ip, d in snap["hosts"].items()
        },
        "recent": snap["recent"],
    }

    path = f"netscope_{int(time.time())}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    return path
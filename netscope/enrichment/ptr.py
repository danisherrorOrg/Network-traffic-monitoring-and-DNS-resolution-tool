# netscope/enrichment/ptr.py
# ─────────────────────────────────────────────────────────────────────
# Layer 3 — Async reverse PTR (rDNS) lookup.
# Resolves IPs to hostnames in background threads so the packet
# capture thread is never blocked waiting for DNS responses.
#
# Results feed into Layer 4 (friendly.py) which maps raw PTR strings
# like "pnmaaa-av-in-x08.1e100.net" to human names like "Google".
# ─────────────────────────────────────────────────────────────────────

import socket
import threading

# ip → PTR hostname (empty string means lookup ran but found nothing)
_cache:   dict[str, str] = {}
_lock     = threading.Lock()

# Tracks IPs currently being resolved so we don't fire duplicate threads
_pending: set[str] = set()
_pending_lock = threading.Lock()


def _do_ptr(ip: str) -> None:
    """Background worker — runs in its own daemon thread."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ""
    with _lock:
        _cache[ip] = hostname
    with _pending_lock:
        _pending.discard(ip)


def lookup(ip: str) -> str | None:
    """
    Return the cached PTR hostname for this IP, or None if not yet resolved.
    Automatically schedules a background lookup on the first call per IP.
    """
    with _lock:
        if ip in _cache:
            return _cache[ip] or None   # empty string → None

    # Not cached yet — schedule lookup if not already in flight
    with _pending_lock:
        if ip not in _pending:
            _pending.add(ip)
            threading.Thread(target=_do_ptr, args=(ip,), daemon=True).start()

    return None


def get_cache() -> dict[str, str]:
    """Return a copy of the full PTR cache (used by JSON export)."""
    with _lock:
        return dict(_cache)
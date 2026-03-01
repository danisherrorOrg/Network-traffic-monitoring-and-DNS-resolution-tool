# netscope/modes/__init__.py

from .stop import setup_stop_event
from .runner import MODES
__all__ = ["MODES", "setup_stop_event"]
# netscope/__main__.py
# ─────────────────────────────────────────────────────────────────────
# Makes the package runnable as:
#   python -m netscope          (always works, no install needed)
#   netscope                    (works after: pip install -e .)
#
# main() lives in main.py at the project root so it can also be run as:
#   python main.py              (useful during development)
#
# All three entry points call the same function.
# ─────────────────────────────────────────────────────────────────────

import sys
import os

# Allow running from the repo root without installing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscope.cli import main

if __name__ == "__main__":
    main()
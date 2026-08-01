"""Support `python -m netmalper`."""

import sys

from netmalper.cli import entry

if __name__ == "__main__":
    sys.exit(entry())

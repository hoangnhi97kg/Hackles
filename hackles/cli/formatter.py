"""Custom argparse formatter with ANSI color support"""

import argparse
import sys

from hackles.display.colors import colors


class ColoredHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Argparse formatter that adds ANSI colors to help output"""

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix is None:
            prefix = "usage: "
        if sys.stdout.isatty():
            prefix = f"{colors.BOLD}{prefix}{colors.END}"
        return super()._format_usage(usage, actions, groups, prefix)

    def start_section(self, heading):
        if sys.stdout.isatty() and heading:
            heading = f"{colors.CYAN}{heading}{colors.END}"
        super().start_section(heading)

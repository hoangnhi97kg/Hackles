"""Tool banner display"""

from hackles.display.colors import colors


def print_banner():
    """Print the tool banner"""
    banner = r"""
  _    _            _    _
 | |  | |          | |  | |
 | |__| | __ _  ___| | _| | ___  ___
 |  __  |/ _` |/ __| |/ / |/ _ \/ __|
 | |  | | (_| | (__|   <| |  __/\__ \
 |_|  |_|\__,_|\___|_|\_\_|\___||___/
    """
    print(f"{colors.CYAN}{banner}{colors.END}")

"""Display and formatting utilities for Hackles"""

from hackles.display.colors import Severity, colors


# Lazy imports for modules that require prettytable
def __getattr__(name):
    if name in (
        "print_header",
        "print_subheader",
        "print_warning",
        "print_table",
        "print_node_info",
        "print_severity_summary",
    ):
        from hackles.display import tables

        return getattr(tables, name)
    if name == "print_path":
        from hackles.display.paths import print_path

        return print_path
    if name == "print_banner":
        from hackles.display.banner import print_banner

        return print_banner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "colors",
    "Severity",
    "print_header",
    "print_subheader",
    "print_warning",
    "print_table",
    "print_node_info",
    "print_severity_summary",
    "print_path",
    "print_banner",
]

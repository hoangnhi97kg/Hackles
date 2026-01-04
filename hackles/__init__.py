"""
Hackles - BloodHound CE Quick Win Extractor

A CLI tool for identifying Active Directory attack paths, misconfigurations,
and privilege escalation opportunities from BloodHound Community Edition data.
"""

__version__ = "2.0.0"
__author__ = "Real-Fruit-Snacks"

from hackles.core.config import config
from hackles.display.colors import Severity, colors


# Lazy imports to avoid requiring neo4j at import time
def __getattr__(name):
    if name == "BloodHoundCE":
        from hackles.core.bloodhound import BloodHoundCE

        return BloodHoundCE
    if name == "get_query_registry":
        from hackles.queries import get_query_registry

        return get_query_registry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BloodHoundCE",
    "config",
    "colors",
    "Severity",
    "get_query_registry",
]

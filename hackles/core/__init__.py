"""Core components for Hackles"""

from hackles.core.config import config
from hackles.core.cypher import node_type


# Lazy import BloodHoundCE to avoid requiring neo4j at import time
def __getattr__(name):
    if name == "BloodHoundCE":
        from hackles.core.bloodhound import BloodHoundCE

        return BloodHoundCE
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["BloodHoundCE", "config", "node_type"]

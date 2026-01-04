"""CLI components for Hackles"""


# Lazy import to avoid requiring neo4j at package import time
def __getattr__(name):
    if name == "main":
        from hackles.cli.main import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["main"]

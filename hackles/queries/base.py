"""Query registration base classes and decorator"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, List, Optional

if TYPE_CHECKING:
    from hackles.display.colors import Severity

# Global query registry - populated by @register_query decorator
QUERY_REGISTRY: List["QueryMetadata"] = []


@dataclass
class QueryMetadata:
    """Metadata for a registered query function"""

    name: str
    func: Callable
    category: str
    default: bool
    severity: "Severity"


def register_query(
    name: str, category: str, default: bool = True, severity: Optional["Severity"] = None
):
    """Decorator to register a query function in the global registry.

    Args:
        name: Display name for the query
        category: Category for grouping (e.g., "Privilege Escalation")
        default: Whether query runs by default with -a flag
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    Usage:
        @register_query("Kerberoastable Users", "Privilege Escalation", True, Severity.HIGH)
        def get_kerberoastable(bh, domain=None, severity=None):
            ...
    """

    def decorator(func: Callable) -> Callable:
        from hackles.display.colors import Severity as SeverityEnum

        sev = severity if severity is not None else SeverityEnum.MEDIUM
        QUERY_REGISTRY.append(QueryMetadata(name, func, category, default, sev))
        return func

    return decorator

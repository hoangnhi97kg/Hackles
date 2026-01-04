"""Query registry with auto-discovery from category modules.

This module imports all query category modules, which triggers the
@register_query decorator to populate QUERY_REGISTRY.
"""

from hackles.queries.base import QUERY_REGISTRY, QueryMetadata, register_query

# Import all category modules to trigger decorator registration
# These imports look unused but are required to execute @register_query decorators
from . import acl  # noqa: F401
from . import adcs  # noqa: F401
from . import azure  # noqa: F401
from . import credentials  # noqa: F401
from . import delegation  # noqa: F401
from . import domain  # noqa: F401
from . import exchange  # noqa: F401
from . import groups  # noqa: F401
from . import hygiene  # noqa: F401
from . import lateral  # noqa: F401
from . import misc  # noqa: F401
from . import owned  # noqa: F401
from . import paths  # noqa: F401


def get_query_registry():
    """Return the full query registry as list of tuples for backwards compatibility.

    Returns list of tuples: (name, func, category, default, severity)
    """
    return [(q.name, q.func, q.category, q.default, q.severity) for q in QUERY_REGISTRY]


def get_queries_by_category() -> dict:
    """Return queries grouped by category.

    Returns:
        Dictionary mapping category names to lists of QueryMetadata
    """
    by_category = {}
    for query in QUERY_REGISTRY:
        if query.category not in by_category:
            by_category[query.category] = []
        by_category[query.category].append(query)
    return by_category


def get_query_by_name(name: str) -> QueryMetadata:
    """Get a specific query by its display name.

    Args:
        name: The display name of the query

    Returns:
        QueryMetadata object or None if not found
    """
    for query in QUERY_REGISTRY:
        if query.name == name:
            return query
    return None


__all__ = [
    "QUERY_REGISTRY",
    "QueryMetadata",
    "register_query",
    "get_query_registry",
    "get_queries_by_category",
    "get_query_by_name",
]

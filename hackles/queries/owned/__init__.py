"""Query functions for owned"""

from .owned_group_memberships import get_owned_group_memberships
from .owned_local_admin import get_owned_local_admin
from .owned_principals import get_owned_principals
from .owned_rdp_access import get_owned_rdp_access
from .owned_to_adcs import get_owned_to_adcs
from .owned_to_da_session_chain import get_owned_to_da_session_chain
from .owned_to_dcsync import get_owned_to_dcsync
from .owned_to_high_value import get_owned_to_high_value
from .owned_to_kerberoastable import get_owned_to_kerberoastable
from .owned_to_unconstrained import get_owned_to_unconstrained
from .shortest_paths_to_da import get_shortest_paths_to_da

__all__ = [
    "get_owned_group_memberships",
    "get_owned_local_admin",
    "get_owned_principals",
    "get_owned_rdp_access",
    "get_owned_to_adcs",
    "get_owned_to_da_session_chain",
    "get_owned_to_dcsync",
    "get_owned_to_high_value",
    "get_owned_to_kerberoastable",
    "get_owned_to_unconstrained",
    "get_shortest_paths_to_da",
]

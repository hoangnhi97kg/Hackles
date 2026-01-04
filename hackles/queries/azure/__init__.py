"""Query functions for azure"""

from .aad_connect_servers import get_aad_connect_servers
from .azure_ad_connect_accounts import get_azure_ad_connect_accounts
from .azure_ad_connect_dcsync import get_azure_ad_connect_dcsync

__all__ = [
    "get_aad_connect_servers",
    "get_azure_ad_connect_accounts",
    "get_azure_ad_connect_dcsync",
]

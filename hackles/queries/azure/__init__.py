"""Query functions for azure"""

from .aad_connect_servers import get_aad_connect_servers
from .aadc_server_paths import get_aadc_server_paths
from .azure_ad_connect_accounts import get_azure_ad_connect_accounts
from .azure_ad_connect_dcsync import get_azure_ad_connect_dcsync
from .azure_sp_onprem_admin import get_azure_sp_onprem_admin
from .azure_spns import get_azure_spns
from .hybrid_attack_surface import get_hybrid_attack_surface
from .privileged_sync_targets import get_privileged_sync_targets
from .sync_account_privesc import get_sync_account_privesc

__all__ = [
    "get_aad_connect_servers",
    "get_azure_ad_connect_accounts",
    "get_azure_ad_connect_dcsync",
    "get_aadc_server_paths",
    "get_azure_sp_onprem_admin",
    "get_azure_spns",
    "get_hybrid_attack_surface",
    "get_privileged_sync_targets",
    "get_sync_account_privesc",
]

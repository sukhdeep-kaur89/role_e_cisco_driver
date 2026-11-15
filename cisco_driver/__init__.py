"""Role E - Cisco driver.

Applies and removes temporary IP blocks on a Cisco IOS XE router using RESTCONF.

Main entry points:
    CiscoDriver.block(ip, device, ttl_seconds, alert_id, reason)
    CiscoDriver.unblock(ip, device)
    CiscoDriver.expire_due()
"""

from .driver import CiscoDriver, Result
from .restconf_client import DeviceUnreachable, RestconfClient, RestconfError
from .validation import ValidationError

__all__ = [
    "CiscoDriver",
    "Result",
    "RestconfClient",
    "RestconfError",
    "DeviceUnreachable",
    "ValidationError",
]
__version__ = "1.0.0"

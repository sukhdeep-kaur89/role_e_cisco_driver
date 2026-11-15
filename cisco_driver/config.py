"""Settings, read from environment variables so nothing secret is written in code.

Example (PowerShell):
    $env:RESTCONF_DEVICES  = "R1=https://127.0.0.1:8443"
    $env:RESTCONF_USER     = "admin"
    $env:RESTCONF_PASSWORD = "..."
    $env:RESTCONF_VERIFY   = "mock_certs/cert.pem"   # or "true" / "false"
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Union


def _parse_verify(value: str) -> Union[bool, str]:
    text = value.strip()
    if text.lower() in ("", "1", "true", "yes"):
        return True
    if text.lower() in ("0", "false", "no"):
        return False
    return text  # path to a CA certificate file


def _parse_devices(text: str) -> Dict[str, str]:
    """Turn "R1=https://a:443,R2=https://b:443" into {"R1": "...", "R2": "..."}."""
    devices: Dict[str, str] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, url = part.partition("=")
        if not sep or not name.strip() or not url.strip():
            raise ValueError(f"Bad RESTCONF_DEVICES entry {part!r}; expected NAME=URL")
        devices[name.strip()] = url.strip()
    return devices


@dataclass(frozen=True)
class Settings:
    devices: Dict[str, str]
    username: str
    password: str = field(repr=False)  # never printed
    verify_tls: Union[bool, str] = True
    acl_name: str = "BLOCKLIST"
    timeout: float = 10.0
    max_retries: int = 3
    backoff_base: float = 1.0
    db_path: str = "blocks.db"
    min_ttl: int = 60
    max_ttl: int = 86400
    max_changes_per_minute: int = 10
    max_blocks_per_device: int = 50
    expiry_interval: float = 10.0

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        devices = _parse_devices(env.get("RESTCONF_DEVICES", ""))
        if not devices:
            raise ValueError("RESTCONF_DEVICES is not set (example: R1=https://127.0.0.1:8443)")
        password = env.get("RESTCONF_PASSWORD", "")
        if not password:
            raise ValueError("RESTCONF_PASSWORD is not set")
        return cls(
            devices=devices,
            username=env.get("RESTCONF_USER", "admin"),
            password=password,
            verify_tls=_parse_verify(env.get("RESTCONF_VERIFY", "true")),
            acl_name=env.get("BLOCK_ACL_NAME", "BLOCKLIST"),
            timeout=float(env.get("RESTCONF_TIMEOUT", "10")),
            max_retries=int(env.get("RESTCONF_MAX_RETRIES", "3")),
            backoff_base=float(env.get("RESTCONF_BACKOFF", "1")),
            db_path=env.get("BLOCK_DB_PATH", "blocks.db"),
            min_ttl=int(env.get("BLOCK_MIN_TTL", "60")),
            max_ttl=int(env.get("BLOCK_MAX_TTL", "86400")),
            max_changes_per_minute=int(env.get("BLOCK_MAX_CHANGES_PER_MINUTE", "10")),
            max_blocks_per_device=int(env.get("BLOCK_MAX_PER_DEVICE", "50")),
            expiry_interval=float(env.get("BLOCK_EXPIRY_INTERVAL", "10")),
        )

"""Low-level RESTCONF client for the IOS XE extended ACL.

It only knows how to read an ACL, add rules, and delete one rule.
Every request has a timeout, verifies TLS, and is retried with back-off
(1s, 2s, 4s ...) when the router is unreachable or busy.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, List, Optional, Union
from urllib.parse import quote, urlparse

import requests

log = logging.getLogger(__name__)

NATIVE_PATH = "/restconf/data/Cisco-IOS-XE-native:native"
YANG_JSON = "application/yang-data+json"
HEADERS = {"Accept": YANG_JSON, "Content-Type": YANG_JSON}

# Errors that may go away if we wait: busy / temporarily broken router.
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# IOS XE uses "host" for "source is one host" in an ace-rule. Some releases
# show "host-address"; we accept both when reading.
SOURCE_HOST_KEYS = ("host", "host-address")


class RestconfError(Exception):
    """The router answered with an error, or the answer was not usable."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class DeviceUnreachable(RestconfError):
    """The router did not answer after all retries."""


def deny_rule(seq: int, ip: str) -> dict:
    """ACL line: <seq> deny ip host <ip> any"""
    return {
        "sequence": str(seq),
        "ace-rule": {"action": "deny", "protocol": "ip", "host": ip, "dst-any": [None]},
    }


def permit_any_rule(seq: int) -> dict:
    """ACL line: <seq> permit ip any any  (keeps normal traffic flowing)."""
    return {
        "sequence": str(seq),
        "ace-rule": {"action": "permit", "protocol": "ip", "any": [None], "dst-any": [None]},
    }


def denied_host(rule: dict) -> Optional[str]:
    """If this rule is 'deny ip host X any', return X, otherwise None."""
    ace = rule.get("ace-rule") or {}
    if ace.get("action") != "deny":
        return None
    for key in SOURCE_HOST_KEYS:
        if key in ace:
            return str(ace[key])
    return None


def is_permit_any(rule: dict) -> bool:
    ace = rule.get("ace-rule") or {}
    return ace.get("action") == "permit" and "any" in ace and "dst-any" in ace


class RestconfClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify: Union[bool, str] = True,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        max_backoff: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
        session: Optional[requests.Session] = None,
    ):
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("RESTCONF base URL must look like https://host[:port]")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("RESTCONF base URL must not contain a path or query")
        if verify is False:
            log.warning("TLS certificate verification is OFF for %s (lab use only)", parsed.hostname)
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.max_backoff = max_backoff
        self._auth = (username, password)
        self._sleep = sleep
        self._session = session or requests.Session()

    def __repr__(self) -> str:  # never show the password
        return f"RestconfClient({self.base_url!r}, user={self._auth[0]!r})"

    # ------------------------------------------------------------------ core

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> requests.Response:
        url = self.base_url + path
        last_error = "unknown error"
        for attempt in range(self.max_retries + 1):
            try:
                response = self._session.request(
                    method,
                    url,
                    json=body,
                    headers=HEADERS,
                    auth=self._auth,
                    timeout=self.timeout,
                    verify=self.verify,
                )
            except requests.exceptions.SSLError as exc:
                # A bad certificate will not fix itself, so do not retry.
                raise RestconfError(f"TLS verification failed for {self.base_url}: {exc}") from exc
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_error = type(exc).__name__
            else:
                if response.status_code not in RETRYABLE_STATUS:
                    return response
                last_error = f"HTTP {response.status_code}"

            if attempt < self.max_retries:
                delay = min(self.backoff_base * (2 ** attempt), self.max_backoff)
                log.warning(
                    "%s %s failed (%s); retry %d/%d in %.2fs",
                    method, path, last_error, attempt + 1, self.max_retries, delay,
                )
                self._sleep(delay)

        raise DeviceUnreachable(
            f"{method} {self.base_url}{path} failed after {self.max_retries + 1} attempts ({last_error})"
        )

    @staticmethod
    def _check(response: requests.Response, action: str) -> None:
        if 200 <= response.status_code < 300:
            return
        if response.status_code in (401, 403):
            raise RestconfError(
                f"Router refused the credentials while trying to {action} (HTTP {response.status_code})",
                response.status_code,
            )
        raise RestconfError(
            f"Could not {action}: HTTP {response.status_code} {response.text[:200]}",
            response.status_code,
        )

    @staticmethod
    def _acl_path(acl: str) -> str:
        return f"{NATIVE_PATH}/ip/access-list/extended={quote(acl, safe='')}"

    @staticmethod
    def _acl_body(acl: str, rules: List[dict]) -> dict:
        return {"Cisco-IOS-XE-acl:extended": [{"name": acl, "access-list-seq-rule": rules}]}

    # --------------------------------------------------------------- actions

    def get_acl_rules(self, acl: str) -> Optional[List[dict]]:
        """Return the ACL's rules, or None if the ACL does not exist yet."""
        response = self._request("GET", self._acl_path(acl))
        if response.status_code == 404:
            return None
        self._check(response, "read the ACL")
        try:
            data = response.json()
        except ValueError as exc:
            raise RestconfError("Router returned invalid JSON") from exc
        entries = data.get("Cisco-IOS-XE-acl:extended") if isinstance(data, dict) else None
        if not entries:
            return []
        rules = entries[0].get("access-list-seq-rule", [])
        return list(rules) if isinstance(rules, list) else []

    def create_acl(self, acl: str, rules: List[dict]) -> None:
        """Create a new ACL (PUT). Only used when the ACL does not exist yet."""
        response = self._request("PUT", self._acl_path(acl), self._acl_body(acl, rules))
        self._check(response, "create the ACL")

    def add_rules(self, acl: str, rules: List[dict]) -> None:
        """Merge rules into an existing ACL (PATCH). Same rule twice = no change."""
        response = self._request("PATCH", self._acl_path(acl), self._acl_body(acl, rules))
        self._check(response, "add rules to the ACL")

    def delete_rule(self, acl: str, seq: int) -> bool:
        """Delete one ACL line. Returns False if it was already gone."""
        path = f"{self._acl_path(acl)}/access-list-seq-rule={int(seq)}"
        response = self._request("DELETE", path)
        if response.status_code == 404:
            return False
        self._check(response, "delete the ACL rule")
        return True

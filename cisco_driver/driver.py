"""The Cisco driver: safe block / unblock / expiry on top of RestconfClient.

Rules it follows:
  * read before write  - look at the router first; never add the same block twice
  * verify after write - read again and confirm the rule is really there
  * single hosts only  - never a whole network
  * limits             - max changes per minute and max active blocks per device
  * TTL                - every block has an end time and is removed automatically
  * keep traffic alive - the ACL always ends with "permit ip any any"
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .restconf_client import (
    RestconfClient,
    RestconfError,
    denied_host,
    deny_rule,
    is_permit_any,
    permit_any_rule,
)
from .store import BlockRecord, BlockStore, iso
from .validation import ValidationError, clean_text, validate_ip, validate_name, validate_ttl

log = logging.getLogger(__name__)
audit = logging.getLogger("cisco_driver.audit")


@dataclass
class Result:
    status: str  # blocked | already_blocked | unblocked | not_found | refused | error
    device: str
    ip: str
    message: str = ""
    seq: Optional[int] = None
    expires_at: Optional[float] = None
    duration_ms: float = field(default=0.0)

    @property
    def ok(self) -> bool:
        return self.status in ("blocked", "already_blocked", "unblocked", "not_found")

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "device": self.device,
            "ip": self.ip,
            "seq": self.seq,
            "expires_at": self.expires_at,
            "expires_at_utc": iso(self.expires_at),
            "message": self.message,
            "duration_ms": round(self.duration_ms, 1),
        }


class CiscoDriver:
    def __init__(
        self,
        clients: Dict[str, RestconfClient],
        store: BlockStore,
        *,
        acl_name: str = "BLOCKLIST",
        min_ttl: int = 60,
        max_ttl: int = 86400,
        max_changes_per_minute: int = 10,
        max_blocks_per_device: int = 50,
        first_seq: int = 10,
        seq_step: int = 10,
        last_block_seq: int = 990,
        permit_seq: int = 1000,
        clock: Callable[[], float] = time.time,
    ):
        if not clients:
            raise ValueError("At least one device is needed")
        for name in clients:
            validate_name(name, "device")
        self.clients = dict(clients)
        self.store = store
        self.acl = validate_name(acl_name, "ACL")
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.max_changes_per_minute = max_changes_per_minute
        self.max_blocks_per_device = max_blocks_per_device
        self.first_seq = first_seq
        self.seq_step = seq_step
        self.last_block_seq = last_block_seq
        self.permit_seq = permit_seq
        self._clock = clock
        self._lock = threading.RLock()  # block/unblock/expiry never run at the same time

    @classmethod
    def from_settings(cls, settings, clock: Callable[[], float] = time.time) -> "CiscoDriver":
        clients = {
            name: RestconfClient(
                url,
                settings.username,
                settings.password,
                verify=settings.verify_tls,
                timeout=settings.timeout,
                max_retries=settings.max_retries,
                backoff_base=settings.backoff_base,
            )
            for name, url in settings.devices.items()
        }
        return cls(
            clients,
            BlockStore(settings.db_path),
            acl_name=settings.acl_name,
            min_ttl=settings.min_ttl,
            max_ttl=settings.max_ttl,
            max_changes_per_minute=settings.max_changes_per_minute,
            max_blocks_per_device=settings.max_blocks_per_device,
            clock=clock,
        )

    # ---------------------------------------------------------------- helpers

    def _client(self, device: str) -> RestconfClient:
        validate_name(device, "device")
        if device not in self.clients:
            raise ValidationError(f"Unknown device {device!r}; known: {sorted(self.clients)}")
        return self.clients[device]

    @staticmethod
    def _deny_seqs(rules: List[dict], ip: str) -> List[int]:
        return [int(r["sequence"]) for r in rules if denied_host(r) == ip]

    def _free_seq(self, rules: List[dict]) -> Optional[int]:
        used = {int(r.get("sequence", -1)) for r in rules}
        for seq in range(self.first_seq, self.last_block_seq + 1, self.seq_step):
            if seq not in used:
                return seq
        return None

    def _finish(self, result: Result, started: float) -> Result:
        result.duration_ms = (time.perf_counter() - started) * 1000
        audit.info(json.dumps({"event": "enforcement", **result.to_dict()}))
        return result

    # ------------------------------------------------------------------ block

    def block(self, ip: str, device: str, ttl_seconds: int,
              alert_id: Optional[str] = None, reason: str = "") -> Result:
        """Block one IP on one device for ttl_seconds.

        Raises ValidationError for bad input. Router problems come back as
        Result(status="error") so the caller can decide what to do.
        """
        started = time.perf_counter()
        ip = validate_ip(ip)
        ttl = validate_ttl(ttl_seconds, self.min_ttl, self.max_ttl)
        client = self._client(device)
        alert_id = clean_text(alert_id, 128)
        reason = clean_text(reason, 200)

        with self._lock:
            now = self._clock()
            record = self.store.get_active(device, ip)
            try:
                rules = client.get_acl_rules(self.acl)          # 1. read before write
                acl_exists = rules is not None
                rules = rules or []
                existing = self._deny_seqs(rules, ip)

                if existing and record:                          # 2. already done -> no new rule
                    if alert_id and alert_id == (record.alert_id or ""):
                        # duplicate delivery of the same alert: never extend the TTL again
                        return self._finish(Result(
                            "already_blocked", device, ip,
                            f"Duplicate of alert {alert_id}; IP already blocked, expiry unchanged",
                            seq=existing[0], expires_at=record.expires_at), started)
                    # a new alert (or no alert id given): refresh the lifetime
                    new_expiry = max(record.expires_at, now + ttl)
                    self.store.extend(record.id, new_expiry, alert_id or None)
                    return self._finish(Result(
                        "already_blocked", device, ip, "IP already blocked; expiry refreshed",
                        seq=existing[0], expires_at=new_expiry), started)

                if existing and not record:                      # someone else's rule: do not touch
                    return self._finish(Result(
                        "already_blocked", device, ip,
                        "A deny rule for this IP already exists but was not created by this "
                        "driver; it was left untouched and will not be auto-removed",
                        seq=existing[0]), started)

                refusal = self._check_limits(device, ip, now, record)  # 3. safety limits
                if refusal:
                    return self._finish(refusal, started)

                seq = self._free_seq(rules)
                if seq is None:
                    return self._finish(Result("refused", device, ip, "ACL has no free sequence numbers"), started)

                new_rules = [deny_rule(seq, ip)]
                if not acl_exists:                               # 4. write
                    new_rules.append(permit_any_rule(self.permit_seq))
                    client.create_acl(self.acl, new_rules)
                else:
                    if not any(is_permit_any(r) for r in rules) and self.permit_seq not in {
                            int(r.get("sequence", -1)) for r in rules}:
                        new_rules.append(permit_any_rule(self.permit_seq))
                    client.add_rules(self.acl, new_rules)

                after = client.get_acl_rules(self.acl) or []      # 5. verify after write
                if seq not in self._deny_seqs(after, ip):
                    raise RestconfError("Verification failed: rule not found on router after writing it")

            except RestconfError as exc:
                log.error("Block of %s on %s failed: %s", ip, device, exc)
                return self._finish(Result("error", device, ip, str(exc)), started)

            self.store.record_change(device, now)
            if record:  # rule had vanished from the router (drift): replace the record
                self.store.end(record.id, "replaced", "drift-repair", now)
            new = self.store.add(device, ip, self.acl, seq, alert_id, reason, now, now + ttl)
            message = "Rule re-applied (it had disappeared from the router)" if record else "Blocked"
            return self._finish(Result("blocked", device, ip, message, seq=seq,
                                       expires_at=new.expires_at), started)

    def _check_limits(self, device: str, ip: str, now: float,
                      record: Optional[BlockRecord]) -> Optional[Result]:
        active = self.store.count_active(device) - (1 if record else 0)
        if active >= self.max_blocks_per_device:
            return Result("refused", device, ip,
                          f"Device already has {active} active blocks (limit {self.max_blocks_per_device})")
        recent = self.store.changes_since(device, now - 60)
        if recent >= self.max_changes_per_minute:
            return Result("refused", device, ip,
                          f"Rate limit: {recent} changes on this device in the last minute "
                          f"(limit {self.max_changes_per_minute}); try again shortly")
        return None

    # ---------------------------------------------------------------- unblock

    def unblock(self, ip: str, device: str, by: str = "manual") -> Result:
        """Rollback: remove this driver's block for this IP immediately.

        Only the ACL line this driver created and recorded is deleted. Deny rules
        added by anyone else (e.g. an administrator) are never touched.
        """
        started = time.perf_counter()
        ip = validate_ip(ip)
        self._client(device)
        with self._lock:
            record = self.store.get_active(device, ip)
            return self._finish(self._remove(ip, device, record, by), started)

    def _remove(self, ip: str, device: str, record: Optional[BlockRecord], by: str) -> Result:
        client = self.clients[device]
        now = self._clock()
        try:
            rules = client.get_acl_rules(self.acl) or []
            all_seqs = self._deny_seqs(rules, ip)
            # only the exact line this driver created and recorded may be removed
            seqs = [s for s in all_seqs if record is not None and s == record.seq]
            foreign = [s for s in all_seqs if s not in seqs]
            for seq in seqs:
                client.delete_rule(self.acl, seq)
            if seqs:
                left = self._deny_seqs(client.get_acl_rules(self.acl) or [], ip)
                if any(s in left for s in seqs):
                    raise RestconfError("Verification failed: rule still on router after delete")
        except RestconfError as exc:
            log.error("Unblock of %s on %s failed: %s (will retry later)", ip, device, exc)
            return Result("error", device, ip, str(exc), seq=record.seq if record else None)

        if record:
            self.store.end(record.id, "expired" if by == "ttl" else "removed", by, now)
        if not seqs and not record:
            if foreign:
                return Result(
                    "refused", device, ip,
                    f"A deny rule for this IP exists (seq {foreign[0]}) but was not created by "
                    "this driver; it was left untouched. A network administrator must remove "
                    "it on the router if that is intended.",
                    seq=foreign[0])
            return Result("not_found", device, ip, "No block found for this IP")
        message = "Block expired and was removed" if by == "ttl" else "Block removed"
        if foreign:
            message += f" (a deny rule not created by this driver, seq {foreign[0]}, was left untouched)"
        return Result("unblocked", device, ip, message, seq=seqs[0] if seqs else None)

    # ----------------------------------------------------------------- expiry

    def expire_due(self) -> List[Result]:
        """Remove every block whose TTL has passed. Failed ones stay active and retry next time."""
        results = []
        with self._lock:
            for record in self.store.due(self._clock()):
                started = time.perf_counter()
                results.append(self._finish(
                    self._remove(record.ip, record.device, record, by="ttl"), started))
        return results

    # ------------------------------------------------------------------ views

    def list_active(self) -> List[dict]:
        return [r.to_dict() for r in self.store.list_active()]

    def show_acl(self, device: str) -> Optional[List[dict]]:
        return self._client(device).get_acl_rules(self.acl)

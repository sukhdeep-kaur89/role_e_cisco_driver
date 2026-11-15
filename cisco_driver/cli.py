"""Command line for the Cisco driver.

    python -m cisco_driver block 203.0.113.7 --device R1 --ttl 3600 --reason "ssh brute force"
    python -m cisco_driver unblock 203.0.113.7 --device R1        (rollback)
    python -m cisco_driver list
    python -m cisco_driver history
    python -m cisco_driver show-acl --device R1
    python -m cisco_driver expire                                 (run expiry once)
    python -m cisco_driver worker                                 (run expiry forever)

Settings come from environment variables - see config.py.
Exit codes: 0 = ok, 1 = refused / router error, 2 = bad input or settings.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import List, Optional

from .config import Settings
from .driver import CiscoDriver
from .expiry_worker import ExpiryWorker
from .restconf_client import RestconfError
from .validation import ValidationError


def _print(data) -> None:
    print(json.dumps(data, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cisco_driver", description="Role E - Cisco IOS XE block driver")
    p.add_argument("-v", "--verbose", action="store_true", help="show retry and audit logs")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("block", help="block one IP on a device")
    b.add_argument("ip")
    b.add_argument("--device", required=True)
    b.add_argument("--ttl", type=int, default=3600, help="seconds until the block is removed")
    b.add_argument("--reason", default="")
    b.add_argument("--alert-id", default="")

    u = sub.add_parser("unblock", help="rollback: remove a block now")
    u.add_argument("ip")
    u.add_argument("--device", required=True)

    sub.add_parser("list", help="show active blocks")
    sub.add_parser("history", help="show recent blocks, including removed ones")

    s = sub.add_parser("show-acl", help="read the ACL from the router")
    s.add_argument("--device", required=True)

    sub.add_parser("expire", help="remove expired blocks once")

    w = sub.add_parser("worker", help="keep removing expired blocks (Ctrl+C to stop)")
    w.add_argument("--interval", type=float, default=None)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = Settings.from_env()
        driver = CiscoDriver.from_settings(settings)
    except (ValueError, ValidationError) as exc:
        print(f"Settings error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "block":
            result = driver.block(args.ip, args.device, args.ttl, args.alert_id, args.reason)
            _print(result.to_dict())
            return 0 if result.ok else 1
        if args.command == "unblock":
            result = driver.unblock(args.ip, args.device)
            _print(result.to_dict())
            return 0 if result.ok else 1
        if args.command == "list":
            _print(driver.list_active())
            return 0
        if args.command == "history":
            _print([r.to_dict() for r in driver.store.history()])
            return 0
        if args.command == "show-acl":
            rules = driver.show_acl(args.device)
            _print({"acl": driver.acl, "exists": rules is not None, "rules": rules or []})
            return 0
        if args.command == "expire":
            results = driver.expire_due()
            _print([r.to_dict() for r in results])
            return 0 if all(r.ok for r in results) else 1
        if args.command == "worker":
            worker = ExpiryWorker(driver, args.interval or settings.expiry_interval)
            print(f"Expiry worker running every {worker.interval}s - press Ctrl+C to stop")
            worker.start()
            try:
                while True:
                    worker._stop.wait(3600)
            except KeyboardInterrupt:
                worker.stop()
            return 0
    except ValidationError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2
    except RestconfError as exc:
        print(f"Router error: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.store.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())

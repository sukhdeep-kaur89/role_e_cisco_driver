"""Role E demonstration on the Mock IOS XE router (no real Cisco device needed).

Runs the eight demonstration steps in order:
    1. Start the Mock IOS XE server
    2. Connect the Python driver using RESTCONF over HTTPS
    3. Submit an IP-block request
    4. Show the ACL entry created on the mock router
    5. Check whether the IP is blocked
    6. Demonstrate automatic expiry
    7. Demonstrate manual rollback
    8. Show retry and error handling

Usage:
    python demo/lifecycle_demo.py               # block TTL 15 s, minimum TTL 10 s
    python demo/lifecycle_demo.py --ttl 30      # longer block
    python demo/lifecycle_demo.py --pause       # wait for Enter between steps (live presenting)

The demo uses its own temporary folder (certificate + blocks.db), so it never touches
your normal blocks.db. Its minimum TTL is 10 s so expiry can be watched live;
set BLOCK_MIN_TTL to change it.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests  # noqa: E402

from cisco_driver.driver import CiscoDriver  # noqa: E402
from cisco_driver.expiry_worker import ExpiryWorker  # noqa: E402
from cisco_driver.restconf_client import (  # noqa: E402
    NATIVE_PATH, RestconfClient, RestconfError, deny_rule, denied_host,
)
from cisco_driver.store import BlockStore, iso  # noqa: E402
from cisco_driver.validation import ValidationError  # noqa: E402
from mock_router import MockServer  # noqa: E402

USER = "admin"
PASSWORD = secrets.token_urlsafe(12)   # fresh random password for each demo run
DEVICE = "R1"
ATTACKER = "203.0.113.7"       # step 3-6: blocked, then expires automatically
SECOND = "198.51.100.23"       # step 7: blocked, then rolled back by hand
ADMIN_IP = "192.0.2.77"        # step 7: rule added by an administrator (driver must not delete it)
RETRY_IP = "198.51.100.40"     # step 8
CLEAN_IP = "192.0.2.50"        # never blocked, for comparison

PAUSE = False


def step(number: int, title: str) -> None:
    if PAUSE and number > 1:
        input("\n    (press Enter for the next step)")
    print(f"\n{'=' * 78}\n[{datetime.now():%H:%M:%S}] STEP {number}/8 - {title}\n{'=' * 78}")


def say(text: str) -> None:
    print(f"    {text}")


def result(r) -> None:
    extra = f", expires {iso(r.expires_at)}" if r.expires_at else ""
    say(f"-> {r.status.upper()}: {r.message} (seq={r.seq}{extra}, {r.duration_ms:.0f} ms)")


def router_view(mock: MockServer) -> None:
    """Ask the mock router itself, over HTTPS, for its 'show access-lists' output."""
    text = requests.get(f"{mock.url}/_mock/show", auth=(USER, PASSWORD),
                        verify=str(mock.cert_path), timeout=5).text
    say("Router> show access-lists")
    for line in (text.rstrip().splitlines() or ["(no access lists configured)"]):
        say(f"  {line}")


def check(driver: CiscoDriver, ip: str) -> None:
    """Is this IP blocked? Compare the router with the driver's own record."""
    on_router = [int(r["sequence"]) for r in (driver.show_acl(DEVICE) or []) if denied_host(r) == ip]
    record = driver.store.get_active(DEVICE, ip)
    if on_router and record:
        say(f"{ip:<15} BLOCKED      router: deny at seq {on_router[0]} | "
            f"record: alert {record.alert_id or '-'}, expires {iso(record.expires_at)}")
    elif on_router:
        say(f"{ip:<15} BLOCKED      router: deny at seq {on_router[0]} | record: none "
            "(not created by this driver)")
    else:
        say(f"{ip:<15} NOT BLOCKED  router: no deny rule | record: "
            f"{'active (drift!)' if record else 'none active'}")


def main() -> int:
    global PAUSE
    ap = argparse.ArgumentParser(description="Role E demonstration on the mock IOS XE router")
    ap.add_argument("--ttl", type=int, default=15, help="block lifetime in seconds for step 3")
    ap.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    args = ap.parse_args()
    PAUSE = args.pause

    min_ttl = int(os.environ.get("BLOCK_MIN_TTL", "10"))
    if args.ttl < min_ttl:
        print(f"--ttl {args.ttl} is below the minimum TTL of {min_ttl}s "
              f"(use --ttl {min_ttl} or set BLOCK_MIN_TTL)", file=sys.stderr)
        return 2

    # retry warnings and driver errors are printed in line with the steps
    logging.basicConfig(level=logging.WARNING, stream=sys.stdout,
                        format="    [driver log] %(levelname)s %(message)s")
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # hide the mock's access log
    workdir = Path(tempfile.mkdtemp(prefix="role_e_demo_"))

    # ------------------------------------------------------------------ 1
    step(1, "Start the Mock IOS XE server")
    mock = MockServer(USER, PASSWORD, workdir / "certs").start()
    say(f"Mock IOS XE RESTCONF server running at {mock.url}")
    say("HTTPS with a self-signed certificate, HTTP basic authentication")
    say(f"Certificate: {mock.cert_path.name} (generated for this run in a temporary folder)")

    try:
        # -------------------------------------------------------------- 2
        step(2, "Connect the Python driver using RESTCONF over HTTPS")
        client = RestconfClient(mock.url, USER, PASSWORD, verify=str(mock.cert_path),
                                timeout=3, max_retries=3, backoff_base=0.5)
        driver = CiscoDriver({DEVICE: client}, BlockStore(workdir / "blocks.db"), min_ttl=min_ttl)
        say(f"RESTCONF URL : {mock.url}{NATIVE_PATH}/ip/access-list/extended={driver.acl}")
        say("Content-Type : application/yang-data+json")
        say("TLS          : certificate verified against the mock's cert.pem")
        say(f"Settings     : timeout 3 s, 3 retries, back-off 0.5/1/2 s, min TTL {min_ttl} s")
        rules = driver.show_acl(DEVICE)
        say(f"GET {driver.acl} -> connected; ACL "
            f"{'does not exist yet (HTTP 404)' if rules is None else f'has {len(rules)} rules'}")

        # -------------------------------------------------------------- 3
        step(3, f"Submit an IP-block request ({ATTACKER}, TTL {args.ttl} s)")
        say(f"Alert ALERT-001: SSH brute force from {ATTACKER}")
        blocked_at = time.monotonic()
        result(driver.block(ATTACKER, DEVICE, args.ttl, alert_id="ALERT-001", reason="ssh brute force"))
        say("Same alert delivered a second time (idempotency check):")
        result(driver.block(ATTACKER, DEVICE, args.ttl, alert_id="ALERT-001"))

        # -------------------------------------------------------------- 4
        step(4, "Show the ACL entry created on the mock router")
        router_view(mock)
        entry = next(r for r in driver.show_acl(DEVICE) if denied_host(r) == ATTACKER)
        say("Same entry as RESTCONF JSON (what the driver sent):")
        for line in json.dumps(entry, indent=2).splitlines():
            say(f"  {line}")
        say("Line 1000 'permit ip any any' keeps all other traffic flowing.")

        # -------------------------------------------------------------- 5
        step(5, "Check whether the IP is blocked")
        check(driver, ATTACKER)
        check(driver, CLEAN_IP)

        # -------------------------------------------------------------- 6
        step(6, f"Demonstrate automatic expiry (waiting for the {args.ttl} s TTL)")
        say("Expiry worker started (checks every 1 s) ...")
        started = time.monotonic()
        with ExpiryWorker(driver, interval=1):
            while driver.store.get_active(DEVICE, ATTACKER):
                time.sleep(0.5)
                if time.monotonic() - started > args.ttl + 30:
                    say("!! block did not expire in time")
                    return 1
        say(f"Block removed automatically {time.monotonic() - blocked_at:.1f} s after it was applied")
        router_view(mock)
        check(driver, ATTACKER)
        rec = driver.store.history()[0]
        say(f"Record: status={rec.status}, ended_by={rec.ended_by}")

        # -------------------------------------------------------------- 7
        step(7, "Demonstrate manual rollback")
        say(f"Block {SECOND} for 1 hour (ALERT-002):")
        result(driver.block(SECOND, DEVICE, 3600, alert_id="ALERT-002", reason="port scan"))
        check(driver, SECOND)
        say("Operator decides it was a false positive -> rollback now:")
        result(driver.unblock(SECOND, DEVICE))
        check(driver, SECOND)
        say("Safety: an administrator adds their own deny rule by hand (seq 500).")
        client.add_rules(driver.acl, [deny_rule(500, ADMIN_IP)])
        say(f"Rollback request for {ADMIN_IP}:")
        result(driver.unblock(ADMIN_IP, DEVICE))
        router_view(mock)
        say("The driver only removes rules it created; the admin's rule is untouched.")

        # -------------------------------------------------------------- 8
        step(8, "Show retry and error handling")
        say("8a) Router busy: next 2 replies are HTTP 503 -> retry with back-off, then success")
        mock.state.fail_next(2, 503)
        result(driver.block(RETRY_IP, DEVICE, 3600, alert_id="ALERT-003"))

        say("")
        say("8b) Router keeps failing: 4 x HTTP 503 -> gives up safely, nothing recorded")
        mock.state.fail_next(4, 503)
        r = driver.block("198.51.100.41", DEVICE, 3600, alert_id="ALERT-004")
        result(r)
        check(driver, "198.51.100.41")

        say("")
        say("8c) Invalid requests are rejected before anything is sent to the router")
        for ip, ttl in (("10.0.0.0/8", 3600), ("not-an-ip", 3600), ("127.0.0.1", 3600),
                        (RETRY_IP, 1)):
            try:
                driver.block(ip, DEVICE, ttl)
            except ValidationError as exc:
                say(f"block({ip!r}, ttl={ttl}) -> REJECTED: {exc}")

        say("")
        say("8d) Wrong password -> router refuses, error is reported clearly")
        bad = RestconfClient(mock.url, USER, PASSWORD + "-wrong", verify=str(mock.cert_path), timeout=3)
        try:
            bad.get_acl_rules(driver.acl)
        except RestconfError as exc:
            say(f"-> ERROR: {exc}")

        # ------------------------------------------------------------ end
        print(f"\n{'=' * 78}\n[{datetime.now():%H:%M:%S}] Final state\n{'=' * 78}")
        router_view(mock)
        say("History (driver's SQLite record):")
        for rec in reversed(driver.store.history()):
            say(f"  {rec.ip:<15} seq={rec.seq:<4} {rec.status:<8} by={rec.ended_by or '-'}")
        say("")
        say("Demonstration complete: all 8 steps shown.")
        driver.store.close()
        return 0
    finally:
        mock.stop()


if __name__ == "__main__":
    sys.exit(main())

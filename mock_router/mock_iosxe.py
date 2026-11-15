"""Mock Cisco IOS XE RESTCONF server (for tests and offline demos).

It imitates the part of the real router that Role E uses:
    GET/PUT/PATCH/DELETE  /restconf/data/Cisco-IOS-XE-native:native/ip/access-list/extended=<ACL>
    DELETE                .../extended=<ACL>/access-list-seq-rule=<seq>
with HTTPS, HTTP basic auth and RESTCONF-style JSON errors.

Extra test controls (same login needed):
    POST /_mock/fail   {"count": 2, "status": 503}   next N RESTCONF calls fail
    POST /_mock/delay  {"seconds": 2}                answer slowly (timeout tests)
    POST /_mock/reset
    GET  /_mock/show                                 'show access-lists' style text

Run standalone:
    python -m mock_router --port 8443
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import re
import secrets
import threading
import time
from collections import deque
from hmac import compare_digest
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple
from urllib.parse import unquote

from flask import Flask, Response, jsonify, request
from werkzeug.serving import make_server

YANG_JSON = "application/yang-data+json"
ACL_PATH_RE = re.compile(
    r"^Cisco-IOS-XE-native:native/ip/access-list/extended=([^/]+)(?:/access-list-seq-rule=(\d+))?$"
)


class MockState:
    """Everything the fake router remembers. Thread-safe."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.acls: Dict[str, Dict[int, dict]] = {}
            self.failures: Deque[int] = deque()
            self.delay = 0.0
            self.requests: list = []

    def fail_next(self, count: int, status: int = 503) -> None:
        with self.lock:
            self.failures.extend([status] * count)

    def take_failure(self) -> Optional[int]:
        with self.lock:
            return self.failures.popleft() if self.failures else None

    def count(self, method: Optional[str] = None) -> int:
        with self.lock:
            return sum(1 for m, _ in self.requests if method is None or m == method)

    def show_text(self) -> str:
        """Render like IOS 'show access-lists'."""
        lines = []
        with self.lock:
            for name, rules in sorted(self.acls.items()):
                lines.append(f"Extended IP access list {name}")
                for seq in sorted(rules):
                    lines.append(f"    {seq} {_rule_text(rules[seq])}")
        return "\n".join(lines) + ("\n" if lines else "")


def _rule_text(rule: dict) -> str:
    ace = rule.get("ace-rule", {})
    src = f"host {ace['host']}" if "host" in ace else "any"
    dst = "any" if "dst-any" in ace else f"host {ace.get('dst-host', '?')}"
    return f"{ace.get('action')} {ace.get('protocol')} {src} {dst}"


def _error(status: int, tag: str, message: str) -> Tuple[Response, int]:
    body = {"errors": {"error": [{"error-type": "application", "error-tag": tag, "error-message": message}]}}
    resp = jsonify(body)
    resp.mimetype = YANG_JSON
    return resp, status


def _valid_rule(rule: object) -> bool:
    if not isinstance(rule, dict):
        return False
    seq = rule.get("sequence")
    ace = rule.get("ace-rule")
    if not str(seq).isdigit() or not isinstance(ace, dict):
        return False
    if ace.get("action") not in ("permit", "deny") or ace.get("protocol") != "ip":
        return False
    if "host" in ace:
        try:
            ipaddress.IPv4Address(ace["host"])
        except ValueError:
            return False
    elif "any" not in ace:
        return False
    return True


def create_app(username: str, password: str, state: Optional[MockState] = None) -> Flask:
    app = Flask(__name__)
    state = state or MockState()
    app.config["MOCK_STATE"] = state

    def authorised() -> bool:
        auth = request.authorization
        return bool(
            auth
            and compare_digest(auth.username or "", username)
            and compare_digest(auth.password or "", password)
        )

    @app.route("/restconf/data/<path:subpath>", methods=["GET", "PUT", "PATCH", "DELETE"])
    def restconf(subpath: str):
        with state.lock:
            state.requests.append((request.method, subpath))
        if state.delay:
            time.sleep(state.delay)
        if not authorised():
            return _error(401, "access-denied", "Authentication failed")
        injected = state.take_failure()
        if injected:
            return _error(injected, "resource-denied", "Injected failure (mock)")

        match = ACL_PATH_RE.match(subpath)
        if not match:
            return _error(404, "invalid-value", "Uri path not supported by mock")
        name = unquote(match.group(1))
        seq = int(match.group(2)) if match.group(2) else None

        if request.method == "GET":
            with state.lock:
                if name not in state.acls:
                    return _error(404, "invalid-value", "Uri keypath not found")
                rules = state.acls[name]
                if seq is not None:
                    if seq not in rules:
                        return _error(404, "invalid-value", "Uri keypath not found")
                    body = {"Cisco-IOS-XE-acl:access-list-seq-rule": [rules[seq]]}
                else:
                    body = {"Cisco-IOS-XE-acl:extended": [{
                        "name": name,
                        "access-list-seq-rule": [rules[s] for s in sorted(rules)],
                    }]}
            resp = jsonify(body)
            resp.mimetype = YANG_JSON
            return resp

        if request.method == "DELETE":
            with state.lock:
                if name not in state.acls:
                    return _error(404, "data-missing", "ACL not found")
                if seq is None:
                    del state.acls[name]
                elif seq in state.acls[name]:
                    del state.acls[name][seq]
                else:
                    return _error(404, "data-missing", "Rule not found")
            return "", 204

        # PUT / PATCH
        if seq is not None:
            return _error(405, "operation-not-supported", "Write the whole ACL entry, not one rule")
        if request.mimetype != YANG_JSON:
            return _error(415, "invalid-value", f"Content-Type must be {YANG_JSON}")
        body = request.get_json(silent=True)
        entries = body.get("Cisco-IOS-XE-acl:extended") if isinstance(body, dict) else None
        if not isinstance(entries, list) or len(entries) != 1 or entries[0].get("name") != name:
            return _error(400, "malformed-message", "Body must hold exactly this one ACL")
        rules = entries[0].get("access-list-seq-rule", [])
        if not isinstance(rules, list) or not all(_valid_rule(r) for r in rules):
            return _error(400, "invalid-value", "Invalid access-list-seq-rule")

        with state.lock:
            if request.method == "PATCH" and name not in state.acls:
                return _error(404, "data-missing", "PATCH target does not exist")
            created = name not in state.acls
            if request.method == "PUT":
                state.acls[name] = {}
            for rule in rules:
                state.acls[name][int(rule["sequence"])] = rule
        return "", (201 if created else 204)

    # ---- test controls

    @app.route("/_mock/fail", methods=["POST"])
    def mock_fail():
        if not authorised():
            return _error(401, "access-denied", "Authentication failed")
        data = request.get_json(silent=True) or {}
        state.fail_next(int(data.get("count", 1)), int(data.get("status", 503)))
        return jsonify(ok=True)

    @app.route("/_mock/delay", methods=["POST"])
    def mock_delay():
        if not authorised():
            return _error(401, "access-denied", "Authentication failed")
        state.delay = float((request.get_json(silent=True) or {}).get("seconds", 0))
        return jsonify(ok=True)

    @app.route("/_mock/reset", methods=["POST"])
    def mock_reset():
        if not authorised():
            return _error(401, "access-denied", "Authentication failed")
        state.reset()
        return jsonify(ok=True)

    @app.route("/_mock/show", methods=["GET"])
    def mock_show():
        if not authorised():
            return _error(401, "access-denied", "Authentication failed")
        return Response(state.show_text(), mimetype="text/plain")

    return app


def make_self_signed_cert(directory: Path) -> Tuple[Path, Path]:
    """Create cert.pem/key.pem valid for localhost and 127.0.0.1."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock-iosxe.local")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class MockServer:
    """Runs the mock router over HTTPS in a background thread."""

    def __init__(self, username: str, password: str, cert_dir: Path,
                 host: str = "127.0.0.1", port: int = 0):
        self.state = MockState()
        self.app = create_app(username, password, self.state)
        self.cert_path, self.key_path = make_self_signed_cert(Path(cert_dir))
        self._server = make_server(host, port, self.app, threaded=True,
                                   ssl_context=(str(self.cert_path), str(self.key_path)))
        self.url = f"https://{host}:{self._server.server_port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> "MockServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._thread.join(5)

    def __enter__(self) -> "MockServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Cisco IOS XE RESTCONF server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--user", default="admin")
    parser.add_argument("--cert-dir", default="mock_certs")
    args = parser.parse_args()

    password = os.environ.get("MOCK_ROUTER_PASSWORD") or secrets.token_urlsafe(12)
    server = MockServer(args.user, password, Path(args.cert_dir), args.host, args.port)
    print(f"Mock IOS XE RESTCONF server on {server.url}")
    print("Set these in another terminal (PowerShell):")
    print(f'  $env:RESTCONF_DEVICES  = "R1={server.url}"')
    print(f'  $env:RESTCONF_USER     = "{args.user}"')
    print(f'  $env:RESTCONF_PASSWORD = "{password}"')
    print(f'  $env:RESTCONF_VERIFY   = "{server.cert_path.resolve()}"')
    print("Press Ctrl+C to stop.")
    server.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()

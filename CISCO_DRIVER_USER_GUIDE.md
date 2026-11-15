# Cisco Driver — User Guide

**Component:** Role E, Cisco Driver (`cisco_driver` v1.0.0)
**Router:** Mock Cisco IOS XE server (bundled), reached over RESTCONF (HTTPS)
**Audience:** operators who run the driver, and developers who call it from other components

> **Scope.** Role E works against the bundled **Mock IOS XE server**: a small HTTPS web server that imitates the RESTCONF interface of a real Cisco IOS XE router. All instructions, examples and results in this guide were produced and tested on the mock router. No real Cisco device is used. Notes for a possible future real deployment are kept separately in [Appendix A](#appendix-a--real-cisco-hardware-out-of-scope-untested). They are untested and are not part of the demonstration.

---

## Contents

1. [What the Cisco Driver does](#1-what-the-cisco-driver-does)
2. [Files and software required](#2-files-and-software-required)
3. [How to configure and run it](#3-how-to-configure-and-run-it), including the **8-step demonstration** (§3.4)
4. [How to submit an IP-block request](#4-how-to-submit-an-ip-block-request)
5. [How to check whether an IP has been blocked](#5-how-to-check-whether-an-ip-has-been-blocked)
6. [How temporary blocking and automatic expiry work](#6-how-temporary-blocking-and-automatic-expiry-work)
7. [Common errors and solutions](#7-common-errors-and-solutions)
8. [Quick reference](#8-quick-reference)

[Appendix A: Real Cisco hardware (out of scope, untested)](#appendix-a--real-cisco-hardware-out-of-scope-untested)

---

## 1. What the Cisco Driver does

In one line: **the driver talks to the router safely, applies an IP block, and removes it again when its time runs out.**

When another part of the system raises an alert about a malicious IP address, the driver:

1. **Validates the request.** It accepts only one IPv4 host, a known device and an allowed lifetime (TTL).
2. **Reads before it writes.** It fetches the router's `BLOCKLIST` access list (ACL) over RESTCONF. If the IP is already denied, it adds no second rule (see §4.3 for what happens to the expiry).
3. **Checks safety limits.** These are a maximum number of changes per minute and a maximum number of active blocks per device.
4. **Writes the block.** It adds one ACL line, `<seq> deny ip host <IP> any`.
5. **Verifies after writing.** It reads the ACL again and confirms that the rule is really there.
6. **Records the block** in a local SQLite database (`blocks.db`), with an expiry time and the alert that caused it.
7. **Removes the block** when the TTL passes (only while the expiry worker is running, see §6), or immediately on a manual rollback. In both cases it removes **only rules that the driver itself created**.

### The Mock IOS XE server

The mock router (`mock_router/`) imitates the part of a Cisco IOS XE router that the driver uses:

- **HTTPS** with a self-signed certificate, generated automatically at start-up.
- **HTTP basic authentication** (username and password).
- The RESTCONF paths and JSON format of the Cisco `Cisco-IOS-XE-acl` data model (`application/yang-data+json`).
- RESTCONF-style error replies (401, 404, 400, 503…).
- Test controls that the demo and the tests use to simulate a busy or failing router.
- A `show access-lists`-style text view at `/_mock/show`, so you can see the router's ACL as a network engineer would.

The ACL that the driver builds on the mock router looks like this:

```
Extended IP access list BLOCKLIST
    10 deny ip host 203.0.113.7 any
    20 deny ip host 198.51.100.23 any
    1000 permit ip any any
```

### About `1000 permit ip any any`

Every Cisco ACL ends with an invisible "deny everything" rule. The driver therefore adds `1000 permit ip any any` when it creates the ACL, so that blocking one attacker does not block everyone.

> ⚠️ **This line permits all traffic that was not denied by an earlier line.** It is correct **only** because `BLOCKLIST` is a **dedicated blocklist ACL** whose sole intended policy is "deny these listed hosts, allow everything else". Never point the driver (via `BLOCK_ACL_NAME`) at an ACL that carries other security rules.

### Built-in safety features

| Feature | What it means |
|---|---|
| Single hosts only | Networks such as `10.0.0.0/8` are refused, so a bad alert can never cut off a whole range. |
| Special addresses refused | Addresses that can never be a real traffic source are refused: `0.0.0.0`, loopback, link-local, multicast and the reserved `240.0.0.0/4` block. The exact policy is in §4.1. |
| No duplicate ACL entries | Blocking an already blocked IP never adds a second rule. |
| Duplicate alerts ignored | Re-delivery of the same alert ID does **not** extend the block (§4.3). |
| Ownership-aware removal | Both manual rollback and automatic expiry delete **only** the exact ACL line the driver created and recorded. Rules added by hand are never removed. |
| Retries with back-off | If the router is unreachable or busy (HTTP 429/500/502/503/504), the driver waits 1 s, 2 s, 4 s… (8 s maximum) between attempts. Every request has a timeout. |
| Rate limit | By default, at most **10 changes per device per minute**. |
| Block cap | By default, at most **50 active blocks per device**. |
| Drift repair | If a driver-created rule vanishes from the router while still recorded as active, the next block request for that IP re-applies it. |
| Credentials not logged by the driver | The **driver** reads the router password from an environment variable and never prints or logs it (not in results, errors, audit lines or debug output). The **mock server** is different: it displays its lab credentials at start-up on purpose, so you can connect to it (see the note in §3.3). |
| TLS verified | HTTPS certificates are checked (against the mock's `cert.pem`). Turning verification off logs a warning. |

---

## 2. Files and software required

### 2.1 Software

| Requirement | Version | Notes |
|---|---|---|
| Python | **3.14.4** | The only version that has been tested. Other Python 3 versions have not been verified. |
| `requests` | 2.34.2 | HTTPS / RESTCONF client used by the driver. |
| `flask` | 3.1.3 | Runs the Mock IOS XE server. |
| `cryptography` | 50.0.2 | Generates the mock server's self-signed HTTPS certificate. |
| `pytest`, `bandit`, `pip-audit` | 9.0.3, 1.9.4, 2.9.0 | Development only: tests, security scan, dependency audit. pytest was raised from 8.4.2 to fix PYSEC-2026-1845 (§3.5). |
| `curl.exe` | built into Windows 10/11 | Optional: viewing the router's ACL text during the manual demonstration. |

No Cisco hardware, Cisco software or Packet Tracer is needed.

> Cisco Packet Tracer **cannot** run RESTCONF, so the driver cannot control it. If you want slides showing the same ACL on a simulated router by hand, use `packet_tracer/PACKET_TRACER_LAB.txt`.

### 2.2 Project files

```
role_e_cisco_driver/
├── CISCO_DRIVER_USER_GUIDE.md  ← this guide
├── cisco_driver/               ← the driver itself
│   ├── __init__.py             public API: CiscoDriver, Result, errors
│   ├── __main__.py             lets you run "python -m cisco_driver"
│   ├── cli.py                  command line (block, unblock, list, history, show-acl, expire, worker)
│   ├── config.py               reads settings from environment variables
│   ├── driver.py               block / unblock / expiry logic and safety rules
│   ├── restconf_client.py      HTTPS RESTCONF calls, timeouts, retries with back-off
│   ├── store.py                SQLite record of every block (blocks.db)
│   ├── expiry_worker.py        background job that removes expired blocks
│   └── validation.py           input checks (IP, TTL, device and ACL names)
├── mock_router/                ← Mock IOS XE server
│   ├── __main__.py             "python -m mock_router"
│   └── mock_iosxe.py
├── demo/lifecycle_demo.py      the 8-step demonstration (§3.4)
├── tests/                      96 automated tests (pytest), all against the mock router
├── evidence/                   saved test, security, performance and demo outputs (§3.6)
├── packet_tracer/PACKET_TRACER_LAB.txt   optional manual lab for slides
├── requirements.txt            runtime packages (pinned)
├── requirements-dev.txt        runtime + test/security tools
├── pytest.ini
└── .gitignore                  excludes .venv, blocks.db, mock_certs, .env
```

These are created at runtime and are not committed:

| File / folder | Created by | Purpose |
|---|---|---|
| `blocks.db` | the driver | Records every block, its expiry and how it ended. Expiry and ownership checks depend on it, so protect and back it up (§6.5). |
| `mock_certs/cert.pem`, `key.pem` | the mock server | Self-signed TLS certificate for `localhost` / `127.0.0.1`, created again each time the server starts. |

---

## 3. How to configure and run it

All commands below are for **Windows PowerShell**. `<project-folder>` means the folder where you cloned or copied the project, i.e. the one that **contains** `role_e_cisco_driver`. Run every command from inside `role_e_cisco_driver`.

### 3.1 One-time installation

```powershell
cd <project-folder>\role_e_cisco_driver
py -3.14 -m venv .venv                # skip if .venv already exists
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt   # or requirements.txt for runtime only
```

If PowerShell refuses to run `Activate.ps1`, run this once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 3.2 Settings (environment variables)

The driver reads all settings from environment variables, so no password is ever written in code.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `RESTCONF_DEVICES` | **yes** | — | Devices as `NAME=https://host:port`. For the mock: `R1=https://127.0.0.1:8443` |
| `RESTCONF_PASSWORD` | **yes** | — | Router password (the mock prints it at start-up). |
| `RESTCONF_USER` | no | `admin` | Router username. |
| `RESTCONF_VERIFY` | no | `true` | `true` = check TLS against trusted CAs; a **file path** = trust this certificate file (use the mock's `cert.pem`); `false` = no check. |
| `RESTCONF_TIMEOUT` | no | `10` | Seconds to wait for each request. |
| `RESTCONF_MAX_RETRIES` | no | `3` | Retries after the first attempt (so 4 attempts in total). |
| `RESTCONF_BACKOFF` | no | `1` | First retry delay in seconds; it then doubles (1, 2, 4, capped at 8). |
| `BLOCK_ACL_NAME` | no | `BLOCKLIST` | Name of the **dedicated** blocklist ACL the driver manages. |
| `BLOCK_DB_PATH` | no | `blocks.db` | Location of the SQLite block record. |
| `BLOCK_MIN_TTL` | no | `60` | Shortest allowed block, in seconds. |
| `BLOCK_MAX_TTL` | no | `86400` | Longest allowed block, in seconds (24 h). |
| `BLOCK_MAX_CHANGES_PER_MINUTE` | no | `10` | Rate limit per device. |
| `BLOCK_MAX_PER_DEVICE` | no | `50` | Maximum active blocks per device. |
| `BLOCK_EXPIRY_INTERVAL` | no | `10` | How often, in seconds, the expiry worker checks for expired blocks. |

Device and ACL names must start with a letter and may contain only letters, digits, `_`, `.` and `-` (64 characters maximum). The URL must start with `https://` and must not include a path.

> **Important:** `BLOCK_DB_PATH` defaults to `blocks.db` in the **current folder**. Always run commands from the same folder, or set `BLOCK_DB_PATH` to an absolute path. Otherwise, different terminals will use different databases and will not see each other's blocks.

### 3.3 Start the Mock IOS XE server and connect the driver

**Terminal 1: start the mock router**

```powershell
.\.venv\Scripts\Activate.ps1
$env:MOCK_ROUTER_PASSWORD = "lab-password"     # optional; a random one is generated if not set
python -m mock_router --port 8443
```

It prints the exact settings to copy:

```
Mock IOS XE RESTCONF server on https://127.0.0.1:8443
Set these in another terminal (PowerShell):
  $env:RESTCONF_DEVICES  = "R1=https://127.0.0.1:8443"
  $env:RESTCONF_USER     = "admin"
  $env:RESTCONF_PASSWORD = "lab-password"
  $env:RESTCONF_VERIFY   = "<project-folder>\role_e_cisco_driver\mock_certs\cert.pem"
Press Ctrl+C to stop.
```

**Terminal 2: connect the driver.** Paste the four `$env:` lines, then:

```powershell
.\.venv\Scripts\Activate.ps1
python -m cisco_driver show-acl --device R1
```

```json
{ "acl": "BLOCKLIST", "exists": false, "rules": [] }
```

This answer means the driver reached the mock router over HTTPS, the certificate was verified, and the login was accepted. `"exists": false` is expected before the first block.

> The mock router keeps its ACL **in memory**. Stopping it with Ctrl+C clears the ACL; the next start begins with an empty router.

> 🔑 **About the credentials in this guide.** `admin` / `lab-password` are **demonstration values for the local mock router only**. The mock deliberately prints them, and this guide shows them in plain text (including in the `curl.exe -u admin:lab-password` commands), because they protect nothing but a throw-away test server on `127.0.0.1`. They are **not suitable for any real deployment**:
> - Never reuse `lab-password`, or any password shown in this guide, on a real device.
> - A real router needs a strong, unique password that is never printed, typed into shared commands or shown on slides.
> - Supply it only through `RESTCONF_PASSWORD` (for example from a secrets manager), and never pass it on a command line, where it can end up in shell history.
>
> The scripted demonstration (Option A) avoids even the demo password: it generates a new random one on every run.

### 3.4 The 8-step demonstration

The demonstration shows these eight steps in order:

| # | Step | What the audience sees |
|---|---|---|
| 1 | Start the Mock IOS XE server | HTTPS server running, certificate generated |
| 2 | Connect the Python driver using RESTCONF over HTTPS | RESTCONF URL, TLS verified, first `GET` succeeds |
| 3 | Submit an IP-block request | `BLOCKED` result with sequence number and expiry; a repeated alert creates no duplicate |
| 4 | Show the ACL entry created on the mock router | `show access-lists` output from the router, plus the RESTCONF JSON entry |
| 5 | Check whether the IP is blocked | Router and driver record both say `BLOCKED`; a clean IP says `NOT BLOCKED` |
| 6 | Demonstrate automatic expiry | After the TTL, the rule disappears on its own; record shows `expired` / `ttl` |
| 7 | Demonstrate manual rollback | Rule removed immediately on request; an admin's hand-made rule is protected |
| 8 | Show retry and error handling | Retry with back-off, giving up safely, invalid input rejected, wrong password |

There are two ways to present it.

#### Option A: scripted demonstration (one command, recommended)

```powershell
python demo/lifecycle_demo.py            # about 30 seconds in total
python demo/lifecycle_demo.py --pause    # waits for Enter between steps, for live presenting
python demo/lifecycle_demo.py --ttl 30   # longer block in step 3
```

The script starts its own mock router in a temporary folder, so you do **not** need Terminal 1, and your normal `blocks.db` is not touched. It prints a heading for each of the 8 steps. Abridged output from a real run (full output: `evidence/demo_output.txt`):

```
STEP 1/8 - Start the Mock IOS XE server
    Mock IOS XE RESTCONF server running at https://127.0.0.1:52549
    HTTPS with a self-signed certificate, HTTP basic authentication

STEP 2/8 - Connect the Python driver using RESTCONF over HTTPS
    RESTCONF URL : https://127.0.0.1:52549/restconf/data/Cisco-IOS-XE-native:native/ip/access-list/extended=BLOCKLIST
    TLS          : certificate verified against the mock's cert.pem
    Settings     : timeout 3 s, 3 retries, back-off 0.5/1/2 s, min TTL 10 s
    GET BLOCKLIST -> connected; ACL does not exist yet (HTTP 404)

STEP 3/8 - Submit an IP-block request (203.0.113.7, TTL 15 s)
    -> BLOCKED: Blocked (seq=10, expires 2026-11-14T16:18:56+00:00, 51 ms)
    Same alert delivered a second time (idempotency check):
    -> ALREADY_BLOCKED: Duplicate of alert ALERT-001; IP already blocked, expiry unchanged

STEP 4/8 - Show the ACL entry created on the mock router
    Router> show access-lists
      Extended IP access list BLOCKLIST
          10 deny ip host 203.0.113.7 any
          1000 permit ip any any

STEP 5/8 - Check whether the IP is blocked
    203.0.113.7     BLOCKED      router: deny at seq 10 | record: alert ALERT-001, expires ...
    192.0.2.50      NOT BLOCKED  router: no deny rule | record: none active

STEP 6/8 - Demonstrate automatic expiry (waiting for the 15 s TTL)
    Block removed automatically 16.0 s after it was applied
    203.0.113.7     NOT BLOCKED  router: no deny rule | record: none active
    Record: status=expired, ended_by=ttl

STEP 7/8 - Demonstrate manual rollback
    -> BLOCKED: Blocked (seq=10, ...)
    -> UNBLOCKED: Block removed (seq=10, 33 ms)
    Rollback request for 192.0.2.77:
    -> REFUSED: A deny rule for this IP exists (seq 500) but was not created by this driver; it was left untouched. ...

STEP 8/8 - Show retry and error handling
    8a) Router busy: next 2 replies are HTTP 503 -> retry with back-off, then success
    [driver log] WARNING GET ... failed (HTTP 503); retry 1/3 in 0.50s
    [driver log] WARNING GET ... failed (HTTP 503); retry 2/3 in 1.00s
    -> BLOCKED: Blocked (seq=10, ..., 1559 ms)
    8b) Router keeps failing: 4 x HTTP 503 -> gives up safely, nothing recorded
    -> ERROR: GET ... failed after 4 attempts (HTTP 503)
    8c) Invalid requests are rejected before anything is sent to the router
    block('10.0.0.0/8', ttl=3600) -> REJECTED: Only a single IP address can be blocked, not a network
    block('198.51.100.40', ttl=1) -> REJECTED: TTL must be between 10 and 86400 seconds
    8d) Wrong password -> router refuses, error is reported clearly
    -> ERROR: Router refused the credentials while trying to read the ACL (HTTP 401)

Demonstration complete: all 8 steps shown.
```

**About the retry timing in the demo.** In normal operation, the driver waits **1 s, 2 s, then 4 s** between retries (`RESTCONF_BACKOFF` = 1, doubling each time, with a 10 s timeout per request). To save presentation time, the scripted demo uses a **shorter back-off: 0.5 s, 1 s, 2 s**, with a 3 s timeout, which is why step 8 shows `retry 1/3 in 0.50s` and `retry 2/3 in 1.00s`. The retry logic itself is identical; only the waiting is halved. Step 2 of the demo prints these settings. The manual demonstration (Option B) uses the normal defaults, so its step 8 shows the full 1 s / 2 s / 4 s delays.

**About the TTL in the demo.** In normal use, the minimum TTL is 60 s (`BLOCK_MIN_TTL`). To keep the demonstration short, the scripted demo uses a **10-second minimum** and a **15-second** block. It applies only inside the demo's own temporary environment, and the demo prints both values in step 2. Set `$env:BLOCK_MIN_TTL` to change the demo minimum. If `--ttl` is below the minimum, the demo stops at once with `--ttl 5 is below the minimum TTL of 10s (use --ttl 10 or set BLOCK_MIN_TTL)` and exit code 2.

#### Option B: manual demonstration with the command line

This option uses the real CLI in three terminals and is useful to show each command live. In **Terminals 2 and 3**, paste the four `$env:` lines printed by the mock, **plus** the line below. It lowers the minimum TTL for this demonstration only, so you wait 30 s rather than at least 60 s:

```powershell
$env:BLOCK_MIN_TTL = "10"
```

| # | Terminal | Command | What to point out |
|---|---|---|---|
| 1 | T1 | `$env:MOCK_ROUTER_PASSWORD = "lab-password"`<br>`python -m mock_router --port 8443` | Server running on `https://127.0.0.1:8443`; certificate created in `mock_certs\`. |
| 2 | T2 | `python -m cisco_driver show-acl --device R1` | `"exists": false`: HTTPS connection, certificate and login all work. |
| 3 | T2 | `python -m cisco_driver block 203.0.113.7 --device R1 --ttl 30 --alert-id ALERT-001 --reason "ssh brute force"` | `"status": "blocked"`, `"seq": 10`, `expires_at_utc`. Run it again: `already_blocked`, `expiry unchanged`. |
| 4 | T2 | `python -m cisco_driver show-acl --device R1`<br>`curl.exe -s --cacert mock_certs\cert.pem -u admin:lab-password https://127.0.0.1:8443/_mock/show` | The JSON rule `deny … host 203.0.113.7`, and the router's own `show access-lists` text. |
| 5 | T2 | `python -m cisco_driver list` | The IP is listed as `"status": "active"` with its expiry (§5). |
| 6 | T3 | `python -m cisco_driver worker --interval 2` | Leave it running. About 30 s after step 3, run `list` (now `[]`), `show-acl` (deny line gone) and `history` (`expired`, `ttl`) in T2. |
| 7 | T2 | `python -m cisco_driver block 198.51.100.23 --device R1 --ttl 3600 --alert-id ALERT-002`<br>`python -m cisco_driver unblock 198.51.100.23 --device R1`<br>`python -m cisco_driver history` | The block is created, then removed immediately: `unblocked`, and history shows `removed` / `manual`. |
| 8 | T1 + T2 | (a) Press **Ctrl+C** in T1 to stop the router, then in T2: `python -m cisco_driver block 198.51.100.40 --device R1`<br>(b) `python -m cisco_driver block 10.0.0.0/8 --device R1`<br>(c) Restart the router in T1, then in T2: `$env:RESTCONF_PASSWORD = "wrong"; python -m cisco_driver show-acl --device R1` (afterwards set the correct password again) | (a) Retry warnings at 1 s, 2 s, 4 s, then `"status": "error"`, `failed after 4 attempts`, exit code 1, nothing recorded. This takes about 15 s, so tell the audience it is retrying. (b) `Invalid input: Only a single IP address can be blocked, not a network`, exit code 2. (c) `Router error: Router refused the credentials ... (HTTP 401)`, exit code 1. |

**When the demonstration is finished**, remove the temporary TTL setting in **both Terminal 2 and Terminal 3**:

```powershell
Remove-Item Env:BLOCK_MIN_TTL
```

Otherwise, later commands in those windows keep accepting a 10-second minimum instead of the normal 60 seconds. Closing the terminal windows has the same effect. Option A never changes your terminal's settings, so it needs no clean-up.

> In step 8(a) the router is stopped and cannot answer at all, so the retries end with a connection error. The scripted demo (Option A) can also show a router that is reachable but **busy** (HTTP 503) and then recovers. The CLI has no way to inject that.

### 3.5 Run the tests

```powershell
python -m pytest                          # 96 tests, under a minute, all against the mock router
bandit -r cisco_driver mock_router demo   # static security scan of the project's code
pip-audit -r requirements.txt             # dependency audit 1: runtime packages
pip-audit -r requirements-dev.txt         # dependency audit 2: runtime + development/test tools
```

The two audits answer different questions:
- `requirements.txt` covers what the driver and the mock router need to **run**.
- `requirements-dev.txt` adds the tools used to **test and check** the code (pytest, bandit, pip-audit).

Both are audited, because a vulnerable test tool is still a risk on a developer's or CI machine. The development audit found **PYSEC-2026-1845** in pytest 8.4.2: on Linux and macOS, its use of shared `/tmp/pytest-of-<user>` folders lets a local user cause a denial of service or possibly gain privileges. pytest is now pinned to **9.0.3**, the fixed release, and both audits report no known vulnerabilities.

### 3.6 Evidence files

The `evidence/` folder holds saved results from the current version of the code (regenerated 14 Nov 2026):

| File | Contents | Current result |
|---|---|---|
| `test_results.txt`, `junit_results.xml` | Full pytest run (text and JUnit XML) | **96 passed**, 0 failed |
| `performance_results.txt` | 50 blocks + 50 expiries; slow router with failures | `block()` mean 62.6 ms, p95 82.3 ms; 50 expiries in 2.20 s |
| `bandit_report.txt` | Static security scan of `cisco_driver`, `mock_router`, `demo` | No issues |
| `pip_audit_report.txt` | Dependency audits of **both** `requirements.txt` (runtime) and `requirements-dev.txt` (runtime + development tools), in two labelled sections | No known vulnerabilities in either |
| `demo_output.txt` | Full 8-step demonstration run | All 8 steps completed; block expired 15.8 s after it was applied |
| `installed_packages.txt`, `tool_versions.txt` | Exact environment used | Python 3.14.4, pytest 9.0.3, bandit 1.9.4, pip-audit 2.9.0 |
| `SHA256SUMS.txt` | Checksums of every source file and this guide | Verify with the command below |

To confirm that no file has changed since the evidence was produced, run (Git Bash, from `role_e_cisco_driver`):

```bash
sha256sum -c evidence/SHA256SUMS.txt
```

If you change any code, re-run the tests, demo and scans and regenerate these files, so that the evidence always matches the code.

---

## 4. How to submit an IP-block request

### 4.1 From the command line

```powershell
python -m cisco_driver block <IP> --device <NAME> [--ttl <seconds>] [--reason "<text>"] [--alert-id <id>]
```

| Argument | Required | Default | Notes |
|---|---|---|---|
| `<IP>` | yes | — | One IPv4 host, e.g. `203.0.113.7`. No `/prefix`. |
| `--device` | yes | — | A name from `RESTCONF_DEVICES`, e.g. `R1`. |
| `--ttl` | no | `3600` (1 h) | Block lifetime in seconds; must be between `BLOCK_MIN_TTL` and `BLOCK_MAX_TTL`. |
| `--reason` | no | empty | Free text, stored for the audit trail (200 characters maximum, one line). |
| `--alert-id` | no, but **strongly recommended** | empty | The alert that caused the block (128 characters maximum). Used to recognise duplicate deliveries (§4.3). |

#### Address policy: which IPs can be blocked

| Category | Range | Accepted? | Why |
|---|---|---|---|
| Ordinary public addresses | e.g. `8.8.8.8` | ✅ yes | Normal external attacker sources. |
| Private addresses | single hosts **inside** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, e.g. `10.20.30.40`, `192.168.10.50` | ✅ yes, **one host at a time** | Internal or compromised hosts can also be attackers. |
| **Documentation ranges (RFC 5737)** | single hosts **inside** `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3), e.g. `203.0.113.7` | ✅ yes, **one host at a time, as test fixtures** | See the note below. |
| Unspecified | `0.0.0.0` | ❌ refused | Not a real host. |
| Loopback | `127.0.0.0/8` | ❌ refused | Never arrives over the network. |
| Link-local | `169.254.0.0/16` | ❌ refused | Not routed. |
| Multicast | `224.0.0.0/4` | ❌ refused | Not a single host. |
| Reserved ("Class E"), including broadcast | `240.0.0.0/4`, including `255.255.255.255` | ❌ refused | Not usable as a source. |
| Networks (CIDR notation) | any input containing `/`, e.g. `10.0.0.0/8`, `192.168.10.0/24`, even `203.0.113.7/32` | ❌ refused | Only single hosts, so a bad alert cannot cut off a whole range. |

The **ranges** in the "Range" column describe *where* an address may come from; they are not inputs. Submit one plain host address such as `192.168.10.50`. Typing the range itself (`192.168.0.0/16`) is network notation and is refused like any other CIDR. A host written as `/32` (`192.168.10.50/32`) is refused too: leave the `/32` off.
| IPv6 | e.g. `2001:db8::1` | ❌ refused | The `BLOCKLIST` extended ACL is IPv4 only. |

> **About the example addresses in this guide.** Every address used in this guide, the demonstration and the tests (`203.0.113.7`, `198.51.100.23`, `192.0.2.50`, …) comes from the RFC 5737 **documentation ranges**. These ranges are reserved for use in documentation and examples, and are **not intended to be routed on the public Internet**. Misconfigured networks can still leak them into real traffic, so seeing one is not impossible, only unexpected. In this project they are **test fixtures for the mock environment, not real attacker IPs**.
>
> The driver accepts them on purpose, so that the mock demonstration and the tests never have to use a real person's or company's address. In a production deployment, a block request for one of these addresses would mean that test data has leaked into a live alert feed. Investigate it rather than treat it as a real attack. "Reserved" in the refused list above means only the `240.0.0.0/4` block, not the documentation ranges.
>
> The tests (`tests/test_validation.py`) check this policy explicitly. They confirm that each accepted category, including all three documentation ranges, is accepted, and that each refused category is rejected.

**Example**

```powershell
python -m cisco_driver block 203.0.113.7 --device R1 --ttl 3600 --reason "ssh brute force" --alert-id ALERT-001
```

```json
{
  "status": "blocked",
  "device": "R1",
  "ip": "203.0.113.7",
  "seq": 10,
  "expires_at": 1794671876.08,
  "expires_at_utc": "2026-11-14T15:57:56+00:00",
  "message": "Blocked",
  "duration_ms": 76.9
}
```

### 4.2 Understanding the result

| `status` | Exit code | Meaning |
|---|---|---|
| `blocked` | 0 | New deny rule written and verified on the router. |
| `already_blocked` | 0 | The IP was already denied. **No new ACL entry was created.** The expiry may or may not have changed; read the `message` and see §4.3. |
| `refused` | 1 | A safety limit stopped the request (rate limit, block cap, or no free ACL sequence numbers). Nothing was changed. |
| `error` | 1 | The router could not be reached or rejected the change. Nothing was recorded; you can safely retry. |
| *(text on stderr)* | 2 | Bad input or bad settings, e.g. `Invalid input: ...` or `Settings error: ...`. |

Add `-v` before the command (`python -m cisco_driver -v block ...`) to also see the audit log lines.

### 4.3 Repeated requests: ACL idempotency vs. expiry refresh

Two different behaviours apply when a block request arrives for an IP that is already blocked:

1. **The ACL change is idempotent.** Repeating a request never creates another ACL entry. The router keeps exactly one deny line for that IP, no matter how many times it is requested.
2. **The block lifetime can change.** Whether it does depends on the alert ID:

| Repeated request | ACL | Expiry | `message` |
|---|---|---|---|
| **Same `--alert-id`** as the one recorded (a duplicate delivery of the same alert) | unchanged | **unchanged**, never extended | `Duplicate of alert ALERT-001; IP already blocked, expiry unchanged` |
| **Different `--alert-id`** (a new, separately approved alert) | unchanged | **refreshed** to `max(current expiry, now + new TTL)`; the new alert ID is recorded | `IP already blocked; expiry refreshed` |
| **No `--alert-id`** | unchanged | **refreshed** (duplicates cannot be detected without an ID) | `IP already blocked; expiry refreshed` |
| Rule exists on the router but was **not created by the driver** | unchanged | none; the rule is left alone and never auto-removed | `...was not created by this driver; it was left untouched...` |

**Example.** At 10:00, ALERT-001 blocks an IP for 60 minutes, so it expires at 11:00.
- At 10:10, ALERT-001 is delivered again → still expires at **11:00**.
- At 10:10, a new ALERT-002 arrives with a 60-minute TTL → now expires at **11:10**.

The expiry is never shortened by a repeated request. Use `unblock` to end a block early.

> **For integrators:** always pass the alert ID. Without it, a message queue that re-delivers the same alert would keep extending the block.

### 4.4 From Python (for other components)

```python
from cisco_driver.config import Settings
from cisco_driver.driver import CiscoDriver
from cisco_driver.validation import ValidationError

driver = CiscoDriver.from_settings(Settings.from_env())
try:
    result = driver.block("203.0.113.7", device="R1", ttl_seconds=3600,
                          alert_id="ALERT-001", reason="ssh brute force")
    if result.ok:
        print("Enforced:", result.status, "seq", result.seq, "until", result.to_dict()["expires_at_utc"])
    else:
        print("Not enforced:", result.status, result.message)   # refused / error
except ValidationError as exc:
    print("Rejected input:", exc)
finally:
    driver.store.close()
```

- Bad input raises `ValidationError`.
- Router problems **do not raise**. They come back as `Result(status="error")`, so the caller decides whether to retry.
- `result.ok` is `True` for `blocked`, `already_blocked`, `unblocked` and `not_found`.
- Every action writes one JSON line to the `cisco_driver.audit` logger (`{"event": "enforcement", ...}`), which can be forwarded to a SIEM.

### 4.5 Removing a block early (manual rollback)

```powershell
python -m cisco_driver unblock 203.0.113.7 --device R1
```

Manual rollback is **ownership-aware**, exactly like automatic expiry. It deletes only the ACL line that **this driver created and recorded** in `blocks.db` for that IP. Deny rules that someone else added, for example an administrator protecting a server, are **never** deleted.

| `status` | Exit code | Meaning |
|---|---|---|
| `unblocked` | 0 | The driver's rule was deleted from the router; the record is marked `removed`, `ended_by = manual`. If a hand-added rule for the same IP also exists, the message says it `was left untouched`. |
| `not_found` | 0 | There was nothing to remove (safe to repeat). |
| `refused` | 1 | A deny rule for this IP exists but was **not created by the driver**, so it was left in place. A network administrator must remove it on the router if that is intended. |
| `error` | 1 | Router not reachable; the block stays active. Try again. |

There is deliberately **no** "force" option to delete hand-added rules. Removing a rule the driver does not own is an administrator decision, made under the organisation's normal change control.

---

## 5. How to check whether an IP has been blocked

There are two sources of truth: the driver's record and the router itself. A properly blocked IP appears in **both**.

### 5.1 What the driver has recorded: `list`

```powershell
python -m cisco_driver list
```

This shows every **active** driver-created block, soonest expiry first:

```json
[
  {
    "id": 1,
    "device": "R1",
    "ip": "203.0.113.7",
    "acl": "BLOCKLIST",
    "seq": 10,
    "alert_id": "ALERT-001",
    "reason": "ssh brute force",
    "status": "active",
    "created_at_utc": "2026-11-14T15:56:56+00:00",
    "expires_at_utc": "2026-11-14T15:57:56+00:00",
    "ended_at_utc": null,
    ...
  }
]
```

An IP is blocked by the driver if it appears here with `"status": "active"`. An empty list `[]` means there are no active driver blocks. `alert_id` shows the most recent alert that applied or refreshed the block.

To check a single IP quickly in PowerShell:

```powershell
python -m cisco_driver list | ConvertFrom-Json | Where-Object ip -eq "203.0.113.7"
```

### 5.2 What is really on the router: `show-acl`

```powershell
python -m cisco_driver show-acl --device R1
```

```json
{
  "acl": "BLOCKLIST",
  "exists": true,
  "rules": [
    { "sequence": "10",   "ace-rule": { "action": "deny",   "protocol": "ip", "host": "203.0.113.7", "dst-any": [null] } },
    { "sequence": "1000", "ace-rule": { "action": "permit", "protocol": "ip", "any": [null],          "dst-any": [null] } }
  ]
}
```

The IP is blocked on the router if a rule shows `"action": "deny"` with `"host": "<IP>"`.

The mock router can also show its ACL the way a Cisco engineer would read it (`show access-lists`):

```powershell
curl.exe -s --cacert mock_certs\cert.pem -u admin:<password> https://127.0.0.1:8443/_mock/show
```

```
Extended IP access list BLOCKLIST
    10 deny ip host 203.0.113.7 any
    1000 permit ip any any
```

### 5.3 Past blocks: `history`

```powershell
python -m cisco_driver history
```

This shows the last 50 blocks, newest first, including finished ones. The `status` and `ended_by` fields explain how each one ended:

| `status` | `ended_by` | Meaning |
|---|---|---|
| `active` | — | Still in force. |
| `expired` | `ttl` | Removed automatically when its TTL passed. |
| `removed` | `manual` | Removed by an operator with `unblock`. |
| `replaced` | `drift-repair` | The rule had vanished from the router and was re-applied under a new record. |

### 5.4 If the two views disagree

| `list` says | Router says | What it means / what to do |
|---|---|---|
| active | deny rule present | Normal. |
| active | no rule | The rule was deleted on the router (drift), or the mock router was restarted (its ACL is in memory). Run the same `block` command again with a **new** alert ID; the driver re-applies it. |
| not listed | deny rule present | A rule added by hand or by another system. The driver will neither expire nor unblock it. |

---

## 6. How temporary blocking and automatic expiry work

> ⚠️ **Automatic expiry only happens while an expiry process is running.**
> The TTL is enforced **by the driver, not by the router.** The router has no idea a block is temporary. If neither the `worker` nor a scheduled `expire` command is running, **expired blocks stay on the router indefinitely**, until an expiry process runs again. See §6.2.

### 6.1 The lifecycle

```
 alert ──► block(ip, ttl, alert_id) ──► rule on router + record in blocks.db
                                  │       expires_at = now + ttl
                                  │
          same alert again ───────┤   no new rule, expiry unchanged
          new alert ──────────────┤   no new rule, expiry pushed later
                                  │
          (operator) unblock ─────┤──► driver's rule deleted, status = removed
                                  │
          expiry worker ──────────┘──► when now ≥ expires_at:
          (must be running)             driver's rule deleted, status = expired
```

1. Every block **must** have a TTL. The default is 3600 s; the allowed range is `BLOCK_MIN_TTL` (60 s) to `BLOCK_MAX_TTL` (86 400 s = 24 h).
2. The creation time and end time (`expires_at`) are stored in `blocks.db`. The database is on disk, so pending expiries survive a restart of the PC or the driver. They are processed as soon as an expiry process runs again.
3. The **expiry worker** checks the database every `BLOCK_EXPIRY_INTERVAL` seconds (10 by default) and handles each block whose time has passed.
4. For each expired block, the worker:
   - reads the ACL from the router,
   - deletes **only the exact sequence number the driver recorded** for that IP,
   - reads the ACL again to confirm the rule is gone,
   - marks the record `expired` with `ended_by = ttl`.
5. If the router cannot be reached at that moment, the block **stays active** in the database and is retried on the next check. A block can never be "forgotten".
6. Line `1000 permit ip any any` is never removed, so normal traffic keeps flowing when the ACL holds no deny rules.

### 6.2 Running the expiry process (required)

Choose **one** of these and keep it running for as long as blocks exist. Use the same settings and the same `BLOCK_DB_PATH` as the terminal you block from.

**Option 1: run the worker continuously (recommended)**

```powershell
python -m cisco_driver worker                 # checks every BLOCK_EXPIRY_INTERVAL seconds
python -m cisco_driver worker --interval 5    # or choose the interval
```

```
Expiry worker running every 10.0s - press Ctrl+C to stop
```

Keep this terminal open. Closing it or pressing Ctrl+C stops automatic expiry.

**Option 2: run expiry once on a schedule, e.g. Windows Task Scheduler every minute**

```powershell
python -m cisco_driver expire
```

This prints the blocks it removed (`[]` if none were due). Exit code 1 means at least one removal failed and will be retried next time. With this option, blocks are removed up to one schedule interval late.

**Option 3: inside another Python program**

```python
from cisco_driver.expiry_worker import ExpiryWorker

with ExpiryWorker(driver, interval=10):   # background thread; stops when this block ends
    run_the_rest_of_the_application()
```

The worker survives errors: if one check fails, it logs the error and tries again at the next interval.

To check that expiry is working, run `python -m cisco_driver list`. No `expires_at_utc` should be more than one check interval in the past.

### 6.3 Timing to expect

A block is removed between `ttl` and `ttl + interval` seconds after it was applied, plus the time the router takes to answer. In the recorded demonstration (`evidence/demo_output.txt`: 15-second block, 1-second check interval), the block was removed **15.8 s** after it was applied. In the performance test (`evidence/performance_results.txt`), `expire_due()` removed 50 blocks in **2.20 s**.

### 6.4 Extending or ending a block

- **Extend:** send a block request with a **new** alert ID and the desired TTL (§4.3). Re-sending the same alert ID does not extend it.
- **End early:** `unblock` (§4.5).

### 6.5 Protecting and backing up `blocks.db`

`blocks.db` is the driver's **memory of which ACL rules it owns**. Every automatic expiry and every manual rollback starts by looking up the block's record. If the database is lost or damaged:

- rules that the driver created stay on the router, but with no record they are treated as **foreign rules**;
- they will then **never expire automatically**, and `unblock` will **refuse** to remove them (§4.5);
- an administrator would have to find and remove them by hand.

So treat `blocks.db` as operational data: back it up, restrict access to it, and restore it with care.

> In the mock demonstration this matters less: the mock router forgets its ACL whenever it stops, and Option A uses a throw-away database. The guidance below is for any longer-running use.

#### 0. Find the database file that is actually in use

The driver uses whatever file `BLOCK_DB_PATH` points to. If `BLOCK_DB_PATH` is **not** set, it uses `blocks.db` in the folder the commands are run from. **Back up and restore that exact file**, not just any `blocks.db` you can find. The commands below work this out for you. Run them in the **same terminal, with the same settings and from the same folder** as the driver and the worker:

```powershell
$db = if ($env:BLOCK_DB_PATH) { $env:BLOCK_DB_PATH } else { "blocks.db" }
"Database in use: $db"
```

- With the default, this prints `Database in use: blocks.db`, which is the file in `role_e_cisco_driver`.
- With a custom path, for example `$env:BLOCK_DB_PATH = "D:\driver-data\blocks.db"`, it prints that path. Every command below then backs up and restores **that** file.
- After a restore, **keep using the same `BLOCK_DB_PATH`** in every terminal. If one terminal points at a different file, it will see different blocks, and its ownership checks will be wrong (§3.2).

#### 1. Back it up regularly and safely

Do **not** simply copy the file while the driver or the worker might be writing to it, because the copy could be inconsistent. Use SQLite's built-in online backup instead, which is safe while the worker is running. After step 0 has set `$db`:

```powershell
New-Item -ItemType Directory -Force backups | Out-Null
$backup = "backups\blocks-$(Get-Date -Format yyyyMMdd-HHmmss).db"
python -c "import sqlite3, sys; s = sqlite3.connect(sys.argv[1]); d = sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()" $db $backup
```

This creates, for example, `backups\blocks-20261114-213512.db`. Check that the backup is readable:

```powershell
python -c "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); print(c.execute('PRAGMA integrity_check').fetchone()[0], c.execute('SELECT COUNT(*) FROM blocks').fetchone()[0], 'records')" $backup
```

```
ok 1 records
```

Recommendations:
- **How often:** run it on a schedule (e.g. hourly with Windows Task Scheduler) and before any maintenance, upgrade or move.
- **Where:** keep copies **off the machine** as well (a protected network share or backup system), so a disk failure does not take the backups with it.
- **How long:** keep enough copies to cover at least the longest TTL (`BLOCK_MAX_TTL`, 24 h by default), and delete older ones according to your data-retention policy.
- `backups/` and `*.db` are local operational files. Never commit them to Git: `.gitignore` already excludes `*.db`.

#### 2. Restrict access

The database holds **IP addresses, alert IDs and free-text reasons**, which may count as personal or security-sensitive data. Anyone who can edit it can also change what the driver believes it owns. Limit the folder to the account that runs the driver plus administrators:

```powershell
icacls backups /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" "Administrators:(OI)(CI)F"
```

Apply the same restriction to the folder that holds the live database: the folder of `$db` from step 0, or point `BLOCK_DB_PATH` at a protected folder. Store off-machine copies with equivalent protection (restricted access, encrypted where possible).

#### 3. Restore consistently with the router

A backup is a snapshot. Between the backup and the restore, the router may have changed: blocks expired, new blocks were added, or rules were rolled back. Restore like this:

1. **Stop** the expiry worker (Ctrl+C) and every other driver command, so nothing writes to the database. Set `$db` as in step 0, using the **same** `BLOCK_DB_PATH` the driver uses.
2. Keep the damaged or current file for investigation: `Rename-Item $db "$db.broken"`.
3. Put the newest good backup in place **at the same path**: `Copy-Item backups\blocks-20261114-213512.db $db`.
4. **Compare the two sources of truth** before restarting the worker:
   ```powershell
   python -m cisco_driver list                     # what the restored record believes
   python -m cisco_driver show-acl --device R1     # what is really on the router
   ```
5. Reconcile any differences using the table in §5.4:
   - **Record active, rule missing on the router:** re-send the block with a new alert ID if it is still needed. Otherwise let the worker expire the record; it will simply find nothing to delete.
   - **Rule on the router, no active record** (for example, a block created after the backup was taken): the driver now treats it as foreign and will not remove it. An administrator must review it against the alert history and remove it on the router if it is no longer wanted.
6. **Restart** the worker with the same settings, including the same `BLOCK_DB_PATH`: `python -m cisco_driver worker`.

> Because of step 5, the more recent the backup, the less reconciliation is needed. That is why regular scheduled backups matter.

---

## 7. Common errors and solutions

The CLI uses three exit codes: **0** = success, **1** = refused or router error, **2** = bad input or bad settings.

### 7.1 Settings errors (exit code 2)

| Message | Cause | Solution |
|---|---|---|
| `Settings error: RESTCONF_DEVICES is not set (example: R1=https://127.0.0.1:8443)` | Variable missing. This often happens in a **new terminal**, because `$env:` values last only for the current window. | Paste the `$env:` lines printed by the mock router again. |
| `Settings error: RESTCONF_PASSWORD is not set` | Password variable missing or empty. | `$env:RESTCONF_PASSWORD = "..."` (the mock prints it at start-up). |
| `Settings error: Bad RESTCONF_DEVICES entry 'R1'; expected NAME=URL` | Wrong format. | Use `R1=https://127.0.0.1:8443`. |
| `Settings error: RESTCONF base URL must look like https://host[:port]` | URL uses `http://` or has no host. | RESTCONF must use HTTPS: `https://...` |
| `Settings error: RESTCONF base URL must not contain a path or query` | URL includes `/restconf` or similar. | Give only `https://host:port`; the driver adds the path itself. |
| `Settings error: Invalid ACL name ...` / `Invalid device name ...` | Name has spaces or symbols, or does not start with a letter. | Use letters, digits, `_`, `.`, `-` only. |

### 7.2 Input errors (exit code 2)

| Message | Cause | Solution |
|---|---|---|
| `Invalid input: 'abc' is not a valid IP address` | Typo or hostname instead of IP. | Give a dotted IPv4 address. |
| `Invalid input: Only a single IP address can be blocked, not a network` | A CIDR such as `10.0.0.0/8` was given. | Block individual hosts. Network-wide blocks are deliberately refused. |
| `Invalid input: Only IPv4 addresses are supported by this ACL` | IPv6 address. | The `BLOCKLIST` extended ACL is IPv4 only. |
| `Invalid input: 127.0.0.1 is a special-purpose address and cannot be blocked` | `0.0.0.0`, loopback, link-local, multicast, or the reserved `240.0.0.0/4` block (see the address policy in §4.1). | These are never valid attacker sources. Check the alert data. |
| `Invalid input: TTL must be between 60 and 86400 seconds` | TTL too short or too long. | Choose a TTL in range. For the demonstration only, set `$env:BLOCK_MIN_TTL = "10"`. |
| `Invalid input: Unknown device 'R9'; known: ['R1']` | Device name not in `RESTCONF_DEVICES`. | Use a listed name (names are case-sensitive). |
| Demo: `--ttl 5 is below the minimum TTL of 10s ...` | Demo TTL below the demo minimum. | Use a larger `--ttl` or set `BLOCK_MIN_TTL` (§3.4). |

### 7.3 Router and connection errors (exit code 1)

| Message | Cause | Solution |
|---|---|---|
| `Router error: Router refused the credentials while trying to read the ACL (HTTP 401)` | Wrong username or password. | Use the password the mock printed at start-up. If `MOCK_ROUTER_PASSWORD` was not set, a **new random password** is generated at every restart. |
| `Router error: TLS verification failed for https://...` | `RESTCONF_VERIFY` does not point at the mock's certificate. | Set `RESTCONF_VERIFY` to the `cert.pem` path the mock printed. |
| `"status": "error"`, `... failed after 4 attempts (ConnectionError)` or `(ConnectTimeout)` | The mock router is not running, or the port is wrong. | Start it in Terminal 1 and check the port in `RESTCONF_DEVICES`. |
| `... failed after 4 attempts (HTTP 503)` | Router busy for the whole retry period. | Wait and retry; optionally raise `RESTCONF_MAX_RETRIES` or `RESTCONF_TIMEOUT`. |
| `... failed after 4 attempts (ReadTimeout)` | Router answers too slowly. | Raise `RESTCONF_TIMEOUT` (e.g. `30`). |
| `Could not read the ACL: HTTP 404 ...` / `Could not add rules to the ACL: HTTP 400 ...` | The router rejected the request. | Run with `-v` and read the router's error text. |
| `Verification failed: rule not found on router after writing it` | The router accepted the write but the rule is not there. | Run `show-acl` and retry the block. Nothing was recorded, so a retry is safe. |
| `Verification failed: rule still on router after delete` | The delete did not take effect. | The block stays active and is retried at the next expiry run, or run `unblock` again. |

### 7.4 Refusals (exit code 1, `"status": "refused"`)

| Message | Cause | Solution |
|---|---|---|
| `Rate limit: 10 changes on this device in the last minute (limit 10); try again shortly` | Too many changes too fast. This protects the router. | Wait up to 60 s and resend. For load tests only, raise `BLOCK_MAX_CHANGES_PER_MINUTE`. |
| `Device already has 50 active blocks (limit 50)` | Block cap reached. | Unblock old entries, shorten TTLs, or raise `BLOCK_MAX_PER_DEVICE`. |
| `ACL has no free sequence numbers` | All slots 10–990 (step 10, 99 slots) are used. | Remove unused blocks. |
| On `unblock`: `A deny rule for this IP exists (seq N) but was not created by this driver; it was left untouched...` | The rule was added by hand or by another system. | Intended protection; the driver never deletes rules it does not own. |

### 7.5 Other situations

| Symptom | Cause | Solution |
|---|---|---|
| Blocks never disappear after their TTL | No expiry process is running. | Start `python -m cisco_driver worker`, or schedule `expire` (§6.2). |
| `list` shows a block but `show-acl` does not | The mock router was restarted, and its ACL is held in memory. | Re-send the block with a new alert ID, or start fresh by deleting `blocks.db` while the router is empty. |
| `list` is empty but the router has the driver's rule, or `unblock` says "not created by this driver" for a rule you blocked | The commands used a different `blocks.db` (run from different folders). | Set `BLOCK_DB_PATH` to one absolute path in every terminal. |
| `already_blocked` with `expiry unchanged` | The same alert ID was sent again. | Intended (§4.3). Send a new alert ID to extend the block. |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy. | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `ModuleNotFoundError: No module named 'requests'` (or `flask`) | The virtual environment is not active, or packages are not installed. | `.\.venv\Scripts\Activate.ps1`, then `pip install -r requirements.txt`. |
| `No module named cisco_driver` | Command run from the wrong folder. | `cd <project-folder>\role_e_cisco_driver` first. |
| Mock router: `address already in use` / port error | Port 8443 is taken (e.g. a mock router is already running). | Stop the other one, or use `python -m mock_router --port 9443` and update `RESTCONF_DEVICES`. |
| `curl.exe` shows `401` or a certificate error | Wrong password, or the `--cacert` path is wrong. | Use the mock's password and `mock_certs\cert.pem` from inside `role_e_cisco_driver`. |

---

## 8. Quick reference

```powershell
# setup (each new terminal)
cd <project-folder>\role_e_cisco_driver
.\.venv\Scripts\Activate.ps1

# Terminal 1 - Mock IOS XE server
$env:MOCK_ROUTER_PASSWORD = "lab-password"
python -m mock_router --port 8443

# Terminals 2 and 3 - paste the four $env: lines the mock prints
$env:RESTCONF_DEVICES  = "R1=https://127.0.0.1:8443"
$env:RESTCONF_USER     = "admin"
$env:RESTCONF_PASSWORD = "lab-password"
$env:RESTCONF_VERIFY   = "<project-folder>\role_e_cisco_driver\mock_certs\cert.pem"

python -m cisco_driver worker                           # Terminal 3: automatic expiry (keep running)

python -m cisco_driver block 203.0.113.7 --device R1 --ttl 3600 --reason "ssh brute force" --alert-id ALERT-001
python -m cisco_driver unblock 203.0.113.7 --device R1  # rollback now (driver-created rules only)
python -m cisco_driver list                             # active blocks (driver record)
python -m cisco_driver show-acl --device R1             # what is on the router (JSON)
curl.exe -s --cacert mock_certs\cert.pem -u admin:lab-password https://127.0.0.1:8443/_mock/show
python -m cisco_driver history                          # last 50 blocks incl. ended ones
python -m cisco_driver expire                           # remove expired blocks once
python -m cisco_driver -v <command>                     # verbose: audit log

python demo/lifecycle_demo.py                           # the 8-step demonstration
python demo/lifecycle_demo.py --pause                   # ... with a pause between steps
Remove-Item Env:BLOCK_MIN_TTL                           # after a manual (Option B) demo, in T2 and T3

# back up the database in use, honouring BLOCK_DB_PATH (§6.5)
$db = if ($env:BLOCK_DB_PATH) { $env:BLOCK_DB_PATH } else { "blocks.db" }
New-Item -ItemType Directory -Force backups | Out-Null
python -c "import sqlite3, sys; s = sqlite3.connect(sys.argv[1]); d = sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()" $db "backups\blocks-$(Get-Date -Format yyyyMMdd-HHmmss).db"

python -m pytest                                        # run all 96 tests
pip-audit -r requirements.txt                           # audit runtime packages
pip-audit -r requirements-dev.txt                       # audit runtime + development tools
```

| Exit code | Meaning |
|---|---|
| 0 | Success (`blocked`, `already_blocked`, `unblocked`, `not_found`) |
| 1 | `refused` or `error` (router problem, safety limit, or rule not owned by the driver) |
| 2 | Invalid input or settings |

---

## Appendix A — Real Cisco hardware (out of scope, untested)

> 🧪 **Not part of Role E's demonstration, and not tested.** Role E uses the Mock IOS XE server only. This appendix records what a future real deployment would need. None of it has been run against physical or virtual Cisco equipment. A qualified network administrator must review it before any use.

**Router requirements (illustrative):** a Cisco IOS XE device with RESTCONF enabled, for example:

```
configure terminal
 ip http secure-server
 restconf
 username <user> privilege 15 secret <password>
end
```

The driver would then be pointed at it with `RESTCONF_DEVICES = "R1=https://<router-ip>:443"` and `RESTCONF_VERIFY` set to the router's CA certificate. Start with the read-only `show-acl` command before submitting any block.

**The ACL must also be attached to an interface.** The driver only creates and edits the ACL's lines; it never binds the ACL to an interface. Without that binding, a rule exists on the router but filters no traffic.

> ⚠️ **Warning: attaching an ACL to an interface can replace existing security policy.**
> A Cisco interface normally accepts **only one IP ACL per interface, per protocol, per direction**. Running `ip access-group BLOCKLIST in` on an interface that already has an inbound ACL **replaces** that ACL. Its rules stop being enforced, and because `BLOCKLIST` ends in `permit ip any any`, traffic that the old ACL blocked could be allowed.
>
> **Do not copy the example below blindly.** Before attaching `BLOCKLIST`, a network administrator must:
> 1. Inspect the existing interface ACLs (`show running-config interface <name>`, `show ip interface <name>`).
> 2. Confirm the **correct interface** (normally the outside / Internet-facing one) and the **correct direction** (normally `in`).
> 3. If an ACL is already applied there, **preserve its rules**. Either merge the blocklist into the existing policy design or choose a different enforcement point. Never simply overwrite it.
> 4. Apply the change in a maintenance window, with console or out-of-band access available in case management access is lost.
>
> Illustrative example only, valid **only** when the interface currently has no inbound IP ACL:
> ```
> interface GigabitEthernet1
>  ip access-group BLOCKLIST in
> ```

Real IOS XE releases may differ from the mock in small details of the YANG data model (for example, `host` vs `host-address` for the source address). The driver accepts both when reading, but writes against real hardware have not been verified.

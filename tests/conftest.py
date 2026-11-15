"""Shared test setup: one HTTPS mock router for the whole run, reset before each test."""

import pytest

from cisco_driver.driver import CiscoDriver
from cisco_driver.restconf_client import RestconfClient
from cisco_driver.store import BlockStore
from mock_router import MockServer

USER = "admin"
PASSWORD = "test-only-password"


class FakeClock:
    """Lets tests jump forward in time instead of waiting."""

    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="session")
def mock_server(tmp_path_factory):
    server = MockServer(USER, PASSWORD, tmp_path_factory.mktemp("certs")).start()
    yield server
    server.stop()


@pytest.fixture
def router(mock_server):
    mock_server.state.reset()
    yield mock_server
    mock_server.state.reset()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def sleeps():
    """Records back-off waits instead of really sleeping."""
    return []


@pytest.fixture
def client(router, sleeps):
    return RestconfClient(
        router.url, USER, PASSWORD,
        verify=str(router.cert_path), timeout=2, max_retries=3,
        backoff_base=1.0, sleep=sleeps.append,
    )


@pytest.fixture
def store(tmp_path):
    s = BlockStore(tmp_path / "blocks.db")
    yield s
    s.close()


@pytest.fixture
def driver(client, store, clock):
    return CiscoDriver(
        {"R1": client}, store, clock=clock,
        max_changes_per_minute=5, max_blocks_per_device=8,
    )


def acl_rules(router, name="BLOCKLIST"):
    """What the router really holds, as {seq: rule}."""
    with router.state.lock:
        return dict(router.state.acls.get(name, {}))

"""RESTCONF client: requests, retries with back-off, timeouts, TLS and auth."""

import pytest

from cisco_driver.restconf_client import (
    DeviceUnreachable,
    RestconfClient,
    RestconfError,
    deny_rule,
    permit_any_rule,
)

from .conftest import PASSWORD, USER


def test_missing_acl_returns_none(client):
    assert client.get_acl_rules("BLOCKLIST") is None


def test_create_read_add_delete(client, router):
    client.create_acl("BLOCKLIST", [deny_rule(10, "203.0.113.7"), permit_any_rule(1000)])
    client.add_rules("BLOCKLIST", [deny_rule(20, "198.51.100.23")])
    seqs = [int(r["sequence"]) for r in client.get_acl_rules("BLOCKLIST")]
    assert seqs == [10, 20, 1000]

    assert client.delete_rule("BLOCKLIST", 10) is True
    assert client.delete_rule("BLOCKLIST", 10) is False   # already gone: no error
    assert "deny ip host 198.51.100.23 any" in router.state.show_text()


def test_retries_with_exponential_backoff_then_succeeds(client, router, sleeps):
    router.state.fail_next(3, 503)
    assert client.get_acl_rules("BLOCKLIST") is None
    assert sleeps == [1.0, 2.0, 4.0]          # waited 1s, 2s, 4s
    assert router.state.count("GET") == 4


def test_gives_up_after_max_retries(client, router, sleeps):
    router.state.fail_next(10, 503)
    with pytest.raises(DeviceUnreachable):
        client.get_acl_rules("BLOCKLIST")
    assert router.state.count() == 4         # 1 try + 3 retries, then stop
    assert sleeps == [1.0, 2.0, 4.0]


def test_backoff_is_capped(router):
    waits = []
    c = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path),
                       max_retries=6, backoff_base=1, max_backoff=8, sleep=waits.append)
    router.state.fail_next(6, 502)
    c.get_acl_rules("BLOCKLIST")
    assert waits == [1, 2, 4, 8, 8, 8]


def test_wrong_password_is_not_retried(router, sleeps):
    c = RestconfClient(router.url, USER, "wrong", verify=str(router.cert_path), sleep=sleeps.append)
    with pytest.raises(RestconfError) as err:
        c.get_acl_rules("BLOCKLIST")
    assert err.value.status == 401
    assert not isinstance(err.value, DeviceUnreachable)
    assert router.state.count() == 1 and sleeps == []


def test_bad_request_is_not_retried(client, router, sleeps):
    router.state.fail_next(1, 400)
    with pytest.raises(RestconfError) as err:
        client.get_acl_rules("BLOCKLIST")
    assert err.value.status == 400 and sleeps == []


def test_timeout_is_retried_then_reported(router):
    router.state.delay = 1.0
    c = RestconfClient(router.url, USER, PASSWORD, verify=str(router.cert_path),
                       timeout=0.3, max_retries=1, sleep=lambda s: None)
    with pytest.raises(DeviceUnreachable) as err:
        c.get_acl_rules("BLOCKLIST")
    assert "Timeout" in str(err.value)


def test_unreachable_device(sleeps):
    c = RestconfClient("https://127.0.0.1:1", USER, PASSWORD, timeout=0.5,
                       max_retries=2, sleep=sleeps.append)
    with pytest.raises(DeviceUnreachable):
        c.get_acl_rules("BLOCKLIST")
    assert sleeps == [1.0, 2.0]


def test_untrusted_certificate_is_refused_without_retry(router, sleeps):
    c = RestconfClient(router.url, USER, PASSWORD, verify=True, sleep=sleeps.append)
    with pytest.raises(RestconfError) as err:
        c.get_acl_rules("BLOCKLIST")
    assert "TLS verification failed" in str(err.value)
    assert sleeps == []


@pytest.mark.parametrize("url", [
    "http://10.0.0.1",                 # plain HTTP not allowed
    "ftp://10.0.0.1",
    "https://",
    "https://10.0.0.1/restconf",       # no paths in the base URL
])
def test_insecure_or_odd_urls_rejected(url):
    with pytest.raises(ValueError):
        RestconfClient(url, USER, PASSWORD)


def test_password_not_in_repr(client):
    assert PASSWORD not in repr(client)


def test_acl_name_is_url_encoded():
    # even if a strange name got this far, it cannot change the URL path
    assert RestconfClient._acl_path("A/B?x").endswith("extended=A%2FB%3Fx")

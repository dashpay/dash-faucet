import pytest
from starlette.requests import Request

from app.config import settings
from app.middleware import rate_limit
from app.middleware.rate_limit import get_client_ip

CLIENT = "93.184.216.34"
PROXY = "10.0.1.20"


@pytest.fixture(autouse=True)
def reset_warning(monkeypatch):
    monkeypatch.setattr(rate_limit, "_warned_misconfig", False)


def make_request(*forwarded, peer=PROXY):
    headers = [(b"x-forwarded-for", line.encode()) for line in forwarded]
    return Request({"type": "http", "headers": headers, "client": (peer, 1234)})


def test_one_proxy_uses_rightmost_entry():
    # The client wrote "1.1.1.1"; the ALB appended the real peer.
    assert get_client_ip(make_request(f"1.1.1.1, {CLIENT}")) == CLIENT


def test_two_proxies_skip_the_inner_hop(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 2)
    assert get_client_ip(make_request(f"1.1.1.1, {CLIENT}, 10.0.0.5")) == CLIENT


def test_fewer_entries_than_proxies_takes_leftmost(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 2)
    assert get_client_ip(make_request(CLIENT)) == CLIENT


def test_separate_header_lines_are_one_list():
    assert get_client_ip(make_request("6.6.6.6", CLIENT)) == CLIENT


def test_port_is_stripped():
    assert get_client_ip(make_request(f"{CLIENT}:51234")) == CLIENT
    assert get_client_ip(make_request("[2001:db8::1]:443")) == "2001:db8::1"


def test_public_peer_header_is_ignored():
    # Reached the app directly, not through our proxy: the header is forged.
    assert get_client_ip(make_request("1.1.1.1", peer=CLIENT)) == CLIENT


def test_zero_hops_ignores_header(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 0)
    assert get_client_ip(make_request(CLIENT)) == PROXY


def test_missing_header_falls_back_to_peer_and_warns(caplog):
    assert get_client_ip(make_request()) == PROXY
    assert "no X-Forwarded-For" in caplog.text


def test_private_client_warns(caplog):
    assert get_client_ip(make_request("10.0.0.9")) == "10.0.0.9"
    assert "TRUSTED_PROXY_HOPS" in caplog.text


def test_garbage_entry_falls_back_to_peer():
    assert get_client_ip(make_request("not-an-ip")) == PROXY

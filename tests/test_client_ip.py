from starlette.requests import Request

from app.config import settings
from app.middleware.rate_limit import get_client_ip


def make_request(forwarded=None, peer="203.0.113.9"):
    headers = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request({"type": "http", "headers": headers, "client": (peer, 1234)})


def test_one_proxy_uses_rightmost_entry():
    # The client wrote "1.1.1.1"; the ALB appended the real peer.
    assert get_client_ip(make_request("1.1.1.1, 198.51.100.7")) == "198.51.100.7"


def test_two_proxies_skip_the_inner_hop(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 2)
    request = make_request("1.1.1.1, 198.51.100.7, 10.0.0.5")
    assert get_client_ip(request) == "198.51.100.7"


def test_fewer_entries_than_proxies_takes_leftmost(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 2)
    assert get_client_ip(make_request("198.51.100.7")) == "198.51.100.7"


def test_zero_hops_ignores_header(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 0)
    assert get_client_ip(make_request("1.1.1.1")) == "203.0.113.9"


def test_missing_header_falls_back_to_peer():
    assert get_client_ip(make_request()) == "203.0.113.9"

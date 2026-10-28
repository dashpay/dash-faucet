import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.middleware.rate_limit import rate_limiter
from app.routers import faucet


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    """Each test starts with CAP configured and an empty rate limiter."""
    for name, value in {
        "cap_site_key": "soft",
        "cap_secret": "soft-secret",
        "cap_hard_site_key": "hard",
        "cap_hard_secret": "hard-secret",
        "trusted_proxy_hops": 1,
    }.items():
        monkeypatch.setattr(settings, name, value)
    rate_limiter._requests.clear()
    yield
    rate_limiter._requests.clear()


@pytest.fixture
def cap(monkeypatch):
    """Fake CAP server: accepts tokens named "good-soft" / "good-hard"."""
    calls = []

    async def verify(token, hard=False):
        calls.append((token, hard))
        if not faucet.cap_configured(hard):
            return False
        return token == ("good-hard" if hard else "good-soft")

    monkeypatch.setattr(faucet, "verify_cap_token", verify)
    return calls


@pytest.fixture
def sent(monkeypatch):
    """Record payouts instead of talking to Dash Core."""
    payouts = []

    def send_to_address(address, amount):
        payouts.append((address, amount))
        return "ab" * 32

    monkeypatch.setattr(faucet.dash_client, "send_to_address", send_to_address)
    return payouts


@pytest.fixture
def client():
    # No context manager: the lifespan hook would try to reach Dash Core.
    return TestClient(app)

import pytest

from app.config import settings

ADDRESS = "yPrynRN6ViX2rCcRL5SoSi8ntcWgdHSEaS"


def post(client, body, ip="93.184.216.34"):
    return client.post("/api/core-faucet", json=body, headers={"X-Forwarded-For": ip})


def test_soft_captcha_pays_out(client, cap, sent):
    response = post(client, {"address": ADDRESS, "capToken": "good-soft"})
    assert response.status_code == 200
    assert sent == [(ADDRESS, settings.core_faucet_amount)]


def test_missing_captcha_is_rejected(client, cap, sent):
    response = post(client, {"address": ADDRESS})
    assert response.status_code == 400
    assert sent == []


def test_bogus_hard_token_does_not_skip_captcha(client, cap, sent):
    # Regression: a hardCapToken used to skip the soft check without being
    # verified whenever the client was under the rate limit.
    response = post(client, {"address": ADDRESS, "hardCapToken": "junk"})
    assert response.status_code == 400
    assert sent == []
    assert cap == [("junk", True)]


def test_hard_token_is_rejected_when_hard_cap_unconfigured(client, cap, sent, monkeypatch):
    monkeypatch.setattr(settings, "cap_hard_secret", "")
    response = post(client, {"address": ADDRESS, "hardCapToken": "good-hard"})
    assert response.status_code == 400
    assert sent == []


def test_rate_limit_then_hard_captcha(client, cap, sent):
    for _ in range(settings.rate_limit_per_hour):
        assert post(client, {"address": ADDRESS, "capToken": "good-soft"}).status_code == 200

    limited = post(client, {"address": ADDRESS, "capToken": "good-soft"})
    assert limited.status_code == 429
    assert limited.json()["detail"]["requiresHardCaptcha"] is True
    assert "Retry-After" in limited.headers

    bypass = post(client, {"address": ADDRESS, "hardCapToken": "good-hard"})
    assert bypass.status_code == 200


def test_spoofed_forwarded_for_does_not_reset_limit(client, cap, sent):
    # Each request claims a fresh client IP; the ALB-appended entry is the same.
    for i in range(settings.rate_limit_per_hour):
        response = post(client, {"address": ADDRESS, "capToken": "good-soft"},
                        ip=f"10.9.9.{i}, 93.184.216.34")
        assert response.status_code == 200
    response = post(client, {"address": ADDRESS, "capToken": "good-soft"},
                    ip="10.9.9.99, 93.184.216.34")
    assert response.status_code == 429


def test_rpc_error_is_not_echoed(client, cap, monkeypatch):
    from app.routers import faucet

    def boom(address, amount):
        raise RuntimeError("rpc password=hunter2 at http://dashcore")

    monkeypatch.setattr(faucet.dash_client, "send_to_address", boom)
    response = post(client, {"address": ADDRESS, "capToken": "good-soft"})
    assert response.status_code == 500
    assert "hunter2" not in response.text


def test_ui_retry_with_spent_soft_and_good_hard(client, cap, sent):
    for _ in range(settings.rate_limit_per_hour):
        post(client, {"address": ADDRESS, "capToken": "good-soft"})
    response = post(client, {"address": ADDRESS, "capToken": "spent", "hardCapToken": "good-hard"})
    assert response.status_code == 200
    assert ("spent", False) not in cap


def test_no_cap_configured_is_open_and_429_has_no_hard_hint(client, cap, sent, monkeypatch):
    for name in ("cap_site_key", "cap_secret", "cap_hard_site_key", "cap_hard_secret"):
        monkeypatch.setattr(settings, name, "")
    for _ in range(settings.rate_limit_per_hour):
        assert post(client, {"address": ADDRESS}).status_code == 200
    limited = post(client, {"address": ADDRESS})
    assert limited.status_code == 429
    assert "requiresHardCaptcha" not in limited.json()["detail"]


@pytest.mark.parametrize("path,body", [
    ("/api/asset-lock-proof", {"assetLockPublicKey": "02" + "11" * 32, "hardCapToken": "junk"}),
    ("/api/faucet", {"hardCapToken": "junk"}),
])
def test_identity_endpoints_reject_bogus_hard_token(client, cap, path, body):
    response = client.post(path, json=body, headers={"X-Forwarded-For": "93.184.216.34"})
    assert response.status_code == 400

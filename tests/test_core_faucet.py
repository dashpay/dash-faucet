from app.config import settings

ADDRESS = "yPrynRN6ViX2rCcRL5SoSi8ntcWgdHSEaS"


def post(client, body, ip="198.51.100.7"):
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
                        ip=f"10.9.9.{i}, 198.51.100.7")
        assert response.status_code == 200
    response = post(client, {"address": ADDRESS, "capToken": "good-soft"},
                    ip="10.9.9.99, 198.51.100.7")
    assert response.status_code == 429


def test_rpc_error_is_not_echoed(client, cap, monkeypatch):
    from app.routers import faucet

    def boom(address, amount):
        raise RuntimeError("rpc password=hunter2 at http://dashcore")

    monkeypatch.setattr(faucet.dash_client, "send_to_address", boom)
    response = post(client, {"address": ADDRESS, "capToken": "good-soft"})
    assert response.status_code == 500
    assert "hunter2" not in response.text

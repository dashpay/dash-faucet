from decimal import Decimal

from app.routers import faucet


def test_balance_is_a_json_number(client, monkeypatch):
    core = faucet.dash_client
    monkeypatch.setattr(core, "get_wallet_info", lambda: {"balance": Decimal("701.18845748")})
    monkeypatch.setattr(core, "list_unspent", lambda: [{"amount": Decimal("2.5")}])
    monkeypatch.setattr(core, "get_deposit_address", lambda: "yAddr")
    monkeypatch.setattr(core, "get_block_count", lambda: 1581087)

    body = client.get("/api/status").json()
    assert body["balance"] == 701.18845748
    assert body["availableUtxos"] == 1


def test_backend_error_is_not_echoed(client, monkeypatch):
    def boom():
        raise RuntimeError("http://dashrpc:secret@dashcore:19998")

    monkeypatch.setattr(faucet.dash_client, "get_wallet_info", boom)
    response = client.get("/api/status")
    assert response.status_code == 503
    assert "secret" not in response.text

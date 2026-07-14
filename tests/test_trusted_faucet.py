"""Tests for the trusted server-to-server faucet endpoint."""

import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.routers import faucet


class TrustedFaucetTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_invalid_key_before_payout(self):
        body = faucet.ApiCoreFaucetRequest(address="y" * 34)
        with patch.object(faucet, "authenticate_api_key", return_value=None), patch.object(
            faucet, "dispense_core_dash"
        ) as dispense:
            with self.assertRaises(HTTPException) as raised:
                await faucet.api_core_faucet(body, "Bearer invalid")

        self.assertEqual(raised.exception.status_code, 401)
        dispense.assert_not_called()

    async def test_valid_key_bypasses_public_protection_and_records_usage(self):
        body = faucet.ApiCoreFaucetRequest(address="y" * 34)
        expected = faucet.CoreFaucetResponse(
            txid="ab" * 32,
            amount=1.0,
            address=body.address,
        )
        limiter = Mock()
        limiter.is_allowed.return_value = (True, 0)

        with patch.object(
            faucet, "authenticate_api_key", return_value="platform-team"
        ), patch.object(faucet, "api_key_rate_limiter", limiter), patch.object(
            faucet, "dispense_core_dash", return_value=expected
        ) as dispense:
            result = await faucet.api_core_faucet(body, "Bearer valid")

        self.assertEqual(result, expected)
        dispense.assert_called_once_with(body.address, faucet.settings.core_faucet_amount)
        limiter.record_request.assert_called_once_with("platform-team")

    async def test_daily_limit_blocks_before_payout(self):
        body = faucet.ApiCoreFaucetRequest(address="y" * 34)
        limiter = Mock()
        limiter.is_allowed.return_value = (False, 123)

        with patch.object(
            faucet, "authenticate_api_key", return_value="platform-team"
        ), patch.object(faucet, "api_key_rate_limiter", limiter), patch.object(
            faucet, "dispense_core_dash"
        ) as dispense:
            with self.assertRaises(HTTPException) as raised:
                await faucet.api_core_faucet(body, "Bearer valid")

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.headers["Retry-After"], "123")
        dispense.assert_not_called()


if __name__ == "__main__":
    unittest.main()

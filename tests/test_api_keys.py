"""Tests for trusted faucet API key authentication."""

import hashlib
import unittest
from unittest.mock import patch

from app.services import api_keys


class ApiKeyTests(unittest.TestCase):
    def test_parse_api_key_hashes(self):
        digest = hashlib.sha256(b"secret").hexdigest()
        self.assertEqual(
            api_keys.parse_api_key_hashes(f'{{"platform-team":"{digest}"}}'),
            {"platform-team": digest},
        )

    def test_parse_rejects_non_sha256_hash(self):
        with self.assertRaises(ValueError):
            api_keys.parse_api_key_hashes('{"platform-team":"short"}')

    def test_authenticate_valid_bearer_key(self):
        token = "test-api-key"
        digest = hashlib.sha256(token.encode()).hexdigest()
        with patch.object(api_keys, "API_KEY_HASHES", {"platform-team": digest}):
            self.assertEqual(
                api_keys.authenticate_api_key(f"Bearer {token}"),
                "platform-team",
            )

    def test_authenticate_rejects_invalid_or_missing_key(self):
        digest = hashlib.sha256(b"valid-key").hexdigest()
        with patch.object(api_keys, "API_KEY_HASHES", {"platform-team": digest}):
            self.assertIsNone(api_keys.authenticate_api_key(None))
            self.assertIsNone(api_keys.authenticate_api_key("Basic abc"))
            self.assertIsNone(api_keys.authenticate_api_key("Bearer wrong-key"))


if __name__ == "__main__":
    unittest.main()

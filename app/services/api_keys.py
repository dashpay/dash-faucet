"""Authentication helpers for trusted faucet API clients."""

import hashlib
import hmac
import json

from app.config import settings


def parse_api_key_hashes(value: str) -> dict[str, str]:
    """Parse a JSON mapping of API key IDs to SHA-256 hashes."""
    if not value.strip():
        return {}

    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("FAUCET_API_KEY_HASHES must be a JSON object")

    result: dict[str, str] = {}
    for key_id, key_hash in parsed.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Faucet API key IDs must be non-empty strings")
        if (
            not isinstance(key_hash, str)
            or len(key_hash) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in key_hash)
        ):
            raise ValueError(
                f"Faucet API key hash for {key_id!r} must be a SHA-256 hex digest"
            )
        result[key_id] = key_hash.lower()

    return result


API_KEY_HASHES = parse_api_key_hashes(settings.faucet_api_key_hashes)


def authenticate_api_key(authorization: str | None) -> str | None:
    """Return the matching key ID for a valid Bearer token."""
    if not authorization:
        return None

    scheme, separator, token = authorization.partition(" ")
    token = token.strip()
    if not separator or scheme.casefold() != "bearer" or not token:
        return None

    presented_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched_key_id = None

    # Compare against every configured hash to avoid revealing which key IDs exist.
    for key_id, expected_hash in API_KEY_HASHES.items():
        if hmac.compare_digest(presented_hash, expected_hash):
            matched_key_id = key_id

    return matched_key_id

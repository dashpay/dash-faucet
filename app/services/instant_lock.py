"""InstantLock retrieval module.

Polls the getislocks RPC to retrieve InstantSend lock data for transactions.
"""
import asyncio
import time
from typing import Any

from app.config import settings
from app.services.core_client import dash_client


class InstantLockTimeout(Exception):
    """Raised when InstantLock is not received within timeout."""
    pass


async def wait_for_instant_lock(
    txid: str,
    timeout: float | None = None,
    poll_interval: float | None = None
) -> bytes:
    """Wait for an InstantSend lock for a transaction.

    Args:
        txid: The transaction ID to wait for
        timeout: Maximum time to wait in seconds (default from settings)
        poll_interval: Time between RPC polls in seconds (default from settings)

    Returns:
        The serialized InstantLock bytes

    Raises:
        InstantLockTimeout: If lock is not received within timeout
    """
    if timeout is None:
        timeout = settings.islock_timeout
    if poll_interval is None:
        poll_interval = settings.islock_poll_interval

    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            result = dash_client.get_islocks([txid])

            if result and len(result) > 0:
                lock_data = result[0]

                # Check if we got actual lock data (not "None" string)
                if lock_data != "None" and isinstance(lock_data, dict):
                    # The "hex" field contains the serialized InstantLock
                    if "hex" in lock_data:
                        return bytes.fromhex(lock_data["hex"])

        except Exception as e:
            # Log error but continue polling
            print(f"Error polling for InstantLock: {e}")

        await asyncio.sleep(poll_interval)

    raise InstantLockTimeout(
        f"InstantLock not received for {txid} within {timeout} seconds"
    )


def get_instant_lock_sync(txid: str) -> dict[str, Any] | None:
    """Synchronously check for an InstantSend lock (non-blocking).

    Args:
        txid: The transaction ID to check

    Returns:
        The InstantLock data dict or None if not yet locked
    """
    try:
        result = dash_client.get_islocks([txid])

        if result and len(result) > 0:
            lock_data = result[0]

            if lock_data != "None" and isinstance(lock_data, dict):
                return lock_data

    except Exception:
        pass

    return None

"""Asset Lock Proof builder module.

Builds the InstantAssetLockProof structure required by the Dash Platform SDK.
"""
import base64
import json


def build_instant_asset_lock_proof(
    transaction_bytes: bytes,
    instant_lock_bytes: bytes,
    output_index: int = 0
) -> str:
    """Build an InstantAssetLockProof as hex-encoded JSON.

    The proof structure matches what the Platform SDK expects:
    {
        "instantLock": base64-encoded string,
        "transaction": base64-encoded string,
        "outputIndex": number
    }

    Args:
        transaction_bytes: Serialized transaction bytes
        instant_lock_bytes: Serialized InstantLock bytes
        output_index: Index of the burn output (usually 0)

    Returns:
        Hex-encoded JSON string of the proof
    """
    proof = {
        "instantLock": base64.standard_b64encode(instant_lock_bytes).decode("ascii"),
        "transaction": base64.standard_b64encode(transaction_bytes).decode("ascii"),
        "outputIndex": output_index
    }

    # Convert to JSON and hex-encode
    json_str = json.dumps(proof, separators=(",", ":"))  # Compact JSON
    return json_str.encode("utf-8").hex()


def decode_asset_lock_proof(hex_proof: str) -> dict:
    """Decode a hex-encoded asset lock proof back to a dictionary.

    Args:
        hex_proof: Hex-encoded JSON proof string

    Returns:
        Dictionary with instantLock, transaction, and outputIndex
    """
    json_bytes = bytes.fromhex(hex_proof)
    return json.loads(json_bytes.decode("utf-8"))

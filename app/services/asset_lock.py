"""Asset Lock Transaction creation module.

Implements the creation of Dash asset lock transactions (type 8).
Based on: /Users/pasta/workspace/dash/test/functional/feature_asset_locks.py
"""
import struct
from dataclasses import dataclass
from typing import Any

from app.services.keys import hash256, hash160, KeyPair
from app.config import settings


# Constants
COIN = 100_000_000  # 1 DASH in duffs
TX_VERSION = 3
TX_TYPE_ASSET_LOCK = 8


def ser_compact_size(n: int) -> bytes:
    """Serialize a compact size integer."""
    if n < 253:
        return struct.pack("B", n)
    elif n < 0x10000:
        return struct.pack("<BH", 253, n)
    elif n < 0x100000000:
        return struct.pack("<BI", 254, n)
    else:
        return struct.pack("<BQ", 255, n)


def ser_string(s: bytes) -> bytes:
    """Serialize a variable length string/bytes."""
    return ser_compact_size(len(s)) + s


def ser_uint256(u: int) -> bytes:
    """Serialize a 256-bit integer (little endian)."""
    return u.to_bytes(32, "little")


@dataclass
class COutPoint:
    """Transaction outpoint (reference to a previous output)."""
    txid: bytes  # 32 bytes, internal byte order
    n: int       # output index

    def serialize(self) -> bytes:
        return self.txid + struct.pack("<I", self.n)


@dataclass
class CTxIn:
    """Transaction input."""
    prevout: COutPoint
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF

    def serialize(self) -> bytes:
        r = self.prevout.serialize()
        r += ser_string(self.script_sig)
        r += struct.pack("<I", self.sequence)
        return r


@dataclass
class CTxOut:
    """Transaction output."""
    value: int      # in duffs
    script_pubkey: bytes

    def serialize(self) -> bytes:
        r = struct.pack("<q", self.value)
        r += ser_string(self.script_pubkey)
        return r


def create_p2pkh_script(pubkey_hash: bytes) -> bytes:
    """Create a P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG."""
    # OP_DUP=0x76, OP_HASH160=0xa9, OP_EQUALVERIFY=0x88, OP_CHECKSIG=0xac
    return bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])


def create_op_return_script(data: bytes = b"") -> bytes:
    """Create an OP_RETURN script.

    For asset lock transactions, the script must be exactly OP_RETURN + 0x00
    (OP_RETURN followed by empty pushdata).
    """
    # OP_RETURN=0x6a, followed by pushdata length
    if len(data) == 0:
        return bytes([0x6a, 0x00])  # OP_RETURN + push 0 bytes
    elif len(data) < 76:
        return bytes([0x6a, len(data)]) + data
    else:
        raise ValueError("OP_RETURN data too long")


class CAssetLockPayload:
    """Asset lock transaction payload."""

    def __init__(self, version: int = 1, credit_outputs: list[CTxOut] | None = None):
        self.version = version
        self.credit_outputs = credit_outputs or []

    def serialize(self) -> bytes:
        r = struct.pack("<B", self.version)
        # Serialize credit outputs as a vector
        r += ser_compact_size(len(self.credit_outputs))
        for output in self.credit_outputs:
            r += output.serialize()
        return r


class CTransaction:
    """Dash transaction with special transaction support."""

    def __init__(self):
        self.version = TX_VERSION
        self.tx_type = 0
        self.vin: list[CTxIn] = []
        self.vout: list[CTxOut] = []
        self.lock_time = 0
        self.extra_payload: bytes | None = None

    def serialize(self) -> bytes:
        """Serialize the transaction."""
        r = b""
        # Version and type combined (version is lower 16 bits, type is upper 16 bits)
        ver32bit = self.version | (self.tx_type << 16)
        r += struct.pack("<i", ver32bit)

        # Inputs
        r += ser_compact_size(len(self.vin))
        for vin in self.vin:
            r += vin.serialize()

        # Outputs
        r += ser_compact_size(len(self.vout))
        for vout in self.vout:
            r += vout.serialize()

        # Lock time
        r += struct.pack("<I", self.lock_time)

        # Extra payload for special transactions
        if self.tx_type != 0 and self.extra_payload is not None:
            r += ser_string(self.extra_payload)

        return r

    def txid(self) -> str:
        """Calculate and return the transaction ID."""
        return hash256(self.serialize())[::-1].hex()


def create_asset_lock_transaction(
    utxo: dict[str, Any],
    amount: int,
    asset_lock_pubkey: bytes,
    fee: int | None = None,
    change_script_pubkey: bytes | None = None
) -> tuple[CTransaction, bytes]:
    """Create an asset lock transaction.

    Args:
        utxo: The UTXO to spend (from listunspent)
        amount: Amount to lock in duffs
        asset_lock_pubkey: Compressed public key for the credit output (33 bytes)
        fee: Transaction fee in duffs (default from settings)
        change_script_pubkey: Script for change output (default: UTXO's script)

    Returns:
        Tuple of (transaction, serialized_bytes)
    """
    if fee is None:
        fee = settings.tx_fee

    # Calculate values
    utxo_amount = int(utxo["amount"] * COIN)
    change_amount = utxo_amount - amount - fee

    # Create the transaction
    tx = CTransaction()
    tx.version = TX_VERSION
    tx.tx_type = TX_TYPE_ASSET_LOCK

    # Input from UTXO
    txid_bytes = bytes.fromhex(utxo["txid"])[::-1]  # Reverse for internal byte order
    tx.vin.append(CTxIn(
        prevout=COutPoint(txid=txid_bytes, n=utxo["vout"]),
        script_sig=b"",  # Will be filled by wallet signing
        sequence=0xFFFFFFFF
    ))

    # Create the burn output (OP_RETURN with the locked amount)
    burn_output = CTxOut(
        value=amount,
        script_pubkey=create_op_return_script()
    )
    tx.vout.append(burn_output)

    # Add change output if needed
    if change_amount > 0:
        # Use provided change script or fall back to UTXO's script
        change_script = change_script_pubkey or bytes.fromhex(utxo["scriptPubKey"])
        change_output = CTxOut(
            value=change_amount,
            script_pubkey=change_script
        )
        tx.vout.append(change_output)

    # Create the asset lock payload with credit output
    pubkey_hash = hash160(asset_lock_pubkey)
    credit_output = CTxOut(
        value=amount,
        script_pubkey=create_p2pkh_script(pubkey_hash)
    )
    payload = CAssetLockPayload(version=1, credit_outputs=[credit_output])
    tx.extra_payload = payload.serialize()

    return tx, tx.serialize()


def get_suitable_utxo(utxos: list[dict[str, Any]], min_amount: int) -> dict[str, Any] | None:
    """Find a suitable UTXO for the asset lock transaction.

    Args:
        utxos: List of UTXOs from listunspent
        min_amount: Minimum amount needed in duffs

    Returns:
        A suitable UTXO or None if not found
    """
    min_amount_dash = min_amount / COIN

    for utxo in utxos:
        if utxo["amount"] >= min_amount_dash and utxo["spendable"]:
            return utxo

    return None

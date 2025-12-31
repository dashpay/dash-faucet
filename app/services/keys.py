import base64
import hashlib
import secrets
from dataclasses import dataclass

from ecdsa import SECP256k1, SigningKey
import base58


def sha256(data: bytes) -> bytes:
    """Single SHA256 hash."""
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Double SHA256 hash."""
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    return hashlib.new("ripemd160", sha256(data)).digest()


@dataclass
class KeyPair:
    """Represents an ECDSA secp256k1 key pair."""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 33 bytes (compressed)

    @property
    def private_key_wif(self) -> str:
        """Get private key in WIF format (testnet)."""
        return bytes_to_wif(self.private_key, compressed=True)

    @property
    def public_key_base64(self) -> str:
        """Get public key as base64 string."""
        return base64.b64encode(self.public_key).decode("ascii")

    @property
    def public_key_hash(self) -> bytes:
        """Get RIPEMD160(SHA256(pubkey)) - used for P2PKH."""
        return hash160(self.public_key)


def generate_key_pair() -> KeyPair:
    """Generate a new ECDSA secp256k1 key pair."""
    private_key_bytes = secrets.token_bytes(32)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()

    # Get compressed public key (33 bytes)
    public_key_point = verifying_key.pubkey.point
    x = public_key_point.x()
    y = public_key_point.y()
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    compressed_pubkey = prefix + x.to_bytes(32, "big")

    return KeyPair(
        private_key=private_key_bytes,
        public_key=compressed_pubkey
    )


def bytes_to_wif(private_key: bytes, compressed: bool = True) -> str:
    """Convert private key bytes to WIF format (testnet).

    Testnet WIF prefix is 0xef (239).
    """
    # Add compression flag if compressed
    key_data = private_key
    if compressed:
        key_data = private_key + b"\x01"

    # Prepend testnet version byte (0xef = 239)
    version_byte = bytes([239])
    data = version_byte + key_data

    # Add checksum (first 4 bytes of double SHA256)
    checksum = hash256(data)[:4]
    data_with_checksum = data + checksum

    # Base58 encode
    return base58.b58encode(data_with_checksum).decode("ascii")


def create_identity_public_key(key_pair: KeyPair, key_id: int = 0) -> dict:
    """Create a public key structure for Platform identity.

    Args:
        key_pair: The key pair to use
        key_id: The key ID (0 for master key)

    Returns:
        Dictionary matching the Platform SDK format
    """
    return {
        "id": key_id,
        "type": 0,           # ECDSA_SECP256K1
        "purpose": 0,        # AUTHENTICATION
        "securityLevel": 0,  # MASTER
        "data": key_pair.public_key_base64,
        "readOnly": False,
        "privateKeyWif": key_pair.private_key_wif
    }

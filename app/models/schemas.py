"""Pydantic models for API request/response schemas."""
from pydantic import BaseModel, Field


class PublicKeyInfo(BaseModel):
    """Platform identity public key structure."""
    id: int = Field(description="Key ID (0 for master key)")
    type: int = Field(default=0, description="Key type: 0=ECDSA_SECP256K1, 1=BLS12_381, 2=ECDSA_HASH160")
    purpose: int = Field(default=0, description="Key purpose: 0=AUTHENTICATION, 1=ENCRYPTION, etc.")
    securityLevel: int = Field(default=0, description="Security level: 0=MASTER, 1=CRITICAL, 2=HIGH, 3=MEDIUM")
    data: str = Field(description="Base64-encoded public key")
    readOnly: bool = Field(default=False, description="Whether the key is read-only")
    privateKeyWif: str = Field(description="Private key in WIF format (for signing)")


class FaucetResponse(BaseModel):
    """Response from the faucet endpoint."""
    assetLockProof: str = Field(description="Hex-encoded JSON asset lock proof")
    assetLockProofPrivateKey: str = Field(description="Private key for the asset lock proof in WIF format")
    publicKeys: list[PublicKeyInfo] = Field(description="Identity public keys array")
    identityId: str | None = Field(default=None, description="Predicted identity ID from the proof (if calculable)")
    txid: str = Field(description="Transaction ID of the asset lock transaction")
    creditsAmount: int = Field(description="Amount of credits locked (in duffs)")


class ErrorResponse(BaseModel):
    """Error response schema."""
    error: str = Field(description="Error message")
    detail: str | None = Field(default=None, description="Additional error details")


class RateLimitResponse(BaseModel):
    """Rate limit error response."""
    error: str = Field(default="Rate limit exceeded")
    retryAfter: int = Field(description="Seconds until rate limit resets")

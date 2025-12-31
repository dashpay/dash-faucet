"""Faucet API router.

Provides the main endpoint for creating identity packages.
"""
import httpx
from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel

from app.config import settings


class FaucetRequest(BaseModel):
    """Request body for faucet endpoint."""
    capToken: str | None = None


class CoreFaucetRequest(BaseModel):
    """Request body for core faucet endpoint."""
    address: str
    capToken: str | None = None


class CoreFaucetResponse(BaseModel):
    """Response for core faucet endpoint."""
    txid: str
    amount: float
    address: str


async def verify_cap_token(token: str) -> bool:
    """Verify a CAP token with the CAP server."""
    if not settings.cap_site_key or not settings.cap_secret:
        return True  # CAP not configured, skip verification

    verify_url = f"{settings.cap_internal_endpoint}/{settings.cap_site_key}/siteverify"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                verify_url,
                json={
                    "secret": settings.cap_secret,
                    "response": token
                },
                timeout=10.0
            )
            result = response.json()
            return result.get("success", False)
    except Exception:
        return False
from app.middleware.rate_limit import rate_limiter
from app.models.schemas import FaucetResponse, ErrorResponse, RateLimitResponse, PublicKeyInfo
from app.services.core_client import dash_client
from app.services.keys import generate_key_pair, create_identity_public_key
from app.services.asset_lock import (
    create_asset_lock_transaction,
    get_suitable_utxo,
    COIN
)
from app.services.instant_lock import wait_for_instant_lock, InstantLockTimeout
from app.services.proof_builder import build_instant_asset_lock_proof


router = APIRouter(prefix="/api", tags=["faucet"])


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check for X-Forwarded-For header (when behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain (original client)
        return forwarded.split(",")[0].strip()

    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct client IP
    if request.client:
        return request.client.host

    return "unknown"


@router.post(
    "/faucet",
    response_model=FaucetResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid captcha"},
        429: {"model": RateLimitResponse, "description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Server error"},
        503: {"model": ErrorResponse, "description": "Service unavailable"}
    }
)
async def create_identity_package(request: Request, body: FaucetRequest = FaucetRequest()) -> FaucetResponse:
    """Create an identity package with asset lock proof and keys.

    This endpoint:
    1. Verifies CAP token (if configured)
    2. Generates keys for the asset lock and identity
    3. Creates an asset lock transaction
    4. Broadcasts it to the network
    5. Waits for InstantSend lock
    6. Returns the proof and keys for identity creation

    Returns:
        FaucetResponse with all data needed to create a Platform identity
    """
    # CAP verification (if configured)
    cap_configured = bool(settings.cap_site_key and settings.cap_secret)
    if cap_configured:
        if not body.capToken:
            raise HTTPException(
                status_code=400,
                detail={"error": "Captcha token required"}
            )
        if not await verify_cap_token(body.capToken):
            raise HTTPException(
                status_code=400,
                detail={"error": "Invalid captcha token"}
            )

    # Rate limiting
    client_ip = get_client_ip(request)
    allowed, retry_after = rate_limiter.is_allowed(client_ip)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "retryAfter": retry_after
            },
            headers={"Retry-After": str(retry_after)}
        )

    try:
        # Generate keys
        # 1. One-time key for asset lock (the proof private key)
        asset_lock_keypair = generate_key_pair()

        # 2. Identity master key (for authentication)
        identity_keypair = generate_key_pair()

        # Get a suitable UTXO
        min_amount = settings.credit_amount + settings.tx_fee
        utxos = dash_client.list_unspent()
        utxo = get_suitable_utxo(utxos, min_amount)

        if utxo is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "No suitable UTXO available",
                    "detail": "The faucet wallet needs to be funded"
                }
            )

        # Create asset lock transaction
        tx, tx_bytes = create_asset_lock_transaction(
            utxo=utxo,
            amount=settings.credit_amount,
            asset_lock_pubkey=asset_lock_keypair.public_key
        )

        # Sign the transaction with the wallet
        sign_result = dash_client.sign_raw_transaction_with_wallet(tx_bytes.hex())

        if not sign_result.get("complete"):
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "Failed to sign transaction",
                    "detail": str(sign_result.get("errors", []))
                }
            )

        signed_tx_hex = sign_result["hex"]
        signed_tx_bytes = bytes.fromhex(signed_tx_hex)

        # Broadcast the transaction
        txid = dash_client.send_raw_transaction(signed_tx_hex)

        # Wait for InstantSend lock
        try:
            islock_bytes = await wait_for_instant_lock(txid)
        except InstantLockTimeout:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "InstantSend lock timeout",
                    "detail": f"Transaction {txid} was broadcast but InstantLock was not received in time"
                }
            )

        # Build the asset lock proof
        asset_lock_proof = build_instant_asset_lock_proof(
            transaction_bytes=signed_tx_bytes,
            instant_lock_bytes=islock_bytes,
            output_index=0  # The burn output is first
        )

        # Create the public keys array for the identity
        public_keys = [
            create_identity_public_key(identity_keypair, key_id=0)
        ]

        # Record successful request for rate limiting
        rate_limiter.record_request(client_ip)

        return FaucetResponse(
            assetLockProof=asset_lock_proof,
            assetLockProofPrivateKey=asset_lock_keypair.private_key_wif,
            publicKeys=[PublicKeyInfo(**pk) for pk in public_keys],
            txid=txid,
            creditsAmount=settings.credit_amount,
            identityId=None  # Could calculate from proof if needed
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error",
                "detail": str(e)
            }
        )


MIN_BALANCE_DASH = 50


@router.get("/status")
async def get_status(response: Response) -> dict:
    """Get faucet status including wallet balance and deposit address."""
    try:
        wallet_info = dash_client.get_wallet_info()
        total_balance = wallet_info["balance"]
        utxos = dash_client.list_unspent()
        available_utxos = len([u for u in utxos if u["amount"] * COIN >= settings.credit_amount + settings.tx_fee])
        deposit_address = dash_client.get_deposit_address()
        block_height = dash_client.get_block_count()

        status = "ok"
        if total_balance < MIN_BALANCE_DASH:
            status = "low_balance"
            response.status_code = 503

        # Build CAP endpoint URL for frontend (use site key path)
        cap_endpoint = None
        if settings.cap_site_key:
            cap_endpoint = f"{settings.cap_api_endpoint}/{settings.cap_site_key}/"

        return {
            "status": status,
            "balance": total_balance,
            "availableUtxos": available_utxos,
            "creditAmount": settings.credit_amount / COIN,
            "coreFaucetAmount": settings.core_faucet_amount,
            "rateLimitPerHour": settings.rate_limit_per_hour,
            "depositAddress": deposit_address,
            "blockHeight": block_height,
            "capEndpoint": cap_endpoint
        }
    except Exception as e:
        response.status_code = 503
        return {
            "status": "error",
            "error": str(e)
        }


@router.post(
    "/core-faucet",
    response_model=CoreFaucetResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request or captcha"},
        429: {"model": RateLimitResponse, "description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Server error"},
        503: {"model": ErrorResponse, "description": "Service unavailable"}
    }
)
async def core_faucet(request: Request, body: CoreFaucetRequest) -> CoreFaucetResponse:
    """Send testnet DASH to a provided address.

    This endpoint:
    1. Verifies CAP token (if configured)
    2. Validates the address
    3. Sends DASH to the address
    4. Returns the transaction ID

    Returns:
        CoreFaucetResponse with txid and amount sent
    """
    # CAP verification (if configured)
    cap_configured = bool(settings.cap_site_key and settings.cap_secret)
    if cap_configured:
        if not body.capToken:
            raise HTTPException(
                status_code=400,
                detail={"error": "Captcha token required"}
            )
        if not await verify_cap_token(body.capToken):
            raise HTTPException(
                status_code=400,
                detail={"error": "Invalid captcha token"}
            )

    # Rate limiting
    client_ip = get_client_ip(request)
    allowed, retry_after = rate_limiter.is_allowed(client_ip)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "retryAfter": retry_after
            },
            headers={"Retry-After": str(retry_after)}
        )

    # Validate address format (basic check for testnet address)
    address = body.address.strip()
    if not address or len(address) < 26:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid address format"}
        )

    try:
        # Send DASH to the address
        txid = dash_client.send_to_address(address, settings.core_faucet_amount)

        # Record successful request for rate limiting
        rate_limiter.record_request(client_ip)

        return CoreFaucetResponse(
            txid=txid,
            amount=settings.core_faucet_amount,
            address=address
        )

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        # Check for common RPC errors
        if "Invalid address" in error_msg or "Invalid Dash address" in error_msg:
            raise HTTPException(
                status_code=400,
                detail={"error": "Invalid Dash address"}
            )
        if "Insufficient funds" in error_msg:
            raise HTTPException(
                status_code=503,
                detail={"error": "Faucet has insufficient funds"}
            )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error",
                "detail": error_msg
            }
        )

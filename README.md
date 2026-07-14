# Dash Platform Identity Faucet

A faucet service for Dash Platform that provides:

- **Platform Credits**: Creates asset lock transactions to fund Dash Platform identities
- **Core DASH**: Dispenses testnet DASH for L1 transactions

## Requirements

- Docker and Docker Compose
- Dash Core node (included in docker-compose)

## Quick Start

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Start the services:
   ```bash
   docker compose up -d
   ```

3. Access the faucet at http://localhost:8000

The first startup will take time while Dash Core syncs with testnet.

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DASH_RPC_USER` | Dash Core RPC username | `dashrpc` |
| `DASH_RPC_PASSWORD` | Dash Core RPC password | - |
| `DASH_RPC_HOST` | Dash Core RPC host | `localhost` |
| `DASH_RPC_PORT` | Dash Core RPC port | `19998` |
| `RATE_LIMIT_PER_HOUR` | Requests per IP per hour | `3` |
| `CREDIT_AMOUNT` | Platform credits in duffs | `100000000` |
| `CORE_FAUCET_AMOUNT` | DASH amount for core faucet | `1.0` |
| `CAP_SITE_KEY` | CAP captcha site key | - |
| `CAP_SECRET` | CAP captcha secret | - |
| `FAUCET_API_KEY_HASHES` | JSON map of trusted API key IDs to SHA-256 hashes | - |
| `FAUCET_API_KEY_DAILY_LIMIT` | Successful payouts allowed per trusted key per rolling 24 hours | `100` |

## Architecture

- **faucet**: FastAPI application serving the web UI and API
- **dashcore**: Dash Core node for transaction signing and broadcasting
- **cap**: CAP captcha service for rate limiting protection

## API Endpoints

- `GET /api/status` - Faucet status, balance, and deposit address
- `POST /api/identity-package` - Get an identity package with asset lock proof
- `POST /api/core-faucet` - Request testnet DASH
- `POST /api/v1/core-faucet` - Trusted bearer-key tDASH payout without browser CAPTCHA or public IP limits

### Trusted API

The trusted endpoint requires `Authorization: Bearer <key>` and accepts only an
`address` field. API keys are configured as SHA-256 hashes so plaintext keys do
not need to be stored by the faucet.

```bash
curl -X POST https://faucet.testnet.networks.dash.org/api/v1/core-faucet \
  -H "Authorization: Bearer $FAUCET_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"address":"YOUR_TESTNET_DASH_ADDRESS"}'
```

This endpoint bypasses the browser CAPTCHA and public IP rate limit, but retains
a per-key rolling daily limit. Promo codes are not accepted by the trusted API.

## Development

Run locally without Docker:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## License

MIT License - see [LICENSE](LICENSE) for details.

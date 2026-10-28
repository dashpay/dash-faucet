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
| `DASH_RPC_PASSWORD` | Dash Core RPC password (required by `docker-compose.yml`) | - |
| `DASH_RPC_HOST` | Dash Core RPC host | `localhost` |
| `DASH_RPC_PORT` | Dash Core RPC port | `19998` |
| `RATE_LIMIT_PER_HOUR` | Requests per IP per hour | `3` |
| `TRUSTED_PROXY_HOPS` | Proxies in front of the app that append to `X-Forwarded-For` (AWS ALB, Cloudflare tunnel, nginx: 1 each). The client IP is read that many entries from the right; `0` ignores the header | `1` |
| `CREDIT_AMOUNT` | Platform credits in duffs | `100000000` |
| `CORE_FAUCET_AMOUNT` | DASH amount for core faucet | `1.0` |
| `CAP_SITE_KEY` | CAP captcha site key | - |
| `CAP_SECRET` | CAP captcha secret | - |
| `CAP_HARD_SITE_KEY` / `CAP_HARD_SECRET` | Harder CAP that lifts the per-IP limit after a 429 | - |
| `PROMO_CODES` | JSON map of promo codes, e.g. `{"CODE": {"amount": 5.0}}`; merged over `promo_codes.json` | - |

## Architecture

- **faucet**: FastAPI application serving the web UI and API
- **dashcore**: Dash Core node for transaction signing and broadcasting
- **cap**: CAP captcha service for rate limiting protection

## API Endpoints

- `GET /api/status` - Faucet status, balance, and deposit address
- `POST /api/asset-lock-proof` - Asset lock proof for a client-generated public key
- `POST /api/faucet` - Identity package with server-generated keys (legacy)
- `POST /api/core-faucet` - Request testnet DASH

## Security notes

- Dash Core RPC holds the faucet wallet. `docker-compose.yml` binds it to
  loopback on the host and `dash.conf` only allows private networks; never
  publish port 19998.
- Set `TRUSTED_PROXY_HOPS` to the number of proxies in front of the faucet. Too
  high lets clients choose their rate-limit bucket; too low puts every user in
  the proxy's bucket (the app logs a warning if the client IP looks private).
- Keep real promo codes in `PROMO_CODES`, not in the public `promo_codes.json`.

## Development

Run locally without Docker:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## License

MIT License - see [LICENSE](LICENSE) for details.

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from typing import Any

from app.config import settings

WALLET_NAME = "faucet"
DEPOSIT_LABEL = "deposit"


class DashCoreClient:
    """Client for interacting with Dash Core RPC."""

    def __init__(self):
        self._rpc_url = (
            f"http://{settings.dash_rpc_user}:{settings.dash_rpc_password}"
            f"@{settings.dash_rpc_host}:{settings.dash_rpc_port}"
        )
        self._rpc: AuthServiceProxy | None = None
        self._deposit_address: str | None = None

    @property
    def rpc(self) -> AuthServiceProxy:
        if self._rpc is None:
            self._rpc = AuthServiceProxy(self._rpc_url)
        return self._rpc

    def _reconnect(self) -> AuthServiceProxy:
        """Create a new RPC connection."""
        self._rpc = AuthServiceProxy(self._rpc_url)
        return self._rpc

    def _call(self, method: str, *args) -> Any:
        """Call RPC method with automatic reconnection on failure."""
        try:
            return getattr(self.rpc, method)(*args)
        except (ConnectionError, BrokenPipeError, OSError):
            self._reconnect()
            return getattr(self.rpc, method)(*args)

    def list_unspent(self, min_conf: int = 1, max_conf: int = 9999999) -> list[dict[str, Any]]:
        """Get list of unspent transaction outputs."""
        return self._call("listunspent", min_conf, max_conf)

    def send_raw_transaction(self, hex_tx: str) -> str:
        """Broadcast a raw transaction and return txid."""
        return self._call("sendrawtransaction", hex_tx)

    def get_raw_transaction(self, txid: str, verbose: bool = True) -> dict[str, Any]:
        """Get raw transaction data."""
        return self._call("getrawtransaction", txid, verbose)

    def get_islocks(self, txids: list[str]) -> list[Any]:
        """Get InstantSend lock data for transactions."""
        return self._call("getislocks", txids)

    def sign_raw_transaction_with_wallet(self, hex_tx: str) -> dict[str, Any]:
        """Sign a raw transaction with wallet keys."""
        return self._call("signrawtransactionwithwallet", hex_tx)

    def get_new_address(self) -> str:
        """Generate a new wallet address."""
        return self._call("getnewaddress")

    def dump_priv_key(self, address: str) -> str:
        """Get private key for an address in WIF format."""
        return self._call("dumpprivkey", address)

    def get_block_count(self) -> int:
        """Get current block height."""
        return self._call("getblockcount")

    def get_wallet_info(self) -> dict[str, Any]:
        """Get wallet info including balance."""
        return self._call("getwalletinfo")

    def create_raw_transaction(self, inputs: list, outputs: dict) -> str:
        """Create a raw transaction. Returns hex."""
        return self._call("createrawtransaction", inputs, outputs)

    def fund_raw_transaction(self, hex_tx: str, options: dict | None = None) -> dict[str, Any]:
        """Fund a raw transaction. Returns dict with hex, fee, changepos."""
        if options:
            return self._call("fundrawtransaction", hex_tx, options)
        return self._call("fundrawtransaction", hex_tx)

    def send_to_address(self, address: str, amount: float) -> str:
        """Send DASH to an address with change to deposit address. Returns txid."""
        # Create raw tx with just the output
        raw_tx = self.create_raw_transaction([], {address: amount})

        # Fund it with change going to deposit address
        deposit_addr = self.get_deposit_address()
        funded = self.fund_raw_transaction(raw_tx, {"changeAddress": deposit_addr})

        # Sign and broadcast
        signed = self.sign_raw_transaction_with_wallet(funded["hex"])
        if not signed.get("complete"):
            raise Exception("Transaction signing failed")

        return self.send_raw_transaction(signed["hex"])

    def get_address_info(self, address: str) -> dict[str, Any]:
        """Get information about an address including scriptPubKey."""
        return self._call("getaddressinfo", address)

    def get_deposit_address(self) -> str:
        """Get the static deposit address, creating if needed."""
        if self._deposit_address:
            return self._deposit_address

        # Try to get existing address with deposit label
        try:
            addresses = self._call("getaddressesbylabel", DEPOSIT_LABEL)
            if addresses:
                self._deposit_address = list(addresses.keys())[0]
                return self._deposit_address
        except JSONRPCException:
            pass

        # Create new address with deposit label
        self._deposit_address = self._call("getnewaddress", DEPOSIT_LABEL)
        return self._deposit_address

    def ensure_wallet(self) -> None:
        """Ensure the faucet wallet exists and is loaded."""
        try:
            self.rpc.getwalletinfo()
        except JSONRPCException as e:
            if e.code == -18:  # No wallet loaded
                # Try to load existing wallet first
                try:
                    self.rpc.loadwallet(WALLET_NAME)
                except JSONRPCException as load_err:
                    if load_err.code == -18:  # Wallet doesn't exist
                        self.rpc.createwallet(WALLET_NAME)
                    else:
                        raise
                self._reconnect()
            else:
                raise
        # Initialize the deposit address
        self.get_deposit_address()


# Global client instance
dash_client = DashCoreClient()

"""Local ordinary ecash mint for marketplace development and tests.

Runs Nutshell with the FakeWallet Lightning backend (invoices settle on their
own, like testnut) and activates a pre-v3 secp256k1 keyset, because NUT-14
HTLC secrets are not valid on the v3 keysets this Nutshell version creates
by default. Fake value only; never point real funds at it.

    poetry run python -m cashu.nft.dev_ecash_mint --port 3339 --fee-ppk 0
"""

import argparse
from pathlib import Path

import uvicorn

from cashu.core.settings import settings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=3339)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--data", default="data/dev-ecash-mint")
    parser.add_argument("--fee-ppk", type=int, default=0)
    args = parser.parse_args()

    # Settings are a module singleton that may already be loaded (importing
    # this package loads it), so configure it directly like tests/conftest.py.
    data = Path(args.data).resolve()
    data.mkdir(parents=True, exist_ok=True)
    settings.mint_backend_bolt11_sat = "FakeWallet"
    settings.mint_backend_bolt11_usd = "FakeWallet"
    settings.mint_database = str(data)
    settings.mint_private_key = "DEV_ONLY_FAKE_VALUE_MINT_KEY"
    settings.mint_listen_host = args.host
    settings.mint_listen_port = args.port
    settings.mint_url = f"http://{args.host}:{args.port}"
    settings.mint_input_fee_ppk = args.fee_ppk
    settings.fakewallet_brr = True
    settings.fakewallet_delay_incoming_payment = 1
    settings.fakewallet_stochastic_invoice = False
    settings.tor = False
    settings.debug = False
    settings.cashu_dir = str(data / "cashu")
    settings.mint_rpc_server_enable = False
    settings.mint_watchdog_enabled = False
    settings.mint_transaction_rate_limit_per_minute = 600
    # Deliberately lazy: cashu.mint.app builds the ledger from settings at
    # import time, so these imports must follow the configuration above.
    from cashu.mint.ledger import Ledger

    startup = Ledger._startup_keysets

    async def with_legacy_keyset(ledger: Ledger) -> None:
        await startup(ledger)
        await ledger.activate_keyset(derivation_path="m/0'/0'/1'", version="0.20.0")

    Ledger._startup_keysets = with_legacy_keyset  # type: ignore[method-assign,assignment]
    from cashu.mint.app import app

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

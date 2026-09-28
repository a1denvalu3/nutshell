"""Run the experimental PS-NFT service directly:

    NFT_MINT_SEED="at-least-16-bytes" poetry run python -m cashu.nft

Environment:
    NFT_DB_DIR          sqlite location (default: data/nft)
    NFT_MINT_SEED       mint key seed; random ephemeral key if unset
    NFT_PAYMENT_SECRET  if set, minting requires HMAC payment tickets
                        from this secret (see cashu/nft/payment.py)
    NFT_PORT            default 8338
"""

import asyncio
import os

import uvicorn
from loguru import logger

from ..core.crypto.ps import MintPrivateKeyPS
from ..core.db import Database
from .api import create_app
from .ledger import PSLedger
from .payment import DevPaymentVerifier


def main() -> None:
    db_dir = os.environ.get("NFT_DB_DIR", "data/nft")
    seed = os.environ.get("NFT_MINT_SEED")
    if seed:
        mint_key = MintPrivateKeyPS.from_seed(seed.encode())
    else:
        logger.warning("NFT_MINT_SEED unset: using a random ephemeral mint key")
        mint_key = MintPrivateKeyPS()
    payment_secret = os.environ.get("NFT_PAYMENT_SECRET")
    verifier = DevPaymentVerifier(payment_secret.encode()) if payment_secret else None
    ledger = PSLedger(Database("nft", db_dir), mint_key, payment_verifier=verifier)
    asyncio.run(ledger.migrate())
    logger.info(
        f"PS-NFT service on :{os.environ.get('NFT_PORT', '8338')}, "
        f"keyset {ledger.keyset.keyset_id}, "
        f"payment {'required' if verifier else 'not required'}"
    )
    uvicorn.run(
        create_app(ledger),
        host="127.0.0.1",
        port=int(os.environ.get("NFT_PORT", "8338")),
    )


if __name__ == "__main__":
    main()

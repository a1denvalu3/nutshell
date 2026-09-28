"""Mounting the experimental PS-NFT service inside the ecash mint.

When MINT_NFT_MODULE is enabled, the mint's FastAPI app includes the NFT
router under /v1/nft, so one server (and one URL) serves both ecash and
NFT endpoints. The NFT mint key derives from NFT_MINT_SEED if set, else
from the mint's own MINT_PRIVATE_KEY, so the existing mint backup
covers it; the NFT tables live in a separate nft.sqlite3 next to the
mint database.

Payment: with NFT_MINT_PRICE_SATS > 0 (default 21), minting an NFT
requires a quote backed by a real BOLT11 mint quote on the hosting
mint's own ledger, payable with any Lightning wallet. Set
NFT_MINT_PRICE_SATS=0 for free minting.
"""

import os
from typing import Optional, Tuple

from fastapi import APIRouter
from loguru import logger

from ..core.crypto.ps import MintPrivateKeyPS
from ..core.db import Database
from ..core.settings import settings
from .api import create_router
from .ledger import PSLedger
from .quotes import DEFAULT_PRICE_SATS, EcashQuoteBackend


def build_ledger() -> PSLedger:
    seed: Optional[str] = os.environ.get("NFT_MINT_SEED") or settings.mint_private_key
    if seed:
        mint_key = MintPrivateKeyPS.from_seed(seed.encode())
    else:
        logger.warning(
            "NFT module: neither NFT_MINT_SEED nor MINT_PRIVATE_KEY set, "
            "using a random ephemeral key"
        )
        mint_key = MintPrivateKeyPS()
    price = int(os.environ.get("NFT_MINT_PRICE_SATS", str(DEFAULT_PRICE_SATS)))
    backend = None
    if price > 0:
        # the hosting mint's own ledger provides real BOLT11 quotes
        from ..mint.startup import ledger as mint_ledger

        backend = EcashQuoteBackend(mint_ledger, price_sats=price)
        logger.info(f"NFT module: minting requires a {price} sat quote")
    return PSLedger(
        Database("nft", settings.mint_database), mint_key, quote_backend=backend
    )


def build_router_and_ledger() -> Tuple[APIRouter, PSLedger]:
    ledger = build_ledger()
    return create_router(ledger), ledger

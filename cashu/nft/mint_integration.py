"""Mounting the experimental PS-NFT service inside the ecash mint.

When MINT_NFT_MODULE is enabled, the mint's FastAPI app includes the NFT
router under /v1/nft, so one server (and one URL) serves both ecash and
NFT endpoints. The NFT mint key derives from NFT_MINT_SEED if set, else
from the mint's own MINT_PRIVATE_KEY, so the existing mint backup
covers it; the NFT tables live in a separate nft.sqlite3 next to the
mint database.
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
from .payment import DevPaymentVerifier


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
    payment_secret = os.environ.get("NFT_PAYMENT_SECRET")
    verifier = DevPaymentVerifier(payment_secret.encode()) if payment_secret else None
    return PSLedger(
        Database("nft", settings.mint_database), mint_key, payment_verifier=verifier
    )


def build_router_and_ledger() -> Tuple[APIRouter, PSLedger]:
    ledger = build_ledger()
    return create_router(ledger), ledger

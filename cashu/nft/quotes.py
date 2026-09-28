"""Quote-based payment for NFT minting, NUT-04 style.

Minting an NFT requires a quote: the user requests one for an asset
hash, settles it out of band, and presents the quote id at minting
time. The quote is consumed atomically with issuance, so one quote
mints exactly one NFT.

Two backends:
    EcashQuoteBackend -- mounted in a Nutshell mint: quotes are real
        BOLT11 mint quotes on the mint's own ledger, payable with any
        Lightning wallet.
    DevQuoteBackend   -- standalone/dev: the operator settles a quote
        by issuing an HMAC ticket over the quote id.
"""

import hashlib
import hmac
from abc import ABC, abstractmethod
from typing import Tuple

from ..core.base import MintQuoteState
from ..core.models.mint_quote import PostMintQuoteRequest

QUOTE_TICKET_DST = b"Cashu_PS_NFT_Quote_v1"

DEFAULT_PRICE_SATS = 21


class QuoteBackend(ABC):
    price_sats: int = 0

    @abstractmethod
    async def create_quote(self, quote_id: str, h: int) -> Tuple[int, str, str]:
        """Return (amount_sats, request, external_quote_id) for a new
        quote. `request` is the BOLT11 invoice for the ecash backend, or
        a human-readable hint for the dev backend. `external_quote_id`
        links to the settlement system's own quote (empty for dev)."""
        ...

    @abstractmethod
    async def is_paid(self, quote_id: str, external_quote: str) -> bool:
        """Check external settlement state for a pending quote."""
        ...

    def dev_pay_ticket(self, quote_id: str, ticket: bytes) -> bool:
        """Settle a quote directly (dev backends only)."""
        raise NotImplementedError("this backend does not take dev tickets")

    def issue_dev_ticket(self, quote_id: str) -> bytes:
        """Operator side of dev_pay_ticket (dev backends only)."""
        raise NotImplementedError("this backend does not issue dev tickets")


class DevQuoteBackend(QuoteBackend):
    def __init__(self, secret: bytes, price_sats: int = DEFAULT_PRICE_SATS):
        if len(secret) < 16:
            raise ValueError("payment secret must be at least 16 bytes")
        self.secret = secret
        self.price_sats = price_sats

    def _ticket(self, quote_id: str) -> bytes:
        return hmac.new(
            self.secret, QUOTE_TICKET_DST + quote_id.encode(), hashlib.sha256
        ).digest()

    def issue_dev_ticket(self, quote_id: str) -> bytes:
        return self._ticket(quote_id)

    def dev_pay_ticket(self, quote_id: str, ticket: bytes) -> bool:
        return hmac.compare_digest(ticket, self._ticket(quote_id))

    async def create_quote(self, quote_id: str, h: int) -> Tuple[int, str, str]:
        return self.price_sats, f"dev-settle quote {quote_id} with `nft dev-pay`", ""

    async def is_paid(self, quote_id: str, external_quote: str) -> bool:
        return False  # dev quotes are settled explicitly via dev_pay_ticket


class EcashQuoteBackend(QuoteBackend):
    """Quotes are real BOLT11 mint quotes on the hosting mint's ledger,
    so paying an NFT quote is paying a normal ecash mint quote with any
    Lightning wallet."""

    def __init__(self, mint_ledger, price_sats: int = DEFAULT_PRICE_SATS):
        self.mint_ledger = mint_ledger
        self.price_sats = price_sats

    async def create_quote(self, quote_id: str, h: int) -> Tuple[int, str, str]:
        mint_quote = await self.mint_ledger.mint_quote(
            PostMintQuoteRequest(amount=self.price_sats, unit="sat")
        )
        if mint_quote.state != MintQuoteState.unpaid:
            raise RuntimeError("unexpected state for a fresh mint quote")
        return self.price_sats, mint_quote.request, mint_quote.quote

    async def is_paid(self, quote_id: str, external_quote: str) -> bool:
        if not external_quote:
            return False
        quote = await self.mint_ledger.get_mint_quote(external_quote)
        return quote is not None and quote.state == MintQuoteState.paid

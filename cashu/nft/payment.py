"""Pluggable payment gate for NFT issuance.

PSLedger.issue_nft delegates payment checks to a PaymentVerifier when one
is configured; with no verifier configured, minting is free (dev mode).

DevPaymentVerifier is a stand-in for a real Lightning/ecash integration:
the operator issues an HMAC ticket per asset hash out of band (e.g. after
settling an invoice) and the buyer presents it at minting time. Tickets
are naturally single-use per asset because the ledger only ever mints
each asset hash once.
"""

import hashlib
import hmac
from abc import ABC, abstractmethod
from typing import Optional

from .ledger import PaymentError

PAYMENT_TICKET_DST = b"Cashu_PS_NFT_Payment_v1"


class PaymentVerifier(ABC):
    @abstractmethod
    async def verify_payment(self, payment: Optional[bytes], h: int) -> None:
        """Raise PaymentError if the payment is missing or invalid for
        minting the asset with hash h."""
        ...


class DevPaymentVerifier(PaymentVerifier):
    def __init__(self, secret: bytes):
        if len(secret) < 16:
            raise ValueError("payment secret must be at least 16 bytes")
        self.secret = secret

    def _ticket(self, h: int) -> bytes:
        return hmac.new(
            self.secret,
            PAYMENT_TICKET_DST + h.to_bytes(32, "big"),
            hashlib.sha256,
        ).digest()

    def issue_ticket(self, h: int) -> bytes:
        """Operator side: mint a payment ticket for an asset hash."""
        return self._ticket(h)

    async def verify_payment(self, payment: Optional[bytes], h: int) -> None:
        if payment is None:
            raise PaymentError("payment required")
        if not hmac.compare_digest(payment, self._ticket(h)):
            raise PaymentError("invalid payment ticket")

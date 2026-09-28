"""Persistent ledger for the experimental PS-credential NFT service.

State:
    ps_assets     -- one row per minted asset: h -> current owner commitment
    ps_nullifiers -- spent presentation nullifiers (double-spend prevention)
    ps_quotes     -- mint quotes: h -> settlement state (one NFT per quote)

Invariants enforced here, on top of the cryptography in
cashu/core/crypto/ps.py:
    * one credential per asset hash, enforced by the ps_assets primary key
    * a presentation can be spent exactly once, enforced by claiming the
      nullifier inside the same transaction that moves ownership
    * transfers are atomic: proof checks, nullifier claim, ownership move
      and re-issuance either all commit or all roll back
    * a paid quote mints exactly one NFT, enforced by consuming the quote
      in the same transaction that inserts the asset
"""

import uuid
from typing import Optional, Tuple

from sqlalchemy.exc import IntegrityError

from ..core.crypto.bls import PublicKey
from ..core.crypto.ps import (
    DlogEqProof,
    MintPrivateKeyPS,
    MintPublicKeyPS,
    Presentation,
    PrivatePresentation,
    blind_base_for_nullifier,
    issue,
    issue_blind,
    verify_blind_transfer,
    verify_owner_secret,
    verify_presentation,
)
from ..core.db import Connection, Database, LockOptions
from .quotes import QuoteBackend
from .registry import sign_registry_entry


class NFTError(Exception):
    pass


class AlreadyMintedError(NFTError):
    pass


class UnknownAssetError(NFTError):
    pass


class UnknownQuoteError(NFTError):
    pass


class NotOwnerError(NFTError):
    pass


class AlreadySpentError(NFTError):
    pass


class InvalidProofError(NFTError):
    pass


class PaymentError(NFTError):
    pass


def _h_hex(h: int) -> str:
    return h.to_bytes(32, "big").hex()


class PSLedger:
    def __init__(
        self,
        db: Database,
        mint_key: MintPrivateKeyPS,
        quote_backend: Optional[QuoteBackend] = None,
    ):
        self.db = db
        self.mint_key = mint_key
        # Optional pluggable payment gate, see cashu/nft/quotes.py. When
        # set, issue_nft requires a settled quote.
        self.quote_backend = quote_backend

    @property
    def keyset(self) -> MintPublicKeyPS:
        return self.mint_key.public_key

    async def migrate(self) -> None:
        async with self.db.get_connection() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ps_assets (
                    h TEXT PRIMARY KEY,
                    owner BLOB NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    epoch INTEGER NOT NULL DEFAULT 0,
                    created TEXT NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ps_nullifiers (
                    nullifier BLOB PRIMARY KEY,
                    h TEXT NOT NULL,
                    spent TEXT NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ps_quotes (
                    quote TEXT PRIMARY KEY,
                    h TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    request TEXT NOT NULL DEFAULT '',
                    external_quote TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'unpaid',
                    created TEXT NOT NULL
                )
                """
            )

    async def create_quote(self, h: int) -> dict:
        """Create a mint quote for asset hash h. Settle it out of band,
        then mint with the quote id."""
        if self.quote_backend is None:
            raise PaymentError("this mint does not require quotes")
        quote_id = uuid.uuid4().hex
        amount, request, external = await self.quote_backend.create_quote(quote_id, h)
        async with self.db.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO ps_quotes (quote, h, amount, request, external_quote, state, created)
                VALUES (:quote, :h, :amount, :request, :external, 'unpaid', :created)
                """,
                {
                    "quote": quote_id,
                    "h": _h_hex(h),
                    "amount": amount,
                    "request": request,
                    "external": external,
                    "created": self.db.timestamp_now_str(),
                },
            )
        return {
            "quote": quote_id,
            "asset_hash": _h_hex(h),
            "amount": amount,
            "request": request,
            "state": "unpaid",
        }

    async def _sync_quote(self, conn: Connection, quote_id: str) -> dict:
        row = await conn.fetchone(
            "SELECT * FROM ps_quotes WHERE quote = :quote", {"quote": quote_id}
        )
        if row is None:
            raise UnknownQuoteError("unknown quote")
        if (
            row["state"] == "unpaid"
            and self.quote_backend is not None
            and await self.quote_backend.is_paid(quote_id, row["external_quote"])
        ):
            await conn.execute(
                "UPDATE ps_quotes SET state = 'paid' WHERE quote = :quote",
                {"quote": quote_id},
            )
            row = dict(row)
            row["state"] = "paid"
        return row

    async def get_quote(self, quote_id: str) -> dict:
        async with self.db.get_connection() as conn:
            row = await self._sync_quote(conn, quote_id)
        return {
            "quote": quote_id,
            "asset_hash": row["h"],
            "amount": row["amount"],
            "request": row["request"],
            "state": row["state"],
        }

    async def dev_pay_quote(self, quote_id: str, ticket: bytes) -> None:
        """Settle a quote with a dev ticket (dev backends only)."""
        if self.quote_backend is None:
            raise PaymentError("this mint does not require quotes")
        try:
            valid = self.quote_backend.dev_pay_ticket(quote_id, ticket)
        except NotImplementedError:
            raise PaymentError("this backend does not take dev tickets")
        if not valid:
            raise PaymentError("invalid payment ticket")
        async with self.db.get_connection() as conn:
            result = await conn.execute(
                "UPDATE ps_quotes SET state = 'paid' WHERE quote = :quote AND state = 'unpaid'",
                {"quote": quote_id},
            )
            if result.rowcount != 1:
                raise UnknownQuoteError("unknown or already settled quote")

    async def issue_nft(
        self,
        h: int,
        S: PublicKey,
        pok: DlogEqProof,
        quote: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[PublicKey, PublicKey]:
        """Mint the credential for asset hash h to owner commitment S,
        consuming a settled quote when the mint requires payment."""
        if not verify_owner_secret(S, pok):
            raise InvalidProofError("invalid owner secret proof")
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_assets")]
        ) as c:
            if self.quote_backend is not None:
                if not quote:
                    raise PaymentError("mint quote required")
                row = await self._sync_quote(c, quote)
                if row["h"] != _h_hex(h):
                    raise PaymentError("quote is for a different asset")
                if row["state"] == "unpaid":
                    raise PaymentError("quote is not paid")
                result = await c.execute(
                    "UPDATE ps_quotes SET state = 'used' WHERE quote = :quote AND state = 'paid'",
                    {"quote": quote},
                )
                if result.rowcount != 1:
                    raise AlreadySpentError("quote was already used")
            try:
                await c.execute(
                    """
                    INSERT INTO ps_assets (h, owner, status, created)
                    VALUES (:h, :owner, 'active', :created)
                    """,
                    {
                        "h": _h_hex(h),
                        "owner": S.format(),
                        "created": self.db.timestamp_now_str(),
                    },
                )
            except IntegrityError:
                raise AlreadyMintedError("asset was already minted")
        return issue(self.mint_key, h, S)

    async def get_owner(self, h: int) -> Optional[bytes]:
        """Current owner commitment for an active asset, None if unknown
        or burned."""
        row = await self.db.fetchone(
            "SELECT owner, status FROM ps_assets WHERE h = :h", {"h": _h_hex(h)}
        )
        if row is None or row["status"] != "active":
            return None
        return bytes(row["owner"])

    async def is_spent(self, nullifier: bytes) -> bool:
        row = await self.db.fetchone(
            "SELECT 1 AS x FROM ps_nullifiers WHERE nullifier = :n", {"n": nullifier}
        )
        return row is not None

    async def registry_entry(self, h: int) -> Optional[Tuple[bytes, int, bytes]]:
        """Signed registry entry (owner, epoch, signature) for an active
        asset, verifiable offline against the keyset's X2."""
        row = await self.db.fetchone(
            "SELECT owner, epoch FROM ps_assets WHERE h = :h AND status = 'active'",
            {"h": _h_hex(h)},
        )
        if row is None:
            return None
        owner = bytes(row["owner"])
        epoch = int(row["epoch"])
        sig = sign_registry_entry(self.mint_key, h, owner, epoch)
        return owner, epoch, sig.format()

    async def _spend(
        self,
        pres: Presentation,
        conn: Connection,
    ) -> None:
        """Verify a presentation and claim its nullifier, atomically with
        the caller's transaction. The asset must be active and the
        presentation must come from the registered owner."""
        if pres.keyset_id and pres.keyset_id != self.keyset.keyset_id:
            raise InvalidProofError("unknown keyset")
        if not verify_presentation(self.keyset, pres):
            raise InvalidProofError("invalid presentation")
        if await conn.fetchone(
            "SELECT 1 AS x FROM ps_nullifiers WHERE nullifier = :n",
            {"n": pres.nullifier.format()},
        ):
            raise AlreadySpentError("credential already spent")
        row = await conn.fetchone(
            "SELECT owner, status FROM ps_assets WHERE h = :h",
            {"h": _h_hex(pres.h)},
        )
        if row is None:
            raise UnknownAssetError("unknown asset")
        if row["status"] != "active":
            raise UnknownAssetError("asset is burned")
        if bytes(row["owner"]) != pres.owner_commitment.format():
            raise NotOwnerError("presentation is not from the registered owner")
        try:
            await conn.execute(
                """
                INSERT INTO ps_nullifiers (nullifier, h, spent)
                VALUES (:n, :h, :spent)
                """,
                {
                    "n": pres.nullifier.format(),
                    "h": _h_hex(pres.h),
                    "spent": self.db.timestamp_now_str(),
                },
            )
        except IntegrityError:
            raise AlreadySpentError("credential already spent")

    async def transfer(
        self,
        pres: Presentation,
        S_new: PublicKey,
        pok_new: DlogEqProof,
        conn: Optional[Connection] = None,
    ) -> Tuple[PublicKey, PublicKey]:
        """Atomically spend pres and re-issue the asset to S_new."""
        if not verify_owner_secret(S_new, pok_new):
            raise InvalidProofError("invalid new owner secret proof")
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_nullifiers")]
        ) as c:
            await self._spend(pres, c)
            await c.execute(
                "UPDATE ps_assets SET owner = :owner, epoch = epoch + 1 WHERE h = :h",
                {"owner": S_new.format(), "h": _h_hex(pres.h)},
            )
        return issue(self.mint_key, pres.h, S_new)

    async def burn(self, pres: Presentation, conn: Optional[Connection] = None) -> None:
        """Retire an asset: spend the credential without re-issuing."""
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_nullifiers")]
        ) as c:
            await self._spend(pres, c)
            await c.execute(
                "UPDATE ps_assets SET status = 'burned' WHERE h = :h",
                {"h": _h_hex(pres.h)},
            )

    async def transfer_private_begin(self, nullifier: bytes) -> PublicKey:
        """Round 1 of a hidden-h transfer: hand out the deterministic
        blind base u2 for this nullifier. Stateless."""
        if len(nullifier) != 48:
            raise InvalidProofError("nullifier must be a compressed G1 point")
        _, u2 = blind_base_for_nullifier(self.mint_key, nullifier)
        return u2

    async def transfer_private(
        self,
        pres: PrivatePresentation,
        w_h: PublicKey,
        proof: DlogEqProof,
        S_new: PublicKey,
        pok_new: DlogEqProof,
        conn: Optional[Connection] = None,
    ) -> Tuple[PublicKey, PublicKey]:
        """Atomically spend a hidden-h presentation and blindly re-issue
        the same asset to S_new. The asset hash never reaches the mint;
        the registry row is located by the old owner commitment, which
        must be unique among active assets."""
        if not verify_owner_secret(S_new, pok_new):
            raise InvalidProofError("invalid new owner secret proof")
        if pres.keyset_id and pres.keyset_id != self.keyset.keyset_id:
            raise InvalidProofError("unknown keyset")
        k2, u2 = blind_base_for_nullifier(self.mint_key, pres.nullifier.format())
        if not verify_blind_transfer(self.keyset, pres, w_h, proof, u2):
            raise InvalidProofError("invalid private transfer proof")
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_nullifiers")]
        ) as c:
            if await c.fetchone(
                "SELECT 1 AS x FROM ps_nullifiers WHERE nullifier = :n",
                {"n": pres.nullifier.format()},
            ):
                raise AlreadySpentError("credential already spent")
            await c.execute(
                """
                INSERT INTO ps_nullifiers (nullifier, h, spent)
                VALUES (:n, '', :spent)
                """,
                {"n": pres.nullifier.format(), "spent": self.db.timestamp_now_str()},
            )
            result = await c.execute(
                """
                UPDATE ps_assets SET owner = :owner, epoch = epoch + 1
                WHERE owner = :old_owner AND status = 'active'
                """,
                {"owner": S_new.format(), "old_owner": pres.owner_commitment.format()},
            )
            if result.rowcount != 1:
                raise UnknownAssetError(
                    "no unique active asset for this owner commitment"
                )
        return u2, issue_blind(self.mint_key, k2, u2, w_h, S_new)

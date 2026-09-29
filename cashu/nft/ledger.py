"""Persistent ledger for the experimental PS-credential NFT service.

State:
    ps_assets     -- one row per minted asset: h -> status (active/burned)
    ps_nullifiers -- spent presentation nullifiers (double-spend prevention)
    ps_quotes     -- mint quotes: h -> settlement state (one NFT per quote)

There is no owner column and no ownership registry: a transfer claims the
current credential's nullifier and re-issues the asset under a fresh owner
secret, so every previous generation's nullifier lands in ps_nullifiers
and the only unspent nullifier at any time belongs to the current holder.
A third party shown a presentation therefore only needs an ecash/NUT-07-
style spent check on the nullifier (check_nullifiers) to learn whether the
presenter still owns the NFT. Burn stays distinguishable from transfer via
the per-asset status (asset_status).

Invariants enforced here, on top of the cryptography in
cashu/core/crypto/ps.py:
    * one credential per asset hash, enforced by the ps_assets primary key
    * a presentation can be spent exactly once, enforced by claiming the
      nullifier inside the caller's transaction
    * transfers are atomic: proof checks, nullifier claim and re-issuance
      either all commit or all roll back
    * a paid quote mints exactly one NFT, enforced by consuming the quote
      in the same transaction that inserts the asset
"""

import uuid
from typing import List, Optional, Tuple

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
from ..core.db import SQLITE, Connection, Database, LockOptions
from .quotes import QuoteBackend


class NFTError(Exception):
    pass


class AlreadyMintedError(NFTError):
    pass


class UnknownAssetError(NFTError):
    pass


class UnknownQuoteError(NFTError):
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
            # Old (owner-registry era) schema: ps_assets carried owner/epoch
            # and ps_nullifiers carried h. This feature is experimental, so
            # instead of migrating rows we drop and recreate both tables;
            # ps_quotes is untouched.
            if conn.type == SQLITE:
                rows = await conn.fetchall("PRAGMA table_info(ps_assets)")
                old_schema = any(row["name"] == "owner" for row in rows)
            else:
                rows = await conn.fetchall(
                    """
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'ps_assets'
                    """
                )
                old_schema = any(row["column_name"] == "owner" for row in rows)
            if old_schema:
                await conn.execute("DROP TABLE ps_assets")
                await conn.execute("DROP TABLE ps_nullifiers")
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ps_assets (
                    h TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'active',
                    created TEXT NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ps_nullifiers (
                    nullifier BLOB PRIMARY KEY,
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
                    INSERT INTO ps_assets (h, status, created)
                    VALUES (:h, 'active', :created)
                    """,
                    {
                        "h": _h_hex(h),
                        "created": self.db.timestamp_now_str(),
                    },
                )
            except IntegrityError:
                raise AlreadyMintedError("asset was already minted")
        return issue(self.mint_key, h, S)

    async def is_spent(self, nullifier: bytes) -> bool:
        row = await self.db.fetchone(
            "SELECT 1 AS x FROM ps_nullifiers WHERE nullifier = :n", {"n": nullifier}
        )
        return row is not None

    async def check_nullifiers(self, nullifiers: List[bytes]) -> List[str]:
        """NUT-07-style spent lookup: "SPENT" or "UNSPENT" per nullifier,
        in the same order as the input. The only unspent nullifier of an
        asset belongs to its current holder, so this doubles as the
        ownership check for third parties shown a presentation."""
        states = []
        for n in nullifiers:
            row = await self.db.fetchone(
                "SELECT 1 AS x FROM ps_nullifiers WHERE nullifier = :n", {"n": n}
            )
            states.append("SPENT" if row is not None else "UNSPENT")
        return states

    async def asset_status(self, h: int) -> str:
        """Status of an asset hash: "active", "burned" or "unknown"."""
        row = await self.db.fetchone(
            "SELECT status FROM ps_assets WHERE h = :h", {"h": _h_hex(h)}
        )
        if row is None:
            return "unknown"
        return str(row["status"])

    async def _spend(
        self,
        pres: Presentation,
        conn: Connection,
    ) -> None:
        """Verify a presentation and claim its nullifier, atomically with
        the caller's transaction. The asset must be known and active
        (h is revealed for public presentations)."""
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
            "SELECT status FROM ps_assets WHERE h = :h",
            {"h": _h_hex(pres.h)},
        )
        if row is None:
            raise UnknownAssetError("unknown asset")
        if row["status"] != "active":
            raise UnknownAssetError("asset is burned")
        try:
            await conn.execute(
                """
                INSERT INTO ps_nullifiers (nullifier, spent)
                VALUES (:n, :spent)
                """,
                {
                    "n": pres.nullifier.format(),
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
        the same asset to S_new. The asset hash never reaches the mint, so
        no asset row can be touched here; ownership is implicit in the
        nullifier set — only an unspent nullifier can pass, and the burn
        path spends the nullifier too, so a burned asset cannot transfer."""
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
                INSERT INTO ps_nullifiers (nullifier, spent)
                VALUES (:n, :spent)
                """,
                {"n": pres.nullifier.format(), "spent": self.db.timestamp_now_str()},
            )
        return u2, issue_blind(self.mint_key, k2, u2, w_h, S_new)

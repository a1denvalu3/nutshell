"""Persistent ledger for the experimental PS-credential NFT service.

State:
    ps_assets     -- retained legacy clear-h records
    ps_asset_tags -- public duplicate tag -> status (active/burned)
    ps_issue_sessions -- single-use, expiring blind issuance bases
    ps_nullifiers -- spent presentation nullifiers (double-spend prevention)
    ps_quotes     -- mint quotes: tag (or legacy h) -> settlement state

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
    * one credential per asset hash, enforced by the ps_asset_tags primary key
    * a presentation can be spent exactly once, enforced by claiming the
      nullifier inside the caller's transaction
    * transfers are atomic: proof checks, nullifier claim and re-issuance
      either all commit or all roll back
    * a paid quote mints exactly one NFT, enforced by consuming the quote
      in the same transaction that inserts the asset
"""

import hashlib
import time
import uuid
from typing import List, Optional, Tuple

from sqlalchemy.exc import IntegrityError

from ..core.crypto.bls import PublicKey
from ..core.crypto.ps import (
    PS_BURN_BINDING,
    DlogEqProof,
    LinearProof,
    MintPrivateKeyPS,
    MintPublicKeyPS,
    Presentation,
    PrivatePresentation,
    asset_tag,
    blind_base_for_issuance,
    blind_base_for_nullifier,
    issue,
    issue_blind,
    verify_blind_issue,
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


def _tag_id(tag: PublicKey) -> str:
    return "tag:" + tag.format().hex()


ISSUANCE_SESSION_TTL = 300


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
            await conn.execute(
                """CREATE TABLE IF NOT EXISTS ps_asset_tags (
                    tag TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'active',
                    created TEXT NOT NULL
                )"""
            )
            # Preserve every old asset, including burned assets, in the shared
            # uniqueness registry. Legacy hash records are retained as history.
            for row in await conn.fetchall("SELECT h, status, created FROM ps_assets"):
                await conn.execute(
                    """INSERT INTO ps_asset_tags(tag,status,created)
                    VALUES(:tag,:status,:created) ON CONFLICT(tag) DO NOTHING""",
                    {
                        "tag": _tag_id(asset_tag(int(row["h"], 16))),
                        "status": row["status"],
                        "created": row["created"],
                    },
                )
            await conn.execute(
                """CREATE TABLE IF NOT EXISTS ps_issue_sessions (
                    session TEXT PRIMARY KEY,
                    created INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    request_hash TEXT,
                    response BLOB
                )"""
            )

    async def create_quote(self, h: int) -> dict:
        """Create a mint quote for asset hash h. Settle it out of band,
        then mint with the quote id."""
        return await self._create_quote(_h_hex(h), h)

    async def create_blind_quote(self, tag: PublicKey) -> dict:
        """Bind payment to a public tag without receiving the hash scalar."""
        return await self._create_quote(
            _tag_id(tag), int.from_bytes(tag.format(), "big")
        )

    async def _create_quote(self, asset_id: str, identifier: int) -> dict:
        if self.quote_backend is None:
            raise PaymentError("this mint does not require quotes")
        quote_id = uuid.uuid4().hex
        amount, request, external = await self.quote_backend.create_quote(
            quote_id, identifier
        )
        async with self.db.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO ps_quotes (quote, h, amount, request, external_quote, state, created)
                VALUES (:quote, :h, :amount, :request, :external, 'unpaid', :created)
                """,
                {
                    "quote": quote_id,
                    "h": asset_id,
                    "amount": amount,
                    "request": request,
                    "external": external,
                    "created": self.db.timestamp_now_str(),
                },
            )
        return await self.get_quote(quote_id)

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
            **(
                {"asset_tag": row["h"][4:]}
                if row["h"].startswith("tag:")
                else {"asset_hash": row["h"]}
            ),
            "amount": row["amount"],
            "request": row["request"],
            "state": row["state"],
        }

    async def _consume_quote(
        self, conn: Connection, quote: Optional[str], tag: PublicKey
    ) -> None:
        if self.quote_backend is None:
            return
        if not quote:
            raise PaymentError("mint quote required")
        row = await self._sync_quote(conn, quote)
        # Already-created clear-h quotes remain usable; new clients only
        # request tag quotes. The old quote already disclosed its hash.
        expected = row["h"]
        if not expected.startswith("tag:"):
            expected = _tag_id(asset_tag(int(expected, 16)))
        if expected != _tag_id(tag):
            raise PaymentError("quote is for a different asset")
        if row["state"] == "unpaid":
            raise PaymentError("quote is not paid")
        result = await conn.execute(
            "UPDATE ps_quotes SET state='used' WHERE quote=:quote AND state='paid'",
            {"quote": quote},
        )
        if result.rowcount != 1:
            raise AlreadySpentError("quote was already used")

    async def _register_asset(self, conn: Connection, tag: PublicKey) -> None:
        try:
            await conn.execute(
                """INSERT INTO ps_asset_tags(tag,status,created)
                VALUES(:tag,'active',:created)""",
                {"tag": _tag_id(tag), "created": self.db.timestamp_now_str()},
            )
        except IntegrityError:
            raise AlreadyMintedError("asset was already minted")

    async def issue_nft_begin(self, conn: Optional[Connection] = None) -> dict:
        """Allocate a single-use, mint-controlled issuance base."""
        session = uuid.uuid4().hex
        now = int(time.time())
        async with self.db.get_connection(conn) as c:
            await c.execute(
                "DELETE FROM ps_issue_sessions WHERE used=0 AND created < :expiry",
                {"expiry": now - ISSUANCE_SESSION_TTL},
            )
            await c.execute(
                "INSERT INTO ps_issue_sessions(session,created) VALUES(:session,:now)",
                {"session": session, "now": now},
            )
        _, u = blind_base_for_issuance(self.mint_key, bytes.fromhex(session))
        return {
            "session": session,
            "u": u.format().hex(),
            "keyset_id": self.keyset.keyset_id,
        }

    async def issue_nft_blind(
        self,
        session: str,
        tag: PublicKey,
        B: PublicKey,
        S: PublicKey,
        proof: LinearProof,
        quote: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[PublicKey, PublicKey]:
        session_bytes = bytes.fromhex(session)
        k, u = blind_base_for_issuance(self.mint_key, session_bytes)
        if not verify_blind_issue(self.keyset, tag, B, u, S, proof, session_bytes):
            raise InvalidProofError("invalid blind issuance proof")
        quote_bytes = (quote or "").encode()
        request_hash = hashlib.sha256(
            bytes.fromhex(self.keyset.keyset_id)
            + session_bytes
            + tag.format()
            + B.format()
            + S.format()
            + proof.to_bytes()
            + len(quote_bytes).to_bytes(4, "big")
            + quote_bytes
        ).hexdigest()
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_assets")]
        ) as c:
            row = await c.fetchone(
                "SELECT * FROM ps_issue_sessions WHERE session=:session",
                {"session": session},
            )
            if row is None:
                raise InvalidProofError("unknown or expired issuance session")
            if row["used"]:
                if row["request_hash"] == request_hash and row["response"] is not None:
                    return u, PublicKey(compressed=bytes(row["response"]), group="G1")
                raise AlreadySpentError("issuance session was already used")
            if row["created"] < int(time.time()) - ISSUANCE_SESSION_TTL:
                raise InvalidProofError("unknown or expired issuance session")
            result = await c.execute(
                "UPDATE ps_issue_sessions SET used=1 WHERE session=:session AND used=0",
                {"session": session},
            )
            if result.rowcount != 1:
                raise AlreadySpentError("issuance session was already used")
            await self._consume_quote(c, quote, tag)
            await self._register_asset(c, tag)
            # Sign in the same transaction: failures do not consume payment,
            # uniqueness or the session. Each base signs at most once.
            v_raw = issue_blind(self.mint_key, k, u, B, S)
            await c.execute(
                """UPDATE ps_issue_sessions SET request_hash=:hash,response=:response
                WHERE session=:session""",
                {"hash": request_hash, "response": v_raw.format(), "session": session},
            )
        return u, v_raw

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
            tag = asset_tag(h)
            await self._consume_quote(c, quote, tag)
            await self._register_asset(c, tag)
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
            "SELECT status FROM ps_asset_tags WHERE tag = :tag",
            {"tag": _tag_id(asset_tag(h))},
        )
        if row is None:
            return "unknown"
        return str(row["status"])

    async def _spend(
        self,
        pres: Presentation,
        conn: Connection,
        binding: bytes,
    ) -> None:
        """Verify a presentation and claim its nullifier, atomically with
        the caller's transaction. The asset must be known and active
        (h is revealed for public presentations). The caller picks the
        purpose binding the presentation proof must match."""
        if pres.keyset_id and pres.keyset_id != self.keyset.keyset_id:
            raise InvalidProofError("unknown keyset")
        if not verify_presentation(self.keyset, pres, binding=binding):
            raise InvalidProofError("invalid presentation")
        if await conn.fetchone(
            "SELECT 1 AS x FROM ps_nullifiers WHERE nullifier = :n",
            {"n": pres.nullifier.format()},
        ):
            raise AlreadySpentError("credential already spent")
        row = await conn.fetchone(
            "SELECT status FROM ps_asset_tags WHERE tag = :tag",
            {"tag": _tag_id(asset_tag(pres.h))},
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
        """Atomically spend pres and re-issue the asset to S_new. The
        presentation proof must be bound to S_new, so a presentation
        captured in transit is only good for the re-issuance its owner
        actually authorized."""
        if not verify_owner_secret(S_new, pok_new):
            raise InvalidProofError("invalid new owner secret proof")
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_nullifiers")]
        ) as c:
            await self._spend(pres, c, binding=S_new.format())
        return issue(self.mint_key, pres.h, S_new)

    async def burn(self, pres: Presentation, conn: Optional[Connection] = None) -> None:
        """Retire an asset: spend the credential without re-issuing. The
        presentation must be bound to the burn domain."""
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_nullifiers")]
        ) as c:
            await self._spend(pres, c, binding=PS_BURN_BINDING)
            await c.execute(
                "UPDATE ps_asset_tags SET status = 'burned' WHERE tag = :tag",
                {"tag": _tag_id(asset_tag(pres.h))},
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
        B: PublicKey,
        proof_eq: LinearProof,
        S_new: PublicKey,
        pok_new: DlogEqProof,
        conn: Optional[Connection] = None,
    ) -> Tuple[PublicKey, PublicKey]:
        """Atomically spend a hidden-h presentation and blindly re-issue
        the same asset to S_new. The asset hash never reaches the mint --
        kappa_h and B are Pedersen commitments, so it cannot even be
        enumerated -- so no asset row can be touched here; ownership is
        implicit in the nullifier set: only an unspent nullifier can pass,
        and the burn path spends the nullifier too, so a burned asset
        cannot transfer. Returns (u2, v2_raw); the caller strips the
        blinding term with unblind_issued."""
        if not verify_owner_secret(S_new, pok_new):
            raise InvalidProofError("invalid new owner secret proof")
        if pres.keyset_id and pres.keyset_id != self.keyset.keyset_id:
            raise InvalidProofError("unknown keyset")
        k2, u2 = blind_base_for_nullifier(self.mint_key, pres.nullifier.format())
        if not verify_blind_transfer(
            self.keyset, pres, B, proof_eq, u2, binding=S_new.format()
        ):
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
        return u2, issue_blind(self.mint_key, k2, u2, B, S_new)

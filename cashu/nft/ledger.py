"""Persistent ledger for the experimental PS-credential NFT service.

State:
    ps_assets     -- one row per minted asset: h -> current owner commitment
    ps_nullifiers -- spent presentation nullifiers (double-spend prevention)

Invariants enforced here, on top of the cryptography in
cashu/core/crypto/ps.py:
    * one credential per asset hash, enforced by the ps_assets primary key
    * a presentation can be spent exactly once, enforced by claiming the
      nullifier inside the same transaction that moves ownership
    * transfers are atomic: proof checks, nullifier claim, ownership move
      and re-issuance either all commit or all roll back
"""

from typing import Optional, Tuple

from sqlalchemy.exc import IntegrityError

from ..core.crypto.bls import PublicKey
from ..core.crypto.ps import (
    DlogEqProof,
    MintPrivateKeyPS,
    MintPublicKeyPS,
    Presentation,
    issue,
    verify_owner_secret,
    verify_presentation,
)
from ..core.db import Connection, Database, LockOptions


class NFTError(Exception):
    pass


class AlreadyMintedError(NFTError):
    pass


class UnknownAssetError(NFTError):
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
    def __init__(self, db: Database, mint_key: MintPrivateKeyPS):
        self.db = db
        self.mint_key = mint_key
        # Optional pluggable payment gate, see cashu/nft/payment.py. When
        # set, issue_nft requires a payment token the verifier accepts.
        self.payment_verifier = None

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

    async def issue_nft(
        self,
        h: int,
        S: PublicKey,
        pok: DlogEqProof,
        payment: Optional[bytes] = None,
        conn: Optional[Connection] = None,
    ) -> Tuple[PublicKey, PublicKey]:
        """Mint the credential for asset hash h to owner commitment S."""
        if not verify_owner_secret(S, pok):
            raise InvalidProofError("invalid owner secret proof")
        if self.payment_verifier is not None:
            await self.payment_verifier.verify_payment(payment, h)
        async with self.db.get_connection(
            conn, locks=[LockOptions(table="ps_assets")]
        ) as c:
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
                "UPDATE ps_assets SET owner = :owner WHERE h = :h",
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

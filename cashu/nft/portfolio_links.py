"""Transfer links: send an NFT with a URL instead of a JPG file.

The sender's browser encrypts the bearer credential with a random key that
only travels in the link's URL fragment, which browsers never send to a
server. An optional password is mixed into the key derivation. This module
stores the ciphertext and public metadata only, so the portfolio cannot
redeem a link it hosts. Link status is derived from the mint's spent state
for the linked credential's nullifier.
"""

import time
from typing import TYPE_CHECKING, Literal, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

from ..core.db import LockOptions
from .wallet import NFTClient

if TYPE_CHECKING:
    from .portfolio import Portfolio

LinkStatus = Literal["open", "claimed", "void"]
MAX_OPEN_LINKS = 200


class LinkKdf(BaseModel):
    name: Literal["PBKDF2-SHA256"]
    iterations: int = Field(ge=100_000, le=5_000_000)
    salt: str = Field(pattern=r"^[0-9a-f]{32}$")


class LinkEnvelope(BaseModel):
    version: Literal[1]
    kdf: Optional[LinkKdf] = None
    nonce: str = Field(pattern=r"^[0-9a-f]{24}$")
    # A psnft1 token is ~390 characters; AES-GCM adds a 16-byte tag.
    ciphertext: str = Field(min_length=32, max_length=2048, pattern=r"^[0-9a-f]+$")


class LinkRequest(BaseModel):
    id: str = Field(pattern=r"^[0-9a-f]{32}$")
    card_id: str = Field(min_length=1, max_length=64)
    nullifier: str = Field(pattern=r"^[0-9a-f]{96}$")
    envelope: LinkEnvelope


class Links:
    def __init__(self, portfolio: "Portfolio"):
        self.db = portfolio.db
        self.ledger = portfolio.ledger

    async def migrate(self) -> None:
        async with self.db.get_connection() as conn:
            await conn.execute(
                """CREATE TABLE IF NOT EXISTS portfolio_links (
                id TEXT PRIMARY KEY, sender TEXT NOT NULL, card_id TEXT NOT NULL,
                h TEXT NOT NULL, title TEXT NOT NULL, nullifier TEXT NOT NULL,
                protected INTEGER NOT NULL, envelope TEXT NOT NULL, created INTEGER NOT NULL)"""
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS portfolio_links_sender ON portfolio_links(sender)"
            )

    async def create(self, sender: str, body: LinkRequest) -> dict:
        async with self.db.get_connection(
            locks=[
                LockOptions(table="portfolio_links"),
                LockOptions(table="portfolio_cards"),
            ]
        ) as conn:
            card = await conn.fetchone(
                "SELECT * FROM portfolio_cards WHERE id=:id AND pubkey=:p",
                {"id": body.card_id, "p": sender},
            )
            if card is None or card["status"] != "ready":
                raise HTTPException(
                    409, "Prepare this NFT for sending before creating a link."
                )
            current = NFTClient.decode_showing(card["showing"])[1].nullifier.format()
            # The link must carry the credential this card currently shows.
            if current.hex() != body.nullifier:
                raise HTTPException(
                    409, "This link doesn't match the NFT's current owner proof."
                )
            if await self.ledger.is_spent(current):
                raise HTTPException(409, "This NFT was already transferred.")
            count = await conn.fetchone(
                "SELECT COUNT(*) AS n FROM portfolio_links WHERE sender=:p",
                {"p": sender},
            )
            if count is not None and count["n"] >= MAX_OPEN_LINKS:
                raise HTTPException(429, "You have created too many links.")
            exists = await conn.fetchone(
                "SELECT id FROM portfolio_links WHERE id=:id", {"id": body.id}
            )
            if exists is not None:
                raise HTTPException(409, "This link ID is already in use.")
            await conn.execute(
                """INSERT INTO portfolio_links(id,sender,card_id,h,title,nullifier,protected,envelope,created)
                VALUES(:id,:sender,:card,:h,:title,:n,:protected,:envelope,:now)""",
                {
                    "id": body.id,
                    "sender": sender,
                    "card": body.card_id,
                    "h": card["h"],
                    "title": card["title"],
                    "n": body.nullifier,
                    "protected": 1 if body.envelope.kdf else 0,
                    "envelope": body.envelope.model_dump_json(),
                    "now": int(time.time()),
                },
            )
        return await self.get(body.id)

    async def get(self, link_id: str) -> dict:
        async with self.db.get_connection() as conn:
            row = await conn.fetchone(
                """SELECT l.*, p.name AS sender_name FROM portfolio_links l
                LEFT JOIN portfolio_profiles p ON p.pubkey=l.sender WHERE l.id=:id""",
                {"id": link_id},
            )
            if row is None:
                raise HTTPException(404, "This link doesn't exist.")
            link = dict(row)
            status: LinkStatus = "open"
            claimed_by: Optional[dict] = None
            if await self.ledger.is_spent(bytes.fromhex(link["nullifier"])):
                # A cancel rotates the sender's card to a new showing, so the
                # link is void even if the NFT is later sent another way.
                sender_card = await conn.fetchone(
                    "SELECT showing FROM portfolio_cards WHERE id=:id",
                    {"id": link["card_id"]},
                )
                rotated = (
                    sender_card is not None
                    and NFTClient.decode_showing(sender_card["showing"])[1]
                    .nullifier.format()
                    .hex()
                    != link["nullifier"]
                )
                # Claimed if someone (possibly the sender) took the asset into a
                # new card afterwards; otherwise the sender canceled.
                receiver = None
                if not rotated:
                    receiver = await conn.fetchone(
                        """SELECT c.pubkey, p.name FROM portfolio_cards c
                        LEFT JOIN portfolio_profiles p ON p.pubkey=c.pubkey
                        WHERE c.h=:h AND c.id!=:card AND c.created>=:created
                        ORDER BY c.created ASC, c.rowid ASC LIMIT 1""",
                        {
                            "h": link["h"],
                            "card": link["card_id"],
                            "created": link["created"],
                        },
                    )
                if receiver is not None:
                    status = "claimed"
                    claimed_by = {
                        "pubkey": receiver["pubkey"],
                        "name": receiver["name"],
                    }
                else:
                    status = "void"
        envelope = LinkEnvelope.model_validate_json(link["envelope"])
        return {
            "id": link["id"],
            "sender": link["sender"],
            "sender_name": link["sender_name"],
            "card_id": link["card_id"],
            "h": link["h"],
            "title": link["title"],
            "protected": bool(link["protected"]),
            "created": link["created"],
            "status": status,
            "claimed_by": claimed_by,
            # Ciphertext is useless without the key in the link's fragment.
            "envelope": envelope.model_dump() if status == "open" else None,
        }

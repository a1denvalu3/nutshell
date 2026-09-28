"""Experimental wallet for PS-credential NFTs.

Holds owner secrets (derived deterministically from a seed, so the whole
wallet restores from one backup), the credentials minted against them,
and a thin HTTP client for the service in cashu/nft/api.py.

Transfer orchestration needs both sides:
    receiver: ticket = wallet.prepare_receive()      # fresh secret + PoK
    sender:   spends their credential with the ticket's commitment
    receiver: wallet.finalize_receive(ticket, ...)   # stores new credential
"""

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from typing import List, Optional, Tuple

import httpx

from ..core.crypto.bls import PublicKey, curve_order
from ..core.crypto.ps import (
    Credential,
    DlogEqProof,
    Presentation,
    hash_asset,
    present,
    prove_owner_secret,
    verify_presentation,
)
from ..core.crypto.ps import (
    MintPublicKeyPS as MintPublicKeyPS,
)
from .registry import verify_registry_entry

WALLET_SECRET_DST = b"Cashu_PS_Wallet_v1"


def _derive_owner_secret(seed: bytes, index: int) -> int:
    s = 0
    counter = 0
    while not 0 < s < curve_order:
        s = (
            int.from_bytes(
                hashlib.sha256(
                    WALLET_SECRET_DST
                    + index.to_bytes(4, "big")
                    + counter.to_bytes(4, "big")
                    + seed
                ).digest(),
                "big",
            )
            % curve_order
        )
        counter += 1
    return s


@dataclass
class ReceiveTicket:
    """Receiver side of a transfer: a fresh owner secret commitment to hand
    to the sender, plus the wallet-local index needed to finalize."""

    index: int
    commitment: PublicKey
    proof: DlogEqProof


@dataclass
class WalletAsset:
    h: int
    description: str
    credential: Credential


class NFTWallet:
    def __init__(self, db_path: str, seed: Optional[bytes] = None):
        if os.path.exists(db_path) and seed is not None:
            raise ValueError("wallet exists; seed is only for creating/restoring")
        self.db = sqlite3.connect(db_path)
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS wallet (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
            """
        )
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                h TEXT PRIMARY KEY,
                secret_index INTEGER NOT NULL,
                credential BLOB NOT NULL,
                description TEXT NOT NULL DEFAULT ''
            )
            """
        )
        if seed is not None:
            if len(seed) < 16:
                raise ValueError("seed must be at least 16 bytes")
            self._set_meta("seed", seed)
            self._set_meta("next_index", (0).to_bytes(4, "big"))
        if self._get_meta("seed") is None:
            raise ValueError("wallet has no seed; create or restore with one")

    def _get_meta(self, key: str) -> Optional[bytes]:
        row = self.db.execute(
            "SELECT value FROM wallet WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else bytes(row[0])

    def _set_meta(self, key: str, value: bytes) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO wallet (key, value) VALUES (?, ?)", (key, value)
        )
        self.db.commit()

    @property
    def _seed(self) -> bytes:
        seed = self._get_meta("seed")
        if seed is None:  # guarded in __init__
            raise ValueError("wallet has no seed")
        return seed

    def _next_secret(self) -> Tuple[int, int]:
        index = int.from_bytes(self._get_meta("next_index") or b"\x00" * 4, "big")
        self._set_meta("next_index", (index + 1).to_bytes(4, "big"))
        return index, _derive_owner_secret(self._seed, index)

    def prepare_receive(self) -> ReceiveTicket:
        """Generate a fresh owner secret and its commitment for a mint or
        transfer request."""
        index, s = self._next_secret()
        S, pok = prove_owner_secret(s)
        return ReceiveTicket(index=index, commitment=S, proof=pok)

    def store_credential(
        self,
        ticket: ReceiveTicket,
        u: PublicKey,
        v: PublicKey,
        h: int,
        keyset_id: str,
        description: str = "",
    ) -> Credential:
        cred = Credential(
            u=u,
            v=v,
            h=h,
            s=_derive_owner_secret(self._seed, ticket.index),
            keyset_id=keyset_id,
        )
        self.db.execute(
            "INSERT OR REPLACE INTO assets (h, secret_index, credential, description)"
            " VALUES (?, ?, ?, ?)",
            (h.to_bytes(32, "big").hex(), ticket.index, cred.to_bytes(), description),
        )
        self.db.commit()
        return cred

    def assets(self) -> List[WalletAsset]:
        rows = self.db.execute(
            "SELECT h, credential, description FROM assets ORDER BY rowid"
        ).fetchall()
        return [
            WalletAsset(
                h=int(row[0], 16),
                credential=Credential.from_bytes(bytes(row[1])),
                description=row[2],
            )
            for row in rows
        ]

    def get_credential(self, h: int) -> Credential:
        row = self.db.execute(
            "SELECT credential FROM assets WHERE h = ?", (h.to_bytes(32, "big").hex(),)
        ).fetchone()
        if row is None:
            raise ValueError("no credential for this asset")
        return Credential.from_bytes(bytes(row[0]))

    def present(self, h: int) -> Presentation:
        return present(self.get_credential(h))


class NFTClient:
    """HTTP client for the service in cashu/nft/api.py. Takes any
    httpx.Client (including a TestClient pointed at an in-process app)."""

    def __init__(self, http: httpx.Client):
        self.http = http
        info = self._checked(self.http.get("/v1/info")).json()
        self.keyset = MintPublicKeyPS.from_bytes(bytes.fromhex(info["public_key"]))
        self.keyset_id: str = info["keyset_id"]
        self.payment_required: bool = info["payment_required"]

    @staticmethod
    def _checked(resp: httpx.Response) -> httpx.Response:
        if resp.status_code != 200:
            raise RuntimeError(f"mint error {resp.status_code}: {resp.text}")
        return resp

    def _g1(self, raw: str) -> PublicKey:
        return PublicKey(compressed=bytes.fromhex(raw), group="G1")

    def mint(
        self,
        wallet: NFTWallet,
        asset: bytes,
        payment: Optional[bytes] = None,
        description: str = "",
    ) -> Credential:
        h = hash_asset(asset)
        ticket = wallet.prepare_receive()
        resp = self._checked(
            self.http.post(
                "/v1/mint",
                json={
                    "asset_hash": h.to_bytes(32, "big").hex(),
                    "owner_commitment": ticket.commitment.format().hex(),
                    "proof": ticket.proof.to_bytes().hex(),
                    **({"payment": payment.hex()} if payment else {}),
                },
            )
        ).json()
        return wallet.store_credential(
            ticket,
            self._g1(resp["u"]),
            self._g1(resp["v"]),
            h,
            resp["keyset_id"],
            description,
        )

    def transfer(
        self,
        wallet: NFTWallet,
        h: int,
        new_owner_commitment: bytes,
        new_proof: bytes,
    ) -> Tuple[PublicKey, PublicKey]:
        """Spend the wallet's credential for h toward a receiver's
        commitment. Returns the raw new credential for the receiver to
        finalize."""
        resp = self._checked(
            self.http.post(
                "/v1/transfer",
                json={
                    "presentation": wallet.present(h).to_bytes().hex(),
                    "new_owner_commitment": new_owner_commitment.hex(),
                    "new_proof": new_proof.hex(),
                },
            )
        ).json()
        return self._g1(resp["u"]), self._g1(resp["v"])

    def transfer_to_self(self, wallet: NFTWallet, h: int) -> Credential:
        ticket = wallet.prepare_receive()
        u, v = self.transfer(
            wallet, h, ticket.commitment.format(), ticket.proof.to_bytes()
        )
        return wallet.store_credential(ticket, u, v, h, self.keyset_id)

    def burn(self, wallet: NFTWallet, h: int) -> None:
        self._checked(
            self.http.post(
                "/v1/burn", json={"presentation": wallet.present(h).to_bytes().hex()}
            )
        )
        wallet.db.execute(
            "DELETE FROM assets WHERE h = ?", (h.to_bytes(32, "big").hex(),)
        )
        wallet.db.commit()

    def verify(self, pres: Presentation) -> bool:
        """Offline verification against the keyset fetched from the mint."""
        return pres.keyset_id in ("", self.keyset_id) and verify_presentation(
            self.keyset, pres
        )

    def registry_entry(self, h: int) -> dict:
        resp = self.http.get(f"/v1/registry/{h.to_bytes(32, 'big').hex()}")
        if resp.status_code == 404:
            raise ValueError("unknown or burned asset")
        return self._checked(resp).json()

    def verify_registered_owner(self, pres: Presentation, entry: dict) -> bool:
        """Offline check that a presentation comes from the currently
        registered owner: the registry entry must carry a valid mint
        signature over (h, owner, epoch) and name the presentation's
        owner commitment. Callers comparing entries across time should
        take the one with the highest epoch."""
        owner = bytes.fromhex(entry["owner"])
        if owner != pres.owner_commitment.format():
            return False
        if int(entry["asset_hash"], 16) != pres.h:
            return False
        return verify_registry_entry(
            self.keyset,
            pres.h,
            owner,
            int(entry["epoch"]),
            bytes.fromhex(entry["signature"]),
        )

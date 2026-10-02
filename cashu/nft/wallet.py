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
import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple, Union

import httpx

from ..core.crypto.bls import PublicKey, curve_order
from ..core.crypto.ps import (
    PS_BURN_BINDING,
    Credential,
    DlogEqProof,
    LinearProof,
    Presentation,
    asset_tag,
    blind_issue_commit,
    blind_transfer_commit,
    hash_asset,
    issue_commitment,
    present,
    present_private,
    present_showing,
    prove_owner_secret,
    unblind_issued,
    unblind_issued_v2,
    verify_presentation,
    verify_showing,
)
from ..core.crypto.ps import (
    MintPublicKeyPS as MintPublicKeyPS,
)
from .api import NFT_API_PREFIX

WALLET_SECRET_DST = b"Cashu_PS_Wallet_v1"

# bearer token prefix, cashu-style ("cashuA..." analog)
TOKEN_PREFIX = "psnft1"

# verify-only showing token prefix
SHOW_TOKEN_PREFIX = "pshow1"


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


@dataclass
class PendingMint:
    index: int
    h: int
    description: str
    request: Dict[str, Union[str, int]]
    version: int = 1
    t: Optional[int] = None  # only legacy randomized issuance needs these
    u: Optional[str] = None


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
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS pending (
                commitment TEXT PRIMARY KEY,
                secret_index INTEGER NOT NULL
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

    def remember_quote(self, quote_id: str, h: int) -> None:
        """Keep the hash locally; a blind quote cannot return it later."""
        self._set_meta("quote:" + quote_id, h.to_bytes(32, "big"))

    def quote_hash(self, quote_id: str) -> Optional[int]:
        raw = self._get_meta("quote:" + quote_id)
        return None if raw is None else int.from_bytes(raw, "big")

    def save_pending_mint(
        self, keyset: str, session: str, pending: PendingMint
    ) -> None:
        self._set_meta(
            f"blind-mint:{keyset}:{session}", json.dumps(asdict(pending)).encode()
        )

    def pending_mint(self, keyset: str, session: str) -> PendingMint:
        raw = self._get_meta(f"blind-mint:{keyset}:{session}")
        if raw is None:
            raise ValueError("no pending mint for this session and mint keyset")
        return PendingMint(**json.loads(raw))

    def pending_mint_sessions(self, keyset: str) -> List[str]:
        prefix = f"blind-mint:{keyset}:"
        return [
            row[0][len(prefix) :]
            for row in self.db.execute(
                "SELECT key FROM wallet WHERE key LIKE ? ORDER BY key", (prefix + "%",)
            ).fetchall()
        ]

    def issuance_commit(
        self,
        ticket: ReceiveTicket,
        mint: MintPublicKeyPS,
        h: int,
        u: PublicKey,
        session: bytes,
    ) -> Tuple[PublicKey, PublicKey, int, LinearProof]:
        return blind_issue_commit(
            mint, h, _derive_owner_secret(self._seed, ticket.index), u, session
        )

    def prepare_receive(self) -> ReceiveTicket:
        """Generate a fresh owner secret and its commitment for a mint or
        transfer request. The ticket is persisted as pending until
        store_credential consumes it, so CLI commands can span multiple
        invocations."""
        index, s = self._next_secret()
        S, pok = prove_owner_secret(s)
        self.db.execute(
            "INSERT OR REPLACE INTO pending (commitment, secret_index) VALUES (?, ?)",
            (S.format().hex(), index),
        )
        self.db.commit()
        return ReceiveTicket(index=index, commitment=S, proof=pok)

    def pop_pending(self, commitment: bytes) -> int:
        """Consume a pending ticket by commitment, returning its secret
        index. Raises if no such ticket exists."""
        row = self.db.execute(
            "SELECT secret_index FROM pending WHERE commitment = ?",
            (commitment.hex(),),
        ).fetchone()
        if row is None:
            raise ValueError("no pending receive ticket for this commitment")
        self.db.execute("DELETE FROM pending WHERE commitment = ?", (commitment.hex(),))
        self.db.commit()
        return int(row[0])

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
        self.db.execute(
            "DELETE FROM pending WHERE commitment = ?",
            (ticket.commitment.format().hex(),),
        )
        self.db.commit()
        return cred

    def delete_asset(self, h: int) -> None:
        self.db.execute(
            "DELETE FROM assets WHERE h = ?", (h.to_bytes(32, "big").hex(),)
        )
        self.db.commit()

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
        resp = self.http.get(f"{NFT_API_PREFIX}/info")
        if resp.status_code == 404:
            raise RuntimeError(
                f"no PS-NFT service at this URL ({NFT_API_PREFIX}/info not found). "
                "If this is a Nutshell mint, enable the module with "
                "MINT_NFT_MODULE=TRUE; otherwise start the standalone service "
                "with `poetry run python -m cashu.nft`."
            )
        info = self._checked(resp).json()
        try:
            self.keyset = MintPublicKeyPS.from_bytes(bytes.fromhex(info["public_key"]))
            self.keyset_id = info["keyset_id"]
            self.payment_required = bool(info["payment_required"])
            self.mint_price_sats = int(info.get("mint_price_sats", 0))
        except (KeyError, ValueError):
            raise RuntimeError(
                "the service at this URL does not look like a PS-NFT mint "
                f"(unexpected {NFT_API_PREFIX}/info response)"
            )

    @staticmethod
    def _checked(resp: httpx.Response) -> httpx.Response:
        if resp.status_code != 200:
            raise RuntimeError(f"mint error {resp.status_code}: {resp.text}")
        return resp

    def _g1(self, raw: str) -> PublicKey:
        return PublicKey(compressed=bytes.fromhex(raw), group="G1")

    def mint_quote(self, asset: bytes) -> dict:
        """Request a mint quote for an asset. Settle it (pay the invoice,
        or dev-pay), then call mint with the quote id."""
        h = hash_asset(asset)
        quote = self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/mint/private/quote",
                json={"asset_tag": asset_tag(h).format().hex()},
            )
        ).json()
        # Local convenience for callers, never sent to the mint.
        return {**quote, "asset_hash": h.to_bytes(32, "big").hex()}

    def get_quote(self, quote_id: str) -> dict:
        return self._checked(
            self.http.get(f"{NFT_API_PREFIX}/mint/quote/{quote_id}")
        ).json()

    def quote_state(self, quote_id: str) -> str:
        return self.get_quote(quote_id)["state"]

    def dev_pay_quote(self, quote_id: str, ticket: bytes) -> None:
        self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/mint/quote/{quote_id}/pay",
                json={"ticket": ticket.hex()},
            )
        )

    def mint(
        self,
        wallet: NFTWallet,
        asset: bytes,
        quote: Optional[str] = None,
        description: str = "",
    ) -> Credential:
        return self.mint_h(
            wallet, hash_asset(asset), quote=quote, description=description
        )

    def mint_h(
        self,
        wallet: NFTWallet,
        h: int,
        quote: Optional[str] = None,
        description: str = "",
    ) -> Credential:
        ticket = wallet.prepare_receive()
        session = uuid.uuid4().hex
        tag, B, proof = issue_commitment(
            self.keyset,
            h,
            _derive_owner_secret(wallet._seed, ticket.index),
            bytes.fromhex(session),
        )
        wallet.save_pending_mint(
            self.keyset_id,
            session,
            PendingMint(
                index=ticket.index,
                h=h,
                version=3,
                description=description,
                request={
                    "version": 3,
                    "session": session,
                    "asset_tag": tag.format().hex(),
                    "b": B.format().hex(),
                    "owner_commitment": ticket.commitment.format().hex(),
                    "proof": proof.to_bytes().hex(),
                    **({"quote": quote} if quote else {}),
                },
            ),
        )
        return self.retry_mint(wallet, session)

    def retry_mint(self, wallet: NFTWallet, session: str) -> Credential:
        """Recover the exact original response without issuing a second NFT."""
        pending = wallet.pending_mint(self.keyset_id, session)
        secret = _derive_owner_secret(wallet._seed, pending.index)
        S, pok = prove_owner_secret(secret)
        ticket = ReceiveTicket(pending.index, S, pok)
        if pending.version not in (1, 2, 3):
            raise ValueError("unsupported pending issuance version")
        if pending.version != 3 and pending.t is None:
            raise ValueError("legacy issuance is missing its blinding factor")
        try:
            resp = self._checked(
                self.http.post(f"{NFT_API_PREFIX}/mint/private", json=pending.request)
            ).json()
        except (httpx.HTTPError, RuntimeError) as exc:
            raise RuntimeError(
                f"{exc}. Pending request saved; retry with `cashu nft retry-mint {session}`"
            ) from exc
        u = self._g1(resp["u"])
        if resp["keyset_id"] != self.keyset_id or (
            pending.version == 1 and (pending.u is None or u != self._g1(pending.u))
        ):
            raise RuntimeError("mint changed issuance base or keyset")
        v = self._g1(resp["v"])
        if pending.version != 3 and pending.t is not None:
            v = (
                unblind_issued_v2(v, pending.t, u)
                if pending.version == 2
                else unblind_issued(v, pending.t, self.keyset)
            )
        candidate = Credential(
            u=u,
            v=v,
            h=pending.h,
            s=secret,
            keyset_id=self.keyset_id,
        )
        if not verify_presentation(self.keyset, present(candidate)):
            raise RuntimeError("mint returned an invalid blind signature")
        # Delete recovery material in the same commit that stores the NFT.
        wallet.db.execute(
            "DELETE FROM wallet WHERE key=?",
            (f"blind-mint:{self.keyset_id}:{session}",),
        )
        return wallet.store_credential(
            ticket,
            u,
            v,
            pending.h,
            resp["keyset_id"],
            pending.description,
        )

    def _transfer_cred(
        self, cred: Credential, new_owner_commitment: bytes, new_proof: bytes
    ) -> Tuple[PublicKey, PublicKey]:
        """Swap a credential at the mint toward a receiver's commitment.
        The presentation proves the MAC and is bound to the receiver's
        commitment, so a captured presentation is useless for any other
        re-issuance. Returns the raw new credential for the receiver to
        finalize."""
        resp = self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/transfer",
                json={
                    "presentation": present(cred, binding=new_owner_commitment)
                    .to_bytes()
                    .hex(),
                    "new_owner_commitment": new_owner_commitment.hex(),
                    "new_proof": new_proof.hex(),
                },
            )
        ).json()
        return self._g1(resp["u"]), self._g1(resp["v"])

    def transfer(
        self,
        wallet: NFTWallet,
        h: int,
        new_owner_commitment: bytes,
        new_proof: bytes,
    ) -> Tuple[PublicKey, PublicKey]:
        """Spend the wallet's credential for h toward a receiver's
        commitment."""
        return self._transfer_cred(
            wallet.get_credential(h), new_owner_commitment, new_proof
        )

    def transfer_to_self(self, wallet: NFTWallet, h: int) -> Credential:
        ticket = wallet.prepare_receive()
        u, v = self.transfer(
            wallet, h, ticket.commitment.format(), ticket.proof.to_bytes()
        )
        return wallet.store_credential(ticket, u, v, h, self.keyset_id)

    def burn(self, wallet: NFTWallet, h: int) -> None:
        self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/burn",
                json={
                    "presentation": present(
                        wallet.get_credential(h), binding=PS_BURN_BINDING
                    )
                    .to_bytes()
                    .hex()
                },
            )
        )
        wallet.delete_asset(h)

    def verify(self, pres: Presentation) -> bool:
        """Offline verification against the keyset fetched from the mint."""
        return pres.keyset_id in ("", self.keyset_id) and verify_presentation(
            self.keyset, pres
        )

    def check_state(self, nullifier: bytes) -> str:
        """NUT-07-style spent lookup at the mint: "SPENT" or "UNSPENT".
        The only unspent nullifier of an asset belongs to its current
        holder, so this doubles as the ownership check for a third party
        shown a presentation."""
        resp = self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/checkstate",
                json={"nullifiers": [nullifier.hex()]},
            )
        ).json()
        return str(resp["states"][0]["state"])

    def asset_status(self, h: int) -> str:
        """Asset status at the mint: "active", "burned" or "unknown"."""
        resp = self._checked(
            self.http.get(f"{NFT_API_PREFIX}/asset/{h.to_bytes(32, 'big').hex()}")
        ).json()
        return str(resp["status"])

    def show(self, wallet: NFTWallet, h: int, context: bytes = b"") -> str:
        """Publish a verify-only showing for an asset: a presentation whose
        proof is bound to a showing context, so it verifies offline but is
        rejected by the mint's spend endpoints. Returns a pshow1 token
        carrying the context next to the presentation; the context defaults
        to a fresh random nonce."""
        if not context:
            context = os.urandom(16)
        pres = present_showing(wallet.get_credential(h), context)
        payload = len(context).to_bytes(2, "big") + context + pres.to_bytes()
        return SHOW_TOKEN_PREFIX + payload.hex()

    @staticmethod
    def decode_showing(token: str) -> Tuple[bytes, Presentation]:
        """Parse a pshow1 token into (context, presentation)."""
        t = token.strip()
        if t.startswith(SHOW_TOKEN_PREFIX):
            t = t[len(SHOW_TOKEN_PREFIX) :]
        else:
            raise ValueError("invalid showing token")
        try:
            raw = bytes.fromhex(t)
        except ValueError:
            raise ValueError("invalid showing token")
        if len(raw) < 2:
            raise ValueError("invalid showing token")
        context_len = int.from_bytes(raw[:2], "big")
        context, presentation = raw[2 : 2 + context_len], raw[2 + context_len :]
        if len(context) != context_len:
            raise ValueError("invalid showing token")
        try:
            return context, Presentation.from_bytes(presentation)
        except ValueError:
            raise ValueError("invalid showing token")

    def verify_showing_token(self, token: str) -> dict:
        """Third-party check of a showing token: offline signature/context
        verification plus the mint's spent and status answers. The spent
        check is the ownership check -- only the current holder's nullifier
        is unspent."""
        context, pres = self.decode_showing(token)
        valid = pres.keyset_id in ("", self.keyset_id) and verify_showing(
            self.keyset, pres, context
        )
        spent = self.check_state(pres.nullifier.format()) == "SPENT" if valid else False
        return {
            "valid": valid,
            "spent": spent,
            "asset_status": self.asset_status(pres.h),
            "asset_hash": pres.h.to_bytes(32, "big").hex(),
        }

    def _transfer_private_cred(
        self, cred: Credential, new_owner_commitment: bytes, new_proof: bytes
    ) -> Tuple[PublicKey, PublicKey]:
        """Hidden-h variant of the swap: h reaches the mint only inside
        Pedersen commitments (kappa_h in the presentation, B at
        re-issuance), so the mint cannot learn or enumerate it. The mint's
        v2_raw still carries the blinding term t * Y_h1; we strip it with
        unblind_issued before returning the credential."""
        pres, o = present_private(self.keyset, cred, binding=new_owner_commitment)
        begin = self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/transfer/private/begin",
                json={"nullifier": pres.nullifier.format().hex()},
            )
        ).json()
        u2 = self._g1(begin["u"])
        B, t, proof = blind_transfer_commit(
            self.keyset, cred.h, o, pres.kappa_h, u2, binding=new_owner_commitment
        )
        resp = self._checked(
            self.http.post(
                f"{NFT_API_PREFIX}/transfer/private",
                json={
                    "presentation": pres.to_bytes().hex(),
                    "b": B.format().hex(),
                    "proof": proof.to_bytes().hex(),
                    "new_owner_commitment": new_owner_commitment.hex(),
                    "new_proof": new_proof.hex(),
                },
            )
        ).json()
        v2 = unblind_issued(self._g1(resp["v"]), t, self.keyset)
        return self._g1(resp["u"]), v2

    def transfer_private(
        self, wallet: NFTWallet, h: int, new_owner_commitment: bytes, new_proof: bytes
    ) -> Tuple[PublicKey, PublicKey]:
        """Hidden-h variant of transfer: the mint never sees the asset
        hash. Returns the blind-issued new credential for the receiver."""
        return self._transfer_private_cred(
            wallet.get_credential(h), new_owner_commitment, new_proof
        )

    def transfer_private_to_self(self, wallet: NFTWallet, h: int) -> Credential:
        ticket = wallet.prepare_receive()
        u, v = self.transfer_private(
            wallet, h, ticket.commitment.format(), ticket.proof.to_bytes()
        )
        return wallet.store_credential(ticket, u, v, h, self.keyset_id)

    def send_token(self, wallet: NFTWallet, h: int) -> str:
        """Cashu-style offline send: serialize the credential as a bearer
        token the receiver can swap at the mint. The sender keeps a copy
        of the secret until the receiver swaps, exactly like an unredeemed
        ecash token, so the receiver should swap promptly."""
        cred = wallet.get_credential(h)
        wallet.delete_asset(h)
        return TOKEN_PREFIX + cred.to_bytes().hex()

    def export_token(self, wallet: NFTWallet, h: int) -> str:
        """The psnft1 bearer token WITHOUT deleting the asset from the
        wallet (unlike send_token). Anyone holding the exported token can
        spend the NFT; the exporter keeps full control until someone swaps
        it."""
        cred = wallet.get_credential(h)
        return TOKEN_PREFIX + cred.to_bytes().hex()

    @staticmethod
    def decode_token(token: str) -> Credential:
        t = token.strip()
        if t.startswith(TOKEN_PREFIX):
            t = t[len(TOKEN_PREFIX) :]
        try:
            return Credential.from_bytes(bytes.fromhex(t))
        except ValueError:
            raise ValueError("invalid NFT token")

    def receive(
        self,
        wallet: NFTWallet,
        token: str,
        description: str = "",
        private: bool = True,
    ) -> Credential:
        """Swap a received token at the mint: present the credential and
        re-issue it to a fresh secret of this wallet, all in one step.
        Private by default: the mint never sees h, only a proof that the
        input and output credentials bind the same asset hash."""
        cred = self.decode_token(token)
        if cred.keyset_id != self.keyset_id:
            raise ValueError(
                f"token is for keyset {cred.keyset_id}, not this mint's {self.keyset_id}"
            )
        ticket = wallet.prepare_receive()
        if private:
            u, v = self._transfer_private_cred(
                cred, ticket.commitment.format(), ticket.proof.to_bytes()
            )
        else:
            u, v = self._transfer_cred(
                cred, ticket.commitment.format(), ticket.proof.to_bytes()
            )
        return wallet.store_credential(
            ticket, u, v, cred.h, self.keyset_id, description
        )

"""HTTP API for the experimental PS-credential NFT service.

Standalone FastAPI app, mounted nowhere in the ecash mint; run it
directly for experiments:

    poetry run python -m cashu.nft.api   # or uvicorn cashu.nft.api:build_app

All cryptographic objects cross the wire as hex of their canonical
encodings from cashu/core/crypto/ps.py. Asset hashes are computed
client-side: the mint only ever sees h, never the asset bytes.
"""

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..core.crypto.bls import PublicKey, curve_order
from ..core.crypto.ps import (
    DlogEqProof,
    Presentation,
    verify_presentation,
)
from .ledger import (
    AlreadyMintedError,
    AlreadySpentError,
    InvalidProofError,
    NFTError,
    NotOwnerError,
    PaymentError,
    PSLedger,
    UnknownAssetError,
)


class MintRequest(BaseModel):
    asset_hash: str  # 64 hex chars, hash_asset output
    owner_commitment: str  # 48-byte compressed G1 point, hex
    proof: str  # 64-byte DlogEqProof, hex
    payment: Optional[str] = None  # hex ticket


class TransferRequest(BaseModel):
    presentation: str  # 344-byte Presentation, hex
    new_owner_commitment: str
    new_proof: str


class SpendRequest(BaseModel):
    presentation: str


class IssueResponse(BaseModel):
    u: str
    v: str
    keyset_id: str


def _parse_scalar(raw: str) -> int:
    try:
        value = int(raw, 16)
    except ValueError:
        raise HTTPException(400, "asset_hash must be hex")
    if not 0 <= value < curve_order or len(raw) != 64:
        raise HTTPException(400, "asset_hash must be a 64-hex-char scalar")
    return value


def _parse_g1(raw: str) -> PublicKey:
    try:
        return PublicKey(compressed=bytes.fromhex(raw), group="G1")
    except ValueError:
        raise HTTPException(400, "invalid G1 point encoding")


def _parse_proof(raw: str) -> DlogEqProof:
    try:
        return DlogEqProof.from_bytes(bytes.fromhex(raw))
    except ValueError:
        raise HTTPException(400, "invalid proof encoding")


def _parse_presentation(raw: str) -> Presentation:
    try:
        return Presentation.from_bytes(bytes.fromhex(raw))
    except ValueError:
        raise HTTPException(400, "invalid presentation encoding")


def _http_error(e: NFTError) -> HTTPException:
    if isinstance(e, PaymentError):
        return HTTPException(402, str(e))
    if isinstance(e, AlreadyMintedError):
        return HTTPException(409, str(e))
    if isinstance(e, AlreadySpentError):
        return HTTPException(409, str(e))
    if isinstance(e, UnknownAssetError):
        return HTTPException(404, str(e))
    if isinstance(e, (NotOwnerError, InvalidProofError)):
        return HTTPException(403, str(e))
    return HTTPException(400, str(e))


def create_app(ledger: PSLedger) -> FastAPI:
    app = FastAPI(title="cashu PS-NFT experimental service")

    @app.get("/v1/info")
    async def info():
        return {
            "keyset_id": ledger.keyset.keyset_id,
            "public_key": ledger.keyset.to_bytes().hex(),
            "payment_required": ledger.payment_verifier is not None,
        }

    @app.post("/v1/mint", response_model=IssueResponse)
    async def mint(req: MintRequest):
        try:
            u, v = await ledger.issue_nft(
                h=_parse_scalar(req.asset_hash),
                S=_parse_g1(req.owner_commitment),
                pok=_parse_proof(req.proof),
                payment=bytes.fromhex(req.payment) if req.payment else None,
            )
        except NFTError as e:
            raise _http_error(e)
        return IssueResponse(
            u=u.format().hex(), v=v.format().hex(), keyset_id=ledger.keyset.keyset_id
        )

    @app.post("/v1/transfer", response_model=IssueResponse)
    async def transfer(req: TransferRequest):
        try:
            u, v = await ledger.transfer(
                pres=_parse_presentation(req.presentation),
                S_new=_parse_g1(req.new_owner_commitment),
                pok_new=_parse_proof(req.new_proof),
            )
        except NFTError as e:
            raise _http_error(e)
        return IssueResponse(
            u=u.format().hex(), v=v.format().hex(), keyset_id=ledger.keyset.keyset_id
        )

    @app.post("/v1/burn")
    async def burn(req: SpendRequest):
        try:
            await ledger.burn(pres=_parse_presentation(req.presentation))
        except NFTError as e:
            raise _http_error(e)
        return {"status": "burned"}

    @app.post("/v1/verify")
    async def verify(req: SpendRequest):
        pres = _parse_presentation(req.presentation)
        valid = pres.keyset_id in ("", ledger.keyset.keyset_id) and verify_presentation(
            ledger.keyset, pres
        )
        owner = await ledger.get_owner(pres.h) if valid else None
        return {
            "valid": valid,
            "registered": owner is not None,
            "owner_matches": owner == pres.owner_commitment.format()
            if owner
            else False,
        }

    @app.get("/v1/registry/{asset_hash}")
    async def registry(asset_hash: str):
        h = _parse_scalar(asset_hash)
        entry = await ledger.registry_entry(h)
        if entry is None:
            raise HTTPException(404, "unknown or burned asset")
        owner, epoch, signature = entry
        return {
            "asset_hash": asset_hash,
            "owner": owner.hex(),
            "status": "active",
            "epoch": epoch,
            "signature": signature.hex(),
        }

    return app

"""HTTP API for the experimental PS-credential NFT service.

Standalone FastAPI app, mounted nowhere in the ecash mint; run it
directly for experiments:

    poetry run python -m cashu.nft.api   # or uvicorn cashu.nft.api:build_app

All cryptographic objects cross the wire as hex of their canonical
encodings from cashu/core/crypto/ps.py. Asset hashes are computed
client-side: the mint only ever sees h, never the asset bytes.
"""

from typing import List, Optional

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel

from ..core.crypto.bls import PublicKey, curve_order
from ..core.crypto.ps import (
    DlogEqProof,
    Presentation,
    PrivatePresentation,
    verify_presentation,
)
from .ledger import (
    AlreadyMintedError,
    AlreadySpentError,
    InvalidProofError,
    NFTError,
    PaymentError,
    PSLedger,
    UnknownAssetError,
    UnknownQuoteError,
)

# cap on the /checkstate batch, NUT-07 style
MAX_CHECKSTATE_NULLIFIERS = 1000


class MintRequest(BaseModel):
    asset_hash: str  # 64 hex chars, hash_asset output
    owner_commitment: str  # 48-byte compressed G1 point, hex
    proof: str  # 64-byte DlogEqProof, hex
    quote: Optional[str] = None  # mint quote id, if the mint requires payment


class MintQuoteRequest(BaseModel):
    asset_hash: str


class DevPayRequest(BaseModel):
    ticket: str  # hex dev ticket


class TransferRequest(BaseModel):
    presentation: str  # 321-byte Presentation, hex
    new_owner_commitment: str
    new_proof: str


class SpendRequest(BaseModel):
    presentation: str
    binding: Optional[str] = None  # hex, purpose binding for /verify only


class PrivateTransferBeginRequest(BaseModel):
    nullifier: str  # 48-byte compressed G1 point, hex


class CheckStateRequest(BaseModel):
    nullifiers: List[str]  # hex of 48-byte compressed G1 points


class PrivateTransferRequest(BaseModel):
    presentation: str  # 401-byte PrivatePresentation, hex
    w_h: str  # 48-byte compressed G1 point, hex
    proof: str  # 64-byte DlogEqProof, hex
    new_owner_commitment: str
    new_proof: str


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
    if isinstance(e, (UnknownAssetError, UnknownQuoteError)):
        return HTTPException(404, str(e))
    if isinstance(e, InvalidProofError):
        return HTTPException(403, str(e))
    return HTTPException(400, str(e))


def create_router(ledger: PSLedger) -> APIRouter:
    router = APIRouter()

    @router.get("/info")
    async def info():
        return {
            "keyset_id": ledger.keyset.keyset_id,
            "public_key": ledger.keyset.to_bytes().hex(),
            "payment_required": ledger.quote_backend is not None,
            "mint_price_sats": ledger.quote_backend.price_sats
            if ledger.quote_backend
            else 0,
        }

    @router.post("/mint/quote")
    async def mint_quote(req: MintQuoteRequest):
        try:
            return await ledger.create_quote(_parse_scalar(req.asset_hash))
        except NFTError as e:
            raise _http_error(e)

    @router.get("/mint/quote/{quote_id}")
    async def mint_quote_state(quote_id: str):
        try:
            return await ledger.get_quote(quote_id)
        except NFTError as e:
            raise _http_error(e)

    @router.post("/mint/quote/{quote_id}/pay")
    async def mint_quote_dev_pay(quote_id: str, req: DevPayRequest):
        try:
            await ledger.dev_pay_quote(quote_id, bytes.fromhex(req.ticket))
        except ValueError:
            raise HTTPException(400, "invalid ticket encoding")
        except NFTError as e:
            raise _http_error(e)
        return await ledger.get_quote(quote_id)

    @router.post("/mint", response_model=IssueResponse)
    async def mint(req: MintRequest):
        try:
            u, v = await ledger.issue_nft(
                h=_parse_scalar(req.asset_hash),
                S=_parse_g1(req.owner_commitment),
                pok=_parse_proof(req.proof),
                quote=req.quote,
            )
        except NFTError as e:
            raise _http_error(e)
        return IssueResponse(
            u=u.format().hex(), v=v.format().hex(), keyset_id=ledger.keyset.keyset_id
        )

    @router.post("/transfer", response_model=IssueResponse)
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

    @router.post("/burn")
    async def burn(req: SpendRequest):
        try:
            await ledger.burn(pres=_parse_presentation(req.presentation))
        except NFTError as e:
            raise _http_error(e)
        return {"status": "burned"}

    @router.post("/transfer/private/begin")
    async def transfer_private_begin(req: PrivateTransferBeginRequest):
        try:
            u2 = await ledger.transfer_private_begin(bytes.fromhex(req.nullifier))
        except NFTError as e:
            raise _http_error(e)
        return {"u": u2.format().hex()}

    @router.post("/transfer/private", response_model=IssueResponse)
    async def transfer_private(req: PrivateTransferRequest):
        try:
            u2, v2 = await ledger.transfer_private(
                pres=PrivatePresentation.from_bytes(bytes.fromhex(req.presentation)),
                w_h=_parse_g1(req.w_h),
                proof=_parse_proof(req.proof),
                S_new=_parse_g1(req.new_owner_commitment),
                pok_new=_parse_proof(req.new_proof),
            )
        except ValueError:
            raise HTTPException(400, "invalid presentation encoding")
        except NFTError as e:
            raise _http_error(e)
        return IssueResponse(
            u=u2.format().hex(), v=v2.format().hex(), keyset_id=ledger.keyset.keyset_id
        )

    @router.post("/verify")
    async def verify(req: SpendRequest):
        pres = _parse_presentation(req.presentation)
        try:
            binding = bytes.fromhex(req.binding) if req.binding else b""
        except ValueError:
            raise HTTPException(400, "binding must be hex")
        valid = pres.keyset_id in (
            "",
            ledger.keyset.keyset_id,
        ) and verify_presentation(ledger.keyset, pres, binding=binding)
        spent = await ledger.is_spent(pres.nullifier.format()) if valid else False
        return {"valid": valid, "spent": spent}

    @router.post("/checkstate")
    async def checkstate(req: CheckStateRequest):
        if len(req.nullifiers) > MAX_CHECKSTATE_NULLIFIERS:
            raise HTTPException(
                400, f"too many nullifiers (max {MAX_CHECKSTATE_NULLIFIERS})"
            )
        nullifiers = []
        for raw in req.nullifiers:
            try:
                n = bytes.fromhex(raw)
            except ValueError:
                raise HTTPException(400, "nullifier must be hex")
            if len(n) != 48:
                raise HTTPException(
                    400, "nullifier must be a 48-byte compressed G1 point"
                )
            nullifiers.append(n)
        states = await ledger.check_nullifiers(nullifiers)
        return {
            "states": [
                {"nullifier": n.hex(), "state": s}
                for n, s in zip(nullifiers, states)
            ]
        }

    @router.get("/asset/{asset_hash}")
    async def asset(asset_hash: str):
        h = _parse_scalar(asset_hash)
        return {"asset_hash": asset_hash, "status": await ledger.asset_status(h)}

    return router


NFT_API_PREFIX = "/v1/nft"


def create_app(ledger: PSLedger) -> FastAPI:
    """Standalone app: serves the NFT router under /v1/nft."""
    app = FastAPI(title="cashu PS-NFT experimental service")
    app.include_router(create_router(ledger), prefix=NFT_API_PREFIX, tags=["NFT"])
    return app

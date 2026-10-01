"""Cash leg of marketplace settlement: fixed-output swaps against an
ordinary Cashu mint (NUT-03/11/14), outcome detection (NUT-07) and lost-reply
recovery (NUT-09).

Executor jobs only ever hold locked inputs, fixed blinded outputs and the
owner's SIG_ALL signature. Blinding factors and output secrets stay with the
owner (``OwnerOutputs``), so an executor can submit a job but cannot redirect
or unblind its value.
"""

import json
import secrets as pysecrets
from dataclasses import dataclass, field
from typing import Any, Awaitable, Dict, List, Optional, Protocol, Sequence

import httpx

from ..core.crypto.b_dhke import (
    alice_verify_dleq,
    hash_to_curve,
    step1_alice,
    step3_alice,
)
from ..core.crypto.secp import PrivateKey, PublicKey
from ..core.split import amount_split
from .market_protocol import ProtocolError


@dataclass
class OwnerOutputs:
    """Private output material kept only in the owner's encrypted records."""

    keyset_id: str
    amounts: List[int]
    secrets: List[str]
    blinding_factors: List[str]  # hex scalars
    blinded: List[Dict[str, Any]] = field(default_factory=list)

    def public(self) -> List[Dict[str, Any]]:
        return [dict(o) for o in self.blinded]


def blind_outputs(amount: int, keyset_id: str) -> OwnerOutputs:
    """Fresh random-secret outputs for exactly ``amount``."""
    if amount <= 0:
        raise ProtocolError("output amount must be positive")
    amounts = amount_split(amount)
    owner = OwnerOutputs(
        keyset_id=keyset_id, amounts=amounts, secrets=[], blinding_factors=[]
    )
    for a in amounts:
        secret = pysecrets.token_hex(32)
        B_, r = step1_alice(secret)
        owner.secrets.append(secret)
        owner.blinding_factors.append(r.to_hex())
        owner.blinded.append({"amount": a, "id": keyset_id, "B_": B_.format().hex()})
    return owner


def unblind(
    owner: OwnerOutputs, signatures: Sequence[Dict[str, Any]], keys: Dict[int, str]
) -> List[Dict[str, Any]]:
    """Owner side: turn the mint's blind signatures into spendable proofs,
    checking amounts, keyset and DLEQ when the mint provides it."""
    if len(signatures) != len(owner.blinded):
        raise ProtocolError("signature count differs from the outputs")
    proofs = []
    for sig, out, secret, r_hex in zip(
        signatures, owner.blinded, owner.secrets, owner.blinding_factors
    ):
        if sig.get("amount") != out["amount"]:
            raise ProtocolError("mint signed a different amount")
        A = PublicKey(bytes.fromhex(keys[out["amount"]]))
        r = PrivateKey(bytes.fromhex(r_hex))
        C_ = PublicKey(bytes.fromhex(sig["C_"]))
        dleq = sig.get("dleq")
        if dleq and not alice_verify_dleq(
            PublicKey(bytes.fromhex(out["B_"])),
            C_,
            PrivateKey(bytes.fromhex(dleq["e"])),
            PrivateKey(bytes.fromhex(dleq["s"])),
            A,
        ):
            raise ProtocolError("mint signature has an invalid DLEQ proof")
        C = step3_alice(C_, r, A)
        proofs.append(
            {
                "amount": out["amount"],
                "id": sig.get("id", out["id"]),
                "secret": secret,
                "C": C.format().hex(),
            }
        )
    return proofs


def proof_y(secret: str) -> str:
    return hash_to_curve(secret.encode()).format().hex()


def witness_json(signatures: Sequence[str], preimage: Optional[str] = None) -> str:
    body: Dict[str, Any] = {"signatures": list(signatures)}
    if preimage is not None:
        body["preimage"] = preimage
    return json.dumps(body, separators=(",", ":"))


def swap_inputs(
    proofs: Sequence[Dict[str, Any]], signature: str, preimage: Optional[str] = None
) -> List[Dict[str, Any]]:
    """SIG_ALL puts the one witness on the first input."""
    inputs = [
        {"amount": p["amount"], "id": p["id"], "secret": p["secret"], "C": p["C"]}
        for p in proofs
    ]
    inputs[0]["witness"] = witness_json([signature], preimage)
    return inputs


class MintResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class MintHTTP(Protocol):
    """httpx.AsyncClient or the SSRF-guarded client in market_net."""

    def post(self, url: str, *, json: Any = None) -> Awaitable[Any]: ...


class MintRejected(Exception):
    """The mint refused the request (4xx); retrying unchanged won't help."""


class MintUnavailable(Exception):
    """Network or 5xx failure; the outcome is unknown until reconciled."""


async def _post(client: MintHTTP, url: str, body: Dict[str, Any]) -> Dict[str, Any]:
    try:
        response = await client.post(url, json=body)
    except httpx.HTTPError as exc:
        raise MintUnavailable(str(exc)) from exc
    if response.status_code >= 500:
        raise MintUnavailable(f"mint returned {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise MintUnavailable("mint returned invalid JSON") from exc
    if response.status_code >= 400:
        raise MintRejected(str(data.get("detail", data)))
    return data


async def submit_swap(
    client: MintHTTP,
    mint_url: str,
    inputs: Sequence[Dict[str, Any]],
    outputs: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    data = await _post(
        client,
        f"{mint_url}/v1/swap",
        {"inputs": list(inputs), "outputs": list(outputs)},
    )
    signatures = data.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != len(outputs):
        raise MintUnavailable("mint returned an unexpected swap response")
    return signatures


async def restore(
    client: MintHTTP, mint_url: str, outputs: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """NUT-09: signatures the mint already issued for these exact outputs,
    in output order, or an empty list if it never signed them."""
    data = await _post(client, f"{mint_url}/v1/restore", {"outputs": list(outputs)})
    returned = {
        o["B_"]: sig
        for o, sig in zip(data.get("outputs", []), data.get("signatures", []))
    }
    if not returned:
        return []
    if any(o["B_"] not in returned for o in outputs):
        raise MintUnavailable("mint restored only part of the outputs")
    return [returned[o["B_"]] for o in outputs]


async def proof_states(
    client: MintHTTP, mint_url: str, secrets: Sequence[str]
) -> List[Dict[str, Any]]:
    ys = [proof_y(s) for s in secrets]
    data = await _post(client, f"{mint_url}/v1/checkstate", {"Ys": ys})
    states = data.get("states", [])
    if len(states) != len(ys):
        raise MintUnavailable("mint returned an unexpected checkstate response")
    return states


def spent_by(states: Sequence[Dict[str, Any]]) -> Optional[str]:
    """Which HTLC branch spent the inputs, from the NUT-07 witness:
    ``claim`` (preimage present), ``refund`` (signature only), ``other``,
    or None while unspent. Pending counts as unspent-but-busy."""
    if all(s.get("state") == "UNSPENT" for s in states):
        return None
    for s in states:
        if s.get("state") != "SPENT" or not s.get("witness"):
            continue
        try:
            witness = json.loads(s["witness"])
        except (TypeError, ValueError):
            return "other"
        return "claim" if witness.get("preimage") else "refund"
    return "pending" if any(s.get("state") == "PENDING" for s in states) else "other"

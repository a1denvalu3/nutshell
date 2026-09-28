"""Signed ownership-registry entries.

A presentation proves "I hold a valid credential and know its secret",
but only the registry says who the *current* owner of an asset is. To
keep that answer verifiable without a live, trusted mint connection, the
mint BLS-signs each registry entry with the x component of its PS key
(already public as X2 in G2):

    entry  = (h, S, epoch)         epoch increments on every transfer
    sig    = x * H(entry)          in G1
    check  = e(sig, g2) == e(H(entry), X2)

Verifiers take the entry with the highest epoch they have seen; a stale
entry still verifies cryptographically but loses to any newer epoch.
"""

import hashlib

import pyblst

from ..core.crypto.bls import G2, PublicKey, curve_order
from ..core.crypto.ps import MintPrivateKeyPS, MintPublicKeyPS

REGISTRY_DST = b"CASHU_PS_REGISTRY_XMD:SHA-256_SSWU_RO_"
REGISTRY_ENTRY_DST = b"Cashu_PS_Registry_Entry_v1"


def registry_entry_message(h: int, owner: bytes, epoch: int) -> bytes:
    if not 0 <= h < curve_order:
        raise ValueError("h must be a scalar")
    if len(owner) != 48:
        raise ValueError("owner must be a compressed G1 point")
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    return REGISTRY_ENTRY_DST + h.to_bytes(32, "big") + owner + epoch.to_bytes(8, "big")


def _hash_entry(message: bytes) -> pyblst.BlstP1Element:
    return pyblst.BlstP1Element().hash_to_group(
        hashlib.sha256(message).digest(), REGISTRY_DST
    )


def sign_registry_entry(
    mint_key: MintPrivateKeyPS, h: int, owner: bytes, epoch: int
) -> PublicKey:
    point = _hash_entry(registry_entry_message(h, owner, epoch))
    return PublicKey(point=point.scalar_mul(mint_key.x.scalar), group="G1")


def verify_registry_entry(
    mint_public: MintPublicKeyPS, h: int, owner: bytes, epoch: int, signature: bytes
) -> bool:
    try:
        sig = PublicKey(compressed=signature, group="G1")
    except ValueError:
        return False
    if sig.is_infinity():
        return False
    try:
        point = _hash_entry(registry_entry_message(h, owner, epoch))
    except ValueError:
        return False
    miller = pyblst.miller_loop(-sig.point, G2)
    miller = miller * pyblst.miller_loop(point, mint_public.X2.point)
    return pyblst.final_verify(miller, pyblst.BlstFP12Element())

"""
Pointcheval-Sanders credentials on BLS12-381 for asset-bound NFT credentials.

Experimental. A credential signs two attributes:
    h -- scalar hash of the asset (e.g. a JPEG digest), revealed to the mint at
         issuance so the mint can enforce one-credential-per-asset.
    s -- owner secret, never revealed to the mint, bound into the credential
         during issuance with a Diffie-Hellman trick.

Mint secret key: (x, y_h, y_s). Public parameters live in G2 only:
    X2 = g2^x, Y_h2 = g2^{y_h}, Y_s2 = g2^{y_s}
Publishing the y values in G2 (never in G1) is what prevents the exponent
rescaling forgery: moving a credential from h1 to h2 would require u^{y_h},
which is exactly what the mint withholds.

Issuance (blind in s):
    user sends S = g1^s with a proof of knowledge of s
    mint picks k at random, u = g1^k
    v = u^{x + y_h * h} * S^{k * y_s} = u^{x + y_h*h + y_s*s}

Presentation (public, offline verifiable):
    user randomizes (u', v') = (u^rho, v^rho) and reveals
    (h, u', v', U_s = u'^s, S, N = G_NULL^s, dlog-eq proof of s)
    authenticity: e(v', g2) == e(u', X2 * Y_h2^h) * e(U_s, Y_s2)
    ownership:    Chaum-Pedersen proof that the same s sits in S (G1),
                  N (G_NULL) and U_s (u'). All bases are G1 points, so no
                  GT exponentiation is needed.

Transfer:
    the mint checks the presentation, enforces nullifier N freshness, then
    re-issues a credential over the same h with the new owner's secret.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

import pyblst

from .bls import G2, PrivateKey, PublicKey, curve_order

# BLS12-381 G1 generator, compressed
_G1_HEX = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
G1 = PublicKey(compressed=bytes.fromhex(_G1_HEX), group="G1")

# Domain separation tags
PS_ASSET_DST = b"Cashu_PS_Asset_v1"
PS_ISSUE_DST = b"Cashu_PS_Issue_v1"
PS_PRESENT_DST = b"Cashu_PS_Present_v1"
PS_GNULL_DST = b"CASHU_PS_GNULL_XMD:SHA-256_SSWU_RO_"

# Nullifier base: nothing-up-my-sleeve G1 point with unknown discrete log
G_NULL = PublicKey(
    point=pyblst.BlstP1Element().hash_to_group(b"ps_nullifier_base", PS_GNULL_DST),
    group="G1",
)


def _random_scalar() -> int:
    scalar = 0
    while not 0 < scalar < curve_order:
        scalar = int.from_bytes(os.urandom(32), "big")
    return scalar


def _scalar_bytes(scalar: int) -> bytes:
    return scalar.to_bytes(32, "big")


def _add_p1(a: PublicKey, b: PublicKey) -> PublicKey:
    return PublicKey(point=a.point + b.point, group="G1")


def _neg_p1(a: PublicKey) -> PublicKey:
    return PublicKey(point=-a.point, group="G1")


def hash_asset(asset: bytes) -> int:
    """Hash asset bytes to a nonzero scalar attribute h."""
    digest = hashlib.sha256(
        PS_ASSET_DST + len(asset).to_bytes(4, "big") + asset
    ).digest()
    return int.from_bytes(digest, "big") % curve_order


def _challenge(transcript: bytes) -> int:
    return int.from_bytes(hashlib.sha256(transcript).digest(), "big") % curve_order


@dataclass
class DlogEqProof:
    """Chaum-Pedersen proof that one scalar is the discrete log of n points
    with respect to n bases."""

    challenge: int
    response: int


def _dlog_eq_transcript(
    dst: bytes,
    bases: List[PublicKey],
    points: List[PublicKey],
    commitments: List[PublicKey],
) -> bytes:
    transcript = dst
    for group in (bases, points, commitments):
        for p in group:
            serialized = p.format()
            transcript += len(serialized).to_bytes(2, "big") + serialized
    return transcript


def prove_dlog_eq(
    bases: List[PublicKey], points: List[PublicKey], secret: int, dst: bytes
) -> DlogEqProof:
    if not bases or len(bases) != len(points):
        raise ValueError("need an equal, nonzero number of bases and points")
    if not 0 < secret < curve_order:
        raise ValueError("secret must be in Fr*")
    nonce = _random_scalar()
    commitments = [base * nonce for base in bases]
    challenge = _challenge(_dlog_eq_transcript(dst, bases, points, commitments))
    response = (nonce + challenge * secret) % curve_order
    return DlogEqProof(challenge=challenge, response=response)


def verify_dlog_eq(
    bases: List[PublicKey], points: List[PublicKey], proof: DlogEqProof, dst: bytes
) -> bool:
    if not bases or len(bases) != len(points):
        return False
    if not (0 <= proof.challenge < curve_order and 0 <= proof.response < curve_order):
        return False
    commitments = [
        _add_p1(base * proof.response, _neg_p1(point * proof.challenge))
        for base, point in zip(bases, points)
    ]
    expected = _challenge(_dlog_eq_transcript(dst, bases, points, commitments))
    return expected == proof.challenge


class MintPrivateKeyPS:
    def __init__(
        self,
        x: Optional[PrivateKey] = None,
        y_h: Optional[PrivateKey] = None,
        y_s: Optional[PrivateKey] = None,
    ):
        self.x = x or PrivateKey()
        self.y_h = y_h or PrivateKey()
        self.y_s = y_s or PrivateKey()

    @property
    def public_key(self) -> "MintPublicKeyPS":
        return MintPublicKeyPS(
            X2=self.x.get_g2_public_key(),
            Y_h2=self.y_h.get_g2_public_key(),
            Y_s2=self.y_s.get_g2_public_key(),
        )


class MintPublicKeyPS:
    """Mint public parameters. The y values exist in G2 only, by construction."""

    def __init__(self, X2: PublicKey, Y_h2: PublicKey, Y_s2: PublicKey):
        self.X2 = X2
        self.Y_h2 = Y_h2
        self.Y_s2 = Y_s2


@dataclass
class Credential:
    """A PS credential as held by its owner."""

    u: PublicKey
    v: PublicKey
    h: int
    s: int


@dataclass
class Presentation:
    """A randomized, publicly verifiable credential presentation."""

    h: int
    u: PublicKey
    v: PublicKey
    u_s: PublicKey
    owner_commitment: PublicKey  # S = g1^s
    nullifier: PublicKey  # N = G_NULL^s
    proof: DlogEqProof


def prove_owner_secret(s: int) -> Tuple[PublicKey, DlogEqProof]:
    """User side of issuance: commit to the owner secret as S = g1^s and
    prove knowledge of it."""
    S = G1 * s
    proof = prove_dlog_eq([G1], [S], s, PS_ISSUE_DST)
    return S, proof


def verify_owner_secret(S: PublicKey, proof: DlogEqProof) -> bool:
    if S.is_infinity():
        return False
    return verify_dlog_eq([G1], [S], proof, PS_ISSUE_DST)


def issue(
    mint_key: MintPrivateKeyPS, h: int, S: PublicKey
) -> Tuple[PublicKey, PublicKey]:
    """Mint side of issuance. The caller must have verified the proof of
    knowledge behind S and enforced that h was never issued before."""
    if S.is_infinity():
        raise ValueError("owner commitment must not be the point at infinity")
    if not 0 <= h < curve_order:
        raise ValueError("h must be a scalar")
    k = _random_scalar()
    u = G1 * k
    exponent = (mint_key.x.scalar + mint_key.y_h.scalar * h) % curve_order
    v = _add_p1(u * exponent, S * ((k * mint_key.y_s.scalar) % curve_order))
    return u, v


def present(cred: Credential, rho: Optional[int] = None) -> Presentation:
    """Owner side: randomize the credential and build the presentation."""
    if not 0 <= cred.h < curve_order:
        raise ValueError("h must be a scalar")
    if not 0 < cred.s < curve_order:
        raise ValueError("owner secret must be in Fr*")
    rho = rho or _random_scalar()
    if not 0 < rho < curve_order:
        raise ValueError("rho must be in Fr*")
    u_r = cred.u * rho
    v_r = cred.v * rho
    u_s = u_r * cred.s
    S = G1 * cred.s
    N = G_NULL * cred.s
    proof = prove_dlog_eq([G1, G_NULL, u_r], [S, N, u_s], cred.s, PS_PRESENT_DST)
    return Presentation(
        h=cred.h, u=u_r, v=v_r, u_s=u_s, owner_commitment=S, nullifier=N, proof=proof
    )


def verify_presentation(mint_public: MintPublicKeyPS, pres: Presentation) -> bool:
    """Public, offline verification of a presentation.

    Checks authenticity (pairing equation against the mint's G2 parameters)
    and ownership (the same s in S, N and u_s). The caller must separately
    compare pres.owner_commitment against the ownership registry entry for
    pres.h, and (for transfers) enforce pres.nullifier freshness.
    """
    for p in (pres.u, pres.v, pres.u_s, pres.owner_commitment, pres.nullifier):
        if p.is_infinity():
            return False
    if not 0 <= pres.h < curve_order:
        return False
    if not verify_dlog_eq(
        [G1, G_NULL, pres.u],
        [pres.owner_commitment, pres.nullifier, pres.u_s],
        pres.proof,
        PS_PRESENT_DST,
    ):
        return False
    base_h = PublicKey(
        point=mint_public.X2.point + mint_public.Y_h2.point.scalar_mul(pres.h),
        group="G2",
    )
    miller = pyblst.miller_loop(-pres.v.point, G2)
    miller = miller * pyblst.miller_loop(pres.u.point, base_h.point)
    miller = miller * pyblst.miller_loop(pres.u_s.point, mint_public.Y_s2.point)
    return pyblst.final_verify(miller, pyblst.BlstFP12Element())

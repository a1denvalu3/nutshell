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
import hmac
import os
from dataclasses import dataclass
from typing import List, Mapping, Optional, Tuple

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


def _g1_from_bytes(compressed: bytes) -> PublicKey:
    try:
        return PublicKey(compressed=compressed, group="G1")
    except ValueError:
        raise ValueError("invalid G1 point encoding")


def _g2_from_bytes(compressed: bytes) -> PublicKey:
    try:
        return PublicKey(compressed=compressed, group="G2")
    except ValueError:
        raise ValueError("invalid G2 point encoding")


def _scalar_from_bytes(raw: bytes) -> int:
    if len(raw) != 32:
        raise ValueError("scalars are 32 bytes")
    scalar = int.from_bytes(raw, "big")
    if scalar >= curve_order:
        raise ValueError("scalar out of range")
    return scalar


def hash_asset_parts(parts: List[bytes]) -> int:
    """Streaming variant of hash_asset for large assets: SHA-256 over
    length-prefixed chunks under the same domain separator."""
    hasher = hashlib.sha256(PS_ASSET_DST)
    for chunk in parts:
        hasher.update(len(chunk).to_bytes(8, "big") + chunk)
    return int.from_bytes(hasher.digest(), "big") % curve_order


@dataclass
class DlogEqProof:
    """Chaum-Pedersen proof that one scalar is the discrete log of n points
    with respect to n bases."""

    challenge: int
    response: int

    def to_bytes(self) -> bytes:
        return _scalar_bytes(self.challenge) + _scalar_bytes(self.response)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DlogEqProof":
        if len(raw) != 64:
            raise ValueError("DlogEqProof is 64 bytes")
        return cls(
            challenge=_scalar_from_bytes(raw[:32]),
            response=_scalar_from_bytes(raw[32:]),
        )


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


PS_KEY_DST = b"Cashu_PS_Key_v1"


def _derive_scalar(seed: bytes, label: bytes) -> int:
    scalar = 0
    counter = 0
    while not 0 < scalar < curve_order:
        scalar = (
            int.from_bytes(
                hashlib.sha256(
                    PS_KEY_DST + label + counter.to_bytes(4, "big") + seed
                ).digest(),
                "big",
            )
            % curve_order
        )
        counter += 1
    return scalar


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

    @classmethod
    def from_seed(cls, seed: bytes) -> "MintPrivateKeyPS":
        """Deterministically derive a mint key from at least 16 bytes of
        seed entropy, so mint keys can be backed up and restored."""
        if len(seed) < 16:
            raise ValueError("seed must be at least 16 bytes")
        return cls(
            x=PrivateKey(scalar=_derive_scalar(seed, b"x")),
            y_h=PrivateKey(scalar=_derive_scalar(seed, b"y_h")),
            y_s=PrivateKey(scalar=_derive_scalar(seed, b"y_s")),
        )

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

    def to_bytes(self) -> bytes:
        return self.X2.format() + self.Y_h2.format() + self.Y_s2.format()

    @classmethod
    def from_bytes(cls, raw: bytes) -> "MintPublicKeyPS":
        if len(raw) != 288:
            raise ValueError("MintPublicKeyPS is 288 bytes")
        return cls(
            X2=_g2_from_bytes(raw[:96]),
            Y_h2=_g2_from_bytes(raw[96:192]),
            Y_s2=_g2_from_bytes(raw[192:]),
        )

    @property
    def keyset_id(self) -> str:
        """16-hex-char identifier of this parameter set, cashu keyset style.

        Credentials and presentations carry it so verifiers can select the
        right parameters across key rotations."""
        return hashlib.sha256(self.to_bytes()).hexdigest()[:16]


def _keyset_id_from_bytes(raw: bytes) -> str:
    if len(raw) != 8:
        raise ValueError("keyset id is 8 bytes")
    return raw.hex()


def _keyset_id_to_bytes(keyset_id: str) -> bytes:
    try:
        raw = bytes.fromhex(keyset_id)
    except ValueError:
        raise ValueError("keyset id must be hex")
    if len(raw) != 8:
        raise ValueError("keyset id must be 16 hex chars")
    return raw


@dataclass
class Credential:
    """A PS credential as held by its owner."""

    u: PublicKey
    v: PublicKey
    h: int
    s: int
    keyset_id: str = ""

    def to_bytes(self) -> bytes:
        return (
            _keyset_id_to_bytes(self.keyset_id)
            + self.u.format()
            + self.v.format()
            + _scalar_bytes(self.h)
            + _scalar_bytes(self.s)
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Credential":
        if len(raw) != 168:
            raise ValueError("Credential is 168 bytes")
        return cls(
            u=_g1_from_bytes(raw[8:56]),
            v=_g1_from_bytes(raw[56:104]),
            h=_scalar_from_bytes(raw[104:136]),
            s=_scalar_from_bytes(raw[136:]),
            keyset_id=_keyset_id_from_bytes(raw[:8]),
        )


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
    keyset_id: str = ""

    def to_bytes(self) -> bytes:
        return (
            _keyset_id_to_bytes(self.keyset_id)
            + _scalar_bytes(self.h)
            + self.u.format()
            + self.v.format()
            + self.u_s.format()
            + self.owner_commitment.format()
            + self.nullifier.format()
            + self.proof.to_bytes()
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Presentation":
        if len(raw) != 344:
            raise ValueError("Presentation is 344 bytes")
        return cls(
            keyset_id=_keyset_id_from_bytes(raw[:8]),
            h=_scalar_from_bytes(raw[8:40]),
            u=_g1_from_bytes(raw[40:88]),
            v=_g1_from_bytes(raw[88:136]),
            u_s=_g1_from_bytes(raw[136:184]),
            owner_commitment=_g1_from_bytes(raw[184:232]),
            nullifier=_g1_from_bytes(raw[232:280]),
            proof=DlogEqProof.from_bytes(raw[280:]),
        )


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
        h=cred.h,
        u=u_r,
        v=v_r,
        u_s=u_s,
        owner_commitment=S,
        nullifier=N,
        proof=proof,
        keyset_id=cred.keyset_id,
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


def verify_presentation_keysets(
    keysets: Mapping[str, MintPublicKeyPS], pres: Presentation
) -> bool:
    """Verify a presentation against the keyset it names, so verifiers can
    hold parameters for every key generation a mint has ever used."""
    if pres.keyset_id not in keysets:
        return False
    return verify_presentation(keysets[pres.keyset_id], pres)


# --- Hidden-h private transfers -------------------------------------------
#
# A private presentation never reveals the asset hash. Instead of checking
# e(u', Y_h2^h) the verifier checks e(U_h, Y_h2) with the witness
# U_h = h * u', and a Chaum-Pedersen proof ties h to that base. Re-issuance
# is blind: the mint derives a fresh base u2 deterministically from the
# nullifier, the owner shows W_h = h * u2 with a dlog-eq proof that the
# same h sits in U_h and W_h, and the mint computes
# v2 = u2^x * W_h^{y_h} * S_new^{k2 * y_s} without ever learning h.
#
# Privacy scope: h leaves the owner's wallet in no message. The mint still
# learns *that* a transfer happened and can correlate the old and new
# owner commitments; a mint that shadows its registry can still reverse
# the lookup. This is honest-but-curious privacy for the asset id, not
# full KVAC anonymity.

PS_PRIVATE_DST = b"Cashu_PS_Private_v1"
PS_BLIND_DST = b"Cashu_PS_Blind_v1"
PS_K2_DST = b"Cashu_PS_TransferK2_v1"


def blind_base_for_nullifier(
    mint_key: MintPrivateKeyPS, nullifier: bytes
) -> Tuple[int, PublicKey]:
    """Deterministic fresh base u2 = g1^k2 for one nullifier, so the
    two-round blind transfer is stateless: begin and complete derive the
    same u2 and the user cannot substitute another base."""
    k2 = 0
    counter = 0
    while not 0 < k2 < curve_order:
        k2 = (
            int.from_bytes(
                hmac.new(
                    mint_key.x.private_key,
                    PS_K2_DST + counter.to_bytes(4, "big") + nullifier,
                    hashlib.sha256,
                ).digest(),
                "big",
            )
            % curve_order
        )
        counter += 1
    return k2, G1 * k2


@dataclass
class PrivatePresentation:
    """A randomized credential presentation that keeps h hidden."""

    u: PublicKey
    v: PublicKey
    u_h: PublicKey  # h * u
    u_s: PublicKey  # s * u
    owner_commitment: PublicKey  # S = g1^s
    nullifier: PublicKey  # N = G_NULL^s
    proof_h: DlogEqProof
    proof_s: DlogEqProof
    keyset_id: str = ""

    def to_bytes(self) -> bytes:
        return (
            _keyset_id_to_bytes(self.keyset_id)
            + self.u.format()
            + self.v.format()
            + self.u_h.format()
            + self.u_s.format()
            + self.owner_commitment.format()
            + self.nullifier.format()
            + self.proof_h.to_bytes()
            + self.proof_s.to_bytes()
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PrivatePresentation":
        if len(raw) != 424:
            raise ValueError("PrivatePresentation is 424 bytes")
        return cls(
            keyset_id=_keyset_id_from_bytes(raw[:8]),
            u=_g1_from_bytes(raw[8:56]),
            v=_g1_from_bytes(raw[56:104]),
            u_h=_g1_from_bytes(raw[104:152]),
            u_s=_g1_from_bytes(raw[152:200]),
            owner_commitment=_g1_from_bytes(raw[200:248]),
            nullifier=_g1_from_bytes(raw[248:296]),
            proof_h=DlogEqProof.from_bytes(raw[296:360]),
            proof_s=DlogEqProof.from_bytes(raw[360:]),
        )


def present_private(cred: Credential, rho: Optional[int] = None) -> PrivatePresentation:
    if not 0 < cred.h < curve_order:
        raise ValueError("h must be in Fr* for a private presentation")
    if not 0 < cred.s < curve_order:
        raise ValueError("owner secret must be in Fr*")
    rho = rho or _random_scalar()
    if not 0 < rho < curve_order:
        raise ValueError("rho must be in Fr*")
    u_r = cred.u * rho
    v_r = cred.v * rho
    u_h = u_r * cred.h
    u_s = u_r * cred.s
    S = G1 * cred.s
    N = G_NULL * cred.s
    proof_h = prove_dlog_eq([u_r], [u_h], cred.h, PS_PRIVATE_DST)
    proof_s = prove_dlog_eq([G1, G_NULL, u_r], [S, N, u_s], cred.s, PS_PRESENT_DST)
    return PrivatePresentation(
        u=u_r,
        v=v_r,
        u_h=u_h,
        u_s=u_s,
        owner_commitment=S,
        nullifier=N,
        proof_h=proof_h,
        proof_s=proof_s,
        keyset_id=cred.keyset_id,
    )


def verify_private_presentation(
    mint_public: MintPublicKeyPS, pres: PrivatePresentation
) -> bool:
    for p in (
        pres.u,
        pres.v,
        pres.u_h,
        pres.u_s,
        pres.owner_commitment,
        pres.nullifier,
    ):
        if p.is_infinity():
            return False
    if not verify_dlog_eq([pres.u], [pres.u_h], pres.proof_h, PS_PRIVATE_DST):
        return False
    if not verify_dlog_eq(
        [G1, G_NULL, pres.u],
        [pres.owner_commitment, pres.nullifier, pres.u_s],
        pres.proof_s,
        PS_PRESENT_DST,
    ):
        return False
    miller = pyblst.miller_loop(-pres.v.point, G2)
    miller = miller * pyblst.miller_loop(pres.u.point, mint_public.X2.point)
    miller = miller * pyblst.miller_loop(pres.u_h.point, mint_public.Y_h2.point)
    miller = miller * pyblst.miller_loop(pres.u_s.point, mint_public.Y_s2.point)
    return pyblst.final_verify(miller, pyblst.BlstFP12Element())


def blind_transfer_witness(
    cred: Credential, u_r: PublicKey, u2: PublicKey
) -> Tuple[PublicKey, DlogEqProof]:
    """Owner side of blind re-issuance: W_h = h * u2 and a proof that the
    same h sits in the presentation's U_h (base u') and W_h (base u2)."""
    if u2.is_infinity():
        raise ValueError("u2 must not be the point at infinity")
    w_h = u2 * cred.h
    proof = prove_dlog_eq([u_r, u2], [u_r * cred.h, w_h], cred.h, PS_BLIND_DST)
    return w_h, proof


def verify_blind_transfer(
    mint_public: MintPublicKeyPS,
    pres: PrivatePresentation,
    w_h: PublicKey,
    proof: DlogEqProof,
    u2: PublicKey,
) -> bool:
    if u2.is_infinity() or w_h.is_infinity():
        return False
    if not verify_private_presentation(mint_public, pres):
        return False
    return verify_dlog_eq([pres.u, u2], [pres.u_h, w_h], proof, PS_BLIND_DST)


def issue_blind(
    mint_key: MintPrivateKeyPS, k2: int, u2: PublicKey, w_h: PublicKey, S_new: PublicKey
) -> PublicKey:
    """v2 = u2^{x + y_h * h + y_s * s_new}, computed without learning h:
    u2^{y_h * h} = W_h^{y_h}."""
    if not 0 < k2 < curve_order:
        raise ValueError("k2 must be in Fr*")
    for p in (u2, w_h, S_new):
        if p.is_infinity():
            raise ValueError("points must not be the point at infinity")
    return _add_p1(
        _add_p1(u2 * mint_key.x.scalar, w_h * mint_key.y_h.scalar),
        S_new * ((k2 * mint_key.y_s.scalar) % curve_order),
    )


PS_BATCH_DST = b"Cashu_PS_Batch_v1"


def _derive_batch_scalars(presentations: List[Presentation]) -> List[int]:
    transcript = PS_BATCH_DST
    for pres in presentations:
        transcript += pres.to_bytes()
    seed = hashlib.sha256(transcript).digest()
    scalars = []
    for i in range(len(presentations)):
        counter = 0
        while True:
            digest = hashlib.sha256(
                seed + i.to_bytes(4, "big") + counter.to_bytes(4, "big")
            ).digest()
            scalar = int.from_bytes(digest, "big")
            if 0 < scalar < curve_order:
                scalars.append(scalar)
                break
            counter += 1
    return scalars


def batch_verify_presentations(
    mint_public: MintPublicKeyPS, presentations: List[Presentation]
) -> bool:
    """Verify many same-keyset presentations with one combined pairing.

    The dlog-eq proofs are checked individually (cheap); the pairing
    equations are folded into a random linear combination:

        e(sum r_i v_i, g2) == e(sum r_i u_i, X2)
                            * e(sum r_i h_i u_i, Y_h2)
                            * e(sum r_i u_s_i, Y_s2)
    """
    if not presentations:
        return True
    for pres in presentations:
        if not 0 <= pres.h < curve_order:
            return False
        for p in (pres.u, pres.v, pres.u_s, pres.owner_commitment, pres.nullifier):
            if p.is_infinity():
                return False
        if not verify_dlog_eq(
            [G1, G_NULL, pres.u],
            [pres.owner_commitment, pres.nullifier, pres.u_s],
            pres.proof,
            PS_PRESENT_DST,
        ):
            return False
    rs = _derive_batch_scalars(presentations)
    sum_v = presentations[0].v.point.scalar_mul(rs[0])
    sum_u = presentations[0].u.point.scalar_mul(rs[0])
    sum_hu = presentations[0].u.point.scalar_mul(
        (rs[0] * presentations[0].h) % curve_order
    )
    sum_us = presentations[0].u_s.point.scalar_mul(rs[0])
    for pres, r in zip(presentations[1:], rs[1:]):
        sum_v = sum_v + pres.v.point.scalar_mul(r)
        sum_u = sum_u + pres.u.point.scalar_mul(r)
        sum_hu = sum_hu + pres.u.point.scalar_mul((r * pres.h) % curve_order)
        sum_us = sum_us + pres.u_s.point.scalar_mul(r)
    miller = pyblst.miller_loop(-sum_v, G2)
    miller = miller * pyblst.miller_loop(sum_u, mint_public.X2.point)
    miller = miller * pyblst.miller_loop(sum_hu, mint_public.Y_h2.point)
    miller = miller * pyblst.miller_loop(sum_us, mint_public.Y_s2.point)
    return pyblst.final_verify(miller, pyblst.BlstFP12Element())

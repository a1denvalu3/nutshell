"""
Pointcheval-Sanders credentials on BLS12-381 for asset-bound NFT credentials.

Experimental. A credential signs two attributes:
    h -- scalar hash of the asset (e.g. a JPEG digest). Blind issuance hides
         this scalar but reveals a deterministic, candidate-testable asset tag.
    s -- owner secret, never revealed to the mint, bound into the credential
         during issuance with a Diffie-Hellman trick.

Mint secret key: (x, y_h, y_s). Public parameters live in G2, plus one G1
point needed for blind re-issuance:
    X2 = g2^x, Y_h2 = g2^{y_h}, Y_s2 = g2^{y_s}, Y_h1 = g1^{y_h}
Publishing the y values in G2 is what prevents the exponent rescaling
forgery: moving a credential from h1 to h2 would require u^{y_h}, which is
exactly what the mint withholds. Y_h1 in G1 does not change that: g1^{y_h}
does not yield u^{y_h} without solving CDH in G1 (a type-3 pairing gives
no G1<->G2 homomorphism). y_s stays G2-only.

Issuance (blind in s):
    user sends S = g1^s with a proof of knowledge of s
    mint picks k at random, u = g1^k
    v = u^{x + y_h * h} * S^{k * y_s} = u^{x + y_h*h + y_s*s}

Presentation (public, offline verifiable):
    user randomizes (u', v') = (u^rho, v^rho) and reveals
    (h, u', v', U_s = u'^s, N = G_NULL^s, dlog-eq proof of s)
    authenticity: e(v', g2) == e(u', X2 * Y_h2^h) * e(U_s, Y_s2)
    ownership:    Chaum-Pedersen proof that the same s sits in N (G_NULL)
                  and U_s (u'). All bases are G1 points, so no GT
                  exponentiation is needed.
    The owner commitment S = g1^s is NOT part of a presentation: it is
    only used at issuance/transfer time (the Diffie-Hellman trick needs
    it there), so a presentation cannot be matched against the S values
    in the mint's issuance logs.

Transfer:
    the mint checks the presentation, enforces nullifier N freshness, then
    re-issues a credential over the same h with the new owner's secret.

Purpose binding:
    every presentation proof's Fiat-Shamir transcript carries a length-framed
    binding right after the domain separator, so a presentation is only
    usable for one exact purpose:
      transfers bind S_new (only that exact re-issuance accepts them),
      burns bind PS_BURN_BINDING,
      showings bind PS_SHOW_BINDING + a context (verifiable offline, but
      rejected by transfer and burn -- a published showing cannot be
      replayed into a spend).
    The binding never goes on the wire: it lives only inside the challenge
    computation, so wire formats are unchanged and the verifier must know
    the expected binding out of band.
"""

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import List, Mapping, Optional, Tuple

import pyblst

from .bls import G2, PrivateKey, PublicKey, curve_order
from .keys import derive_keyset_id_psnft

# BLS12-381 G1 generator, compressed
_G1_HEX = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
G1 = PublicKey(compressed=bytes.fromhex(_G1_HEX), group="G1")

# Domain separation tags
PS_ASSET_DST = b"Cashu_PS_Asset_v1"
PS_ISSUE_DST = b"Cashu_PS_Issue_v1"
PS_PRESENT_DST = b"Cashu_PS_Present_v1"
PS_GNULL_DST = b"CASHU_PS_GNULL_XMD:SHA-256_SSWU_RO_"

# Purpose bindings for presentation proofs (see the module docstring)
PS_SHOW_BINDING = b"Cashu_PS_Showing_v1"
PS_BURN_BINDING = b"Cashu_PS_Burn_v1"

# Nullifier base: nothing-up-my-sleeve G1 point with unknown discrete log
G_NULL = PublicKey(
    point=pyblst.BlstP1Element().hash_to_group(b"ps_nullifier_base", PS_GNULL_DST),
    group="G1",
)

# Public duplicate-detection base, distinct from the owner nullifier base.
# This tag reveals equality and permits offline tests of candidate assets.
G_ASSET = PublicKey(
    point=pyblst.BlstP1Element().hash_to_group(
        b"ps_asset_tag_base", b"CASHU_PS_ASSET_TAG_XMD:SHA-256_SSWU_RO_"
    ),
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


def _add_pk(a: PublicKey, b: PublicKey) -> PublicKey:
    return PublicKey(point=a.point + b.point, group=a.group)


def _neg_pk(a: PublicKey) -> PublicKey:
    return PublicKey(point=-a.point, group=a.group)


def _infinity(group: str) -> PublicKey:
    point = pyblst.BlstP1Element() if group == "G1" else pyblst.BlstP2Element()
    return PublicKey(point=point, group=group)


# G2 generator as a PublicKey (bls.G2 is the raw pyblst element, used in
# miller loops)
G2_PK = PublicKey(point=G2, group="G2")


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
    binding: bytes = b"",
) -> bytes:
    transcript = dst + len(binding).to_bytes(2, "big") + binding
    for group in (bases, points, commitments):
        for p in group:
            serialized = p.format()
            transcript += len(serialized).to_bytes(2, "big") + serialized
    return transcript


def prove_dlog_eq(
    bases: List[PublicKey],
    points: List[PublicKey],
    secret: int,
    dst: bytes,
    binding: bytes = b"",
) -> DlogEqProof:
    if not bases or len(bases) != len(points):
        raise ValueError("need an equal, nonzero number of bases and points")
    if not 0 < secret < curve_order:
        raise ValueError("secret must be in Fr*")
    nonce = _random_scalar()
    commitments = [base * nonce for base in bases]
    challenge = _challenge(
        _dlog_eq_transcript(dst, bases, points, commitments, binding)
    )
    response = (nonce + challenge * secret) % curve_order
    return DlogEqProof(challenge=challenge, response=response)


def verify_dlog_eq(
    bases: List[PublicKey],
    points: List[PublicKey],
    proof: DlogEqProof,
    dst: bytes,
    binding: bytes = b"",
) -> bool:
    if not bases or len(bases) != len(points):
        return False
    if not (0 <= proof.challenge < curve_order and 0 <= proof.response < curve_order):
        return False
    commitments = [
        _add_p1(base * proof.response, _neg_p1(point * proof.challenge))
        for base, point in zip(bases, points)
    ]
    expected = _challenge(_dlog_eq_transcript(dst, bases, points, commitments, binding))
    return expected == proof.challenge


# A linear statement: point == sum of base * witness[index] over terms.
# Bases and the point must share a group, but different statements may use
# different groups (G1 and G2 both have order r; the scalar math is shared).
LinearStatement = Tuple[PublicKey, List[Tuple[PublicKey, int]]]


@dataclass
class LinearProof:
    """Multi-witness sigma proof (Fiat-Shamir): knowledge of witnesses
    w_0..w_{n-1} satisfying every statement simultaneously, proving the
    SAME witness values across statements (e.g. one h in both a G2
    commitment and a G1 commitment)."""

    challenge: int
    responses: List[int]

    def to_bytes(self) -> bytes:
        return _scalar_bytes(self.challenge) + b"".join(
            _scalar_bytes(r) for r in self.responses
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "LinearProof":
        if len(raw) < 64 or len(raw) % 32 != 0:
            raise ValueError("LinearProof is 32 * (n + 1) bytes")
        return cls(
            challenge=_scalar_from_bytes(raw[:32]),
            responses=[
                _scalar_from_bytes(raw[i : i + 32]) for i in range(32, len(raw), 32)
            ],
        )


def _linear_num_witnesses(statements: List[LinearStatement]) -> int:
    n = 0
    for _, terms in statements:
        for _, witness_index in terms:
            n = max(n, witness_index + 1)
    return n


def _linear_combine(
    terms: List[Tuple[PublicKey, int]], scalars: List[int]
) -> PublicKey:
    acc = _infinity(terms[0][0].group)
    for base, i in terms:
        acc = _add_pk(acc, base * scalars[i])
    return acc


def _linear_transcript(
    dst: bytes,
    binding: bytes,
    statements: List[LinearStatement],
    commitments: List[PublicKey],
) -> bytes:
    transcript = dst + len(binding).to_bytes(2, "big") + binding
    for (point, terms), commitment in zip(statements, commitments):
        for p in (point, commitment):
            serialized = p.format()
            transcript += len(serialized).to_bytes(2, "big") + serialized
        for base, witness_index in terms:
            serialized = base.format()
            transcript += (
                len(serialized).to_bytes(2, "big")
                + serialized
                + witness_index.to_bytes(2, "big")
            )
    return transcript


def prove_linear(
    statements: List[LinearStatement],
    witnesses: List[int],
    dst: bytes,
    binding: bytes = b"",
) -> LinearProof:
    if not statements:
        raise ValueError("need at least one statement")
    if _linear_num_witnesses(statements) != len(witnesses):
        raise ValueError("witness count does not match the statements")
    if any(not 0 <= w < curve_order for w in witnesses):
        raise ValueError("witnesses must be scalars")
    nonces = [_random_scalar() for _ in witnesses]
    commitments = [_linear_combine(terms, nonces) for _, terms in statements]
    challenge = _challenge(_linear_transcript(dst, binding, statements, commitments))
    responses = [
        (nonce + challenge * w) % curve_order for nonce, w in zip(nonces, witnesses)
    ]
    return LinearProof(challenge=challenge, responses=responses)


def verify_linear(
    statements: List[LinearStatement],
    proof: LinearProof,
    dst: bytes,
    binding: bytes = b"",
) -> bool:
    if not statements:
        return False
    if len(proof.responses) != _linear_num_witnesses(statements):
        return False
    if not 0 <= proof.challenge < curve_order:
        return False
    if any(not 0 <= r < curve_order for r in proof.responses):
        return False
    commitments = [
        _add_pk(
            _linear_combine(terms, proof.responses),
            _neg_pk(point * proof.challenge),
        )
        for point, terms in statements
    ]
    expected = _challenge(_linear_transcript(dst, binding, statements, commitments))
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
            Y_h1=G1 * self.y_h.scalar,
        )


class MintPublicKeyPS:
    """Mint public parameters.

    Y_h1 = y_h * g1 lives in G1 so the owner can strip the re-issuance
    correction term after a blind transfer (unblind_issued). Publishing it
    does not weaken forgery resistance: moving a credential between assets
    still requires u^{y_h}, and g1^{y_h} does not yield that without
    solving CDH in G1 (a type-3 pairing gives no G1<->G2 homomorphism).
    y_s remains G2-only. The other values exist in G2 only, by construction.
    """

    def __init__(
        self, X2: PublicKey, Y_h2: PublicKey, Y_s2: PublicKey, Y_h1: PublicKey
    ):
        self.X2 = X2
        self.Y_h2 = Y_h2
        self.Y_s2 = Y_s2
        self.Y_h1 = Y_h1

    def to_bytes(self) -> bytes:
        return (
            self.X2.format()
            + self.Y_h2.format()
            + self.Y_s2.format()
            + self.Y_h1.format()
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "MintPublicKeyPS":
        if len(raw) != 336:
            raise ValueError("MintPublicKeyPS is 336 bytes")
        return cls(
            X2=_g2_from_bytes(raw[:96]),
            Y_h2=_g2_from_bytes(raw[96:192]),
            Y_s2=_g2_from_bytes(raw[192:288]),
            Y_h1=_g1_from_bytes(raw[288:]),
        )

    @property
    def keyset_id(self) -> str:
        """Version-03 identifier of this parameter set, derived the same
        way as v3 ecash keysets: a full 32-byte SHA-256 hash behind a
        version byte, committing to a length-framed preimage of the three
        G2 points and the G1 point Y_h1 (see keys.derive_keyset_id_psnft).

        Credentials and presentations carry it so verifiers can select the
        right parameters across key rotations."""
        return derive_keyset_id_psnft(
            self.X2.format(),
            self.Y_h2.format(),
            self.Y_s2.format(),
            self.Y_h1.format(),
        )


# keyset ids on the wire: 33 raw bytes (2-hex version byte + 32-byte hash)
KEYSET_ID_BYTES = 33


def _keyset_id_from_bytes(raw: bytes) -> str:
    if len(raw) != KEYSET_ID_BYTES:
        raise ValueError(f"keyset id is {KEYSET_ID_BYTES} bytes")
    return raw.hex()


def _keyset_id_to_bytes(keyset_id: str) -> bytes:
    try:
        raw = bytes.fromhex(keyset_id)
    except ValueError:
        raise ValueError("keyset id must be hex")
    if len(raw) != KEYSET_ID_BYTES:
        raise ValueError(f"keyset id must be {2 * KEYSET_ID_BYTES} hex chars")
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
        if len(raw) != 193:
            raise ValueError("Credential is 193 bytes")
        return cls(
            u=_g1_from_bytes(raw[33:81]),
            v=_g1_from_bytes(raw[81:129]),
            h=_scalar_from_bytes(raw[129:161]),
            s=_scalar_from_bytes(raw[161:]),
            keyset_id=_keyset_id_from_bytes(raw[:33]),
        )


@dataclass
class Presentation:
    """A randomized, publicly verifiable credential presentation."""

    h: int
    u: PublicKey
    v: PublicKey
    u_s: PublicKey
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
            + self.nullifier.format()
            + self.proof.to_bytes()
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Presentation":
        if len(raw) != 321:
            raise ValueError("Presentation is 321 bytes")
        return cls(
            keyset_id=_keyset_id_from_bytes(raw[:33]),
            h=_scalar_from_bytes(raw[33:65]),
            u=_g1_from_bytes(raw[65:113]),
            v=_g1_from_bytes(raw[113:161]),
            u_s=_g1_from_bytes(raw[161:209]),
            nullifier=_g1_from_bytes(raw[209:257]),
            proof=DlogEqProof.from_bytes(raw[257:]),
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


def present(
    cred: Credential, rho: Optional[int] = None, binding: bytes = b""
) -> Presentation:
    """Owner side: randomize the credential and build the presentation.
    The binding is mixed into the proof transcript, tying the presentation
    to one exact purpose (see the module docstring)."""
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
    N = G_NULL * cred.s
    proof = prove_dlog_eq([G_NULL, u_r], [N, u_s], cred.s, PS_PRESENT_DST, binding)
    return Presentation(
        h=cred.h,
        u=u_r,
        v=v_r,
        u_s=u_s,
        nullifier=N,
        proof=proof,
        keyset_id=cred.keyset_id,
    )


def verify_presentation(
    mint_public: MintPublicKeyPS, pres: Presentation, binding: bytes = b""
) -> bool:
    """Public, offline verification of a presentation.

    Checks authenticity (pairing equation against the mint's G2 parameters)
    and ownership (the same s in N and u_s). The caller must supply the
    purpose binding the presentation was created with, ask the mint whether
    pres.nullifier is spent (the only unspent nullifier belongs to the
    current holder) and, for transfers, claim the nullifier atomically with
    the re-issuance.
    """
    for p in (pres.u, pres.v, pres.u_s, pres.nullifier):
        if p.is_infinity():
            return False
    if not 0 <= pres.h < curve_order:
        return False
    if not verify_dlog_eq(
        [G_NULL, pres.u],
        [pres.nullifier, pres.u_s],
        pres.proof,
        PS_PRESENT_DST,
        binding,
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


def _showing_binding(context: bytes) -> bytes:
    return PS_SHOW_BINDING + len(context).to_bytes(2, "big") + context


def present_showing(
    cred: Credential, context: bytes, rho: Optional[int] = None
) -> Presentation:
    """A verify-only presentation bound to a caller-chosen context (e.g. a
    nonce or the verifier's identity). Showings are rejected by the mint's
    spend endpoints, so publishing one cannot lose the NFT."""
    return present(cred, rho=rho, binding=_showing_binding(context))


def verify_showing(
    mint_public: MintPublicKeyPS, pres: Presentation, context: bytes
) -> bool:
    """Verify a showing against the context it claims to be bound to."""
    return verify_presentation(mint_public, pres, binding=_showing_binding(context))


def verify_presentation_keysets(
    keysets: Mapping[str, MintPublicKeyPS], pres: Presentation
) -> bool:
    """Verify a presentation against the keyset it names, so verifiers can
    hold parameters for every key generation a mint has ever used."""
    if pres.keyset_id not in keysets:
        return False
    return verify_presentation(keysets[pres.keyset_id], pres)


# --- Hidden-h private transfers (PS16/Coconut-style blinded aggregates) ----
#
# A private presentation commits to the asset hash instead of revealing it:
#
#     u'  = rho * u                        (randomized base, as before)
#     v'' = rho * v + o * u'               (rerandomized MAC, blinded by o)
#     kappa_h = h * Y_h2 + o * g2          (G2 Pedersen commitment to h)
#     U_s = s * u', N = s * G_NULL, pi_s   (unchanged ownership proof)
#
# and the verifier checks
#     e(v'', g2) == e(u', X2) * e(u', kappa_h) * e(U_s, Y_s2)
# which closes because e(u', kappa_h) supplies exactly the rho*y_h*h + rho*o
# terms of v''. kappa_h needs no proof of its own: every G2 point is a valid
# commitment, the pairing binds it to the credential, and the transfer-time
# equality proof below proves knowledge of its opening.
#
# Crucially this is NOT searchable: for any candidate h_i there exists a
# consistent blinding o_i with kappa_h = h_i * Y_h2 + o_i * g2, so a mint
# holding every minted h_i cannot enumerate the presentation. (The previous
# U_h = h*u' construction failed this: U_h == h_i*u' was a one-pairing-free
# test per candidate.)
#
# Re-issuance is blind:
#     owner:  B = h * u2 + t * g1          (G1 Pedersen commitment to h)
#             pi_eq: one multi-witness sigma proof with witnesses (h, o, t)
#             showing the SAME h opens kappa_h (bases Y_h2, g2) and B
#             (bases u2, g1)
#     mint:   v2_raw = x*u2 + y_h*B + (k2*y_s)*S_new
#                       = credential + t * y_h * g1
#     owner:  v2 = v2_raw - t * Y_h1       (unblind_issued; needs Y_h1 in G1)
#
# Privacy scope: h leaves the owner's wallet only inside Pedersen
# commitments, so the mint learns nothing about which asset moved --
# enumeration is information-theoretically impossible. The mint still
# learns *that* a transfer happened and sees the spent nullifier; since the
# previous generation's nullifier is claimed on every transfer, the mint
# can tell when a given credential generation dies.

PS_COMMIT_DST = b"Cashu_PS_CommitEq_v1"
PS_K2_DST = b"Cashu_PS_TransferK2_v1"
PS_BLIND_ISSUE_DST = b"Cashu_PS_BlindIssue_v1"
PS_BLIND_ISSUE_V2_DST = b"Cashu_PS_BlindIssue_v2"
PS_COMMITTED_ISSUE_DST = b"Cashu_PS_CommittedIssue_v3"
PS_ISSUE_K_DST = b"Cashu_PS_IssueK_v1"


def asset_tag(h: int) -> PublicKey:
    """Public deterministic tag D = h * G_ASSET; this is not a hiding hash."""
    if not 0 <= h < curve_order:
        raise ValueError("h must be a scalar")
    return G_ASSET * h


def blind_issue_binding(mint_public: MintPublicKeyPS, session: bytes) -> bytes:
    if len(session) != 16:
        raise ValueError("issuance session must be 16 bytes")
    return bytes.fromhex(mint_public.keyset_id) + session


def blind_base_for_issuance(
    mint_key: MintPrivateKeyPS, session: bytes
) -> Tuple[int, PublicKey]:
    """Mint-controlled base for a persisted, single-use issuance session."""
    if len(session) != 16:
        raise ValueError("issuance session must be 16 bytes")
    counter = 0
    while True:
        digest = hmac.new(
            mint_key.x.private_key,
            PS_ISSUE_K_DST + counter.to_bytes(4, "big") + session,
            hashlib.sha256,
        ).digest()
        k = int.from_bytes(digest, "big") % curve_order
        if k:
            return k, G1 * k
        counter += 1


def _blind_issue_statements(
    D: PublicKey, B: PublicKey, u: PublicKey, S: PublicKey
) -> List[LinearStatement]:
    return [
        (D, [(G_ASSET, 0)]),
        (B, [(u, 0), (G1, 1)]),
        (S, [(G1, 2)]),
    ]


def blind_issue_commit(
    mint_public: MintPublicKeyPS, h: int, s: int, u: PublicKey, session: bytes
) -> Tuple[PublicKey, PublicKey, int, LinearProof]:
    """Prove the tag and blind commitment contain the same h, and know s.

    Returns (D, B, t, proof). Keep t locally to unblind the signature.
    The transcript binds the mint keyset, single-use session, base and S.
    """
    if u.is_infinity() or not 0 < s < curve_order:
        raise ValueError("invalid issuance base or owner secret")
    D = asset_tag(h)
    t = _random_scalar()
    B = _add_p1(u * h, G1 * t)
    proof = prove_linear(
        _blind_issue_statements(D, B, u, G1 * s),
        [h, t, s],
        PS_BLIND_ISSUE_DST,
        blind_issue_binding(mint_public, session),
    )
    return D, B, t, proof


def verify_blind_issue(
    mint_public: MintPublicKeyPS,
    D: PublicKey,
    B: PublicKey,
    u: PublicKey,
    S: PublicKey,
    proof: LinearProof,
    session: bytes,
) -> bool:
    if u.is_infinity() or B.is_infinity() or S.is_infinity():
        return False
    return verify_linear(
        _blind_issue_statements(D, B, u, S),
        proof,
        PS_BLIND_ISSUE_DST,
        blind_issue_binding(mint_public, session),
    )


def blind_issue_commit_v2(
    mint_public: MintPublicKeyPS, h: int, s: int, request_id: bytes
) -> Tuple[PublicKey, PublicKey, int, LinearProof]:
    """One-request issuance: C = h*Y_h1 + t*G1, before the mint chooses u.

    Prove knowledge of h,t,s and equality of h with the public duplicate tag.
    Bind the noninteractive proof to this keyset and client-chosen request ID.
    """
    if not 0 < s < curve_order:
        raise ValueError("invalid owner secret")
    D = asset_tag(h)
    t = _random_scalar()
    C = _add_p1(mint_public.Y_h1 * h, G1 * t)
    proof = prove_linear(
        _blind_issue_statements(D, C, mint_public.Y_h1, G1 * s),
        [h, t, s],
        PS_BLIND_ISSUE_V2_DST,
        blind_issue_binding(mint_public, request_id),
    )
    return D, C, t, proof


def verify_blind_issue_v2(
    mint_public: MintPublicKeyPS,
    D: PublicKey,
    C: PublicKey,
    S: PublicKey,
    proof: LinearProof,
    request_id: bytes,
) -> bool:
    if C.is_infinity() or S.is_infinity():
        return False
    return verify_linear(
        _blind_issue_statements(D, C, mint_public.Y_h1, S),
        proof,
        PS_BLIND_ISSUE_V2_DST,
        blind_issue_binding(mint_public, request_id),
    )


def _issue_commitment_statements(
    mint_public: MintPublicKeyPS, D: PublicKey, C: PublicKey, S: PublicKey
) -> List[LinearStatement]:
    return [
        (D, [(G_ASSET, 0)]),
        (C, [(mint_public.Y_h1, 0)]),
        (S, [(G1, 1)]),
    ]


def issue_commitment(
    mint_public: MintPublicKeyPS, h: int, s: int, request_id: bytes
) -> Tuple[PublicKey, PublicKey, LinearProof]:
    """Commit deterministically as C = h*Y_h1; prove h and s, without t.

    The duplicate tag is retained across mint key rotations. The equality
    proof ties it to C without sending h. Both points permit candidate matching.
    """
    if not 0 < s < curve_order:
        raise ValueError("invalid owner secret")
    D = asset_tag(h)
    C = mint_public.Y_h1 * h
    proof = prove_linear(
        _issue_commitment_statements(mint_public, D, C, G1 * s),
        [h, s],
        PS_COMMITTED_ISSUE_DST,
        blind_issue_binding(mint_public, request_id),
    )
    return D, C, proof


def verify_issue_commitment(
    mint_public: MintPublicKeyPS,
    D: PublicKey,
    C: PublicKey,
    S: PublicKey,
    proof: LinearProof,
    request_id: bytes,
) -> bool:
    if S.is_infinity():
        return False
    return verify_linear(
        _issue_commitment_statements(mint_public, D, C, S),
        proof,
        PS_COMMITTED_ISSUE_DST,
        blind_issue_binding(mint_public, request_id),
    )


def issue_committed(
    mint_key: MintPrivateKeyPS, C: PublicKey, S: PublicKey
) -> Tuple[PublicKey, PublicKey]:
    """After proof verification, return (k*G1, k*(x*G1 + C + y_s*S)).

    The mint chooses a fresh secret k per issuance, never a client-supplied
    or reused base. Persist both response points for exact-request recovery.
    """
    # C may be the identity for the valid hash scalar h=0 in v3.
    if S.is_infinity():
        raise ValueError("owner commitment must not be the point at infinity")
    k = _random_scalar()
    return G1 * k, _add_p1(
        _add_p1(G1 * mint_key.x.scalar, C), S * mint_key.y_s.scalar
    ) * k


def unblind_issued_v2(v_raw: PublicKey, t: int, u: PublicKey) -> PublicKey:
    """Remove t*u; the result is (x + y_h*h + y_s*s)*u."""
    if not 0 < t < curve_order or u.is_infinity():
        raise ValueError("invalid blinding scalar or issuance base")
    return _add_p1(v_raw, _neg_p1(u * t))


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
    """A randomized credential presentation that commits to h (kappa_h in
    G2) instead of revealing it."""

    u: PublicKey
    v: PublicKey
    kappa_h: PublicKey  # G2: h * Y_h2 + o * g2
    u_s: PublicKey  # s * u
    nullifier: PublicKey  # N = G_NULL^s
    proof_s: DlogEqProof
    keyset_id: str = ""

    def to_bytes(self) -> bytes:
        return (
            _keyset_id_to_bytes(self.keyset_id)
            + self.u.format()
            + self.v.format()
            + self.kappa_h.format()
            + self.u_s.format()
            + self.nullifier.format()
            + self.proof_s.to_bytes()
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PrivatePresentation":
        if len(raw) != 385:
            raise ValueError("PrivatePresentation is 385 bytes")
        return cls(
            keyset_id=_keyset_id_from_bytes(raw[:33]),
            u=_g1_from_bytes(raw[33:81]),
            v=_g1_from_bytes(raw[81:129]),
            kappa_h=_g2_from_bytes(raw[129:225]),
            u_s=_g1_from_bytes(raw[225:273]),
            nullifier=_g1_from_bytes(raw[273:321]),
            proof_s=DlogEqProof.from_bytes(raw[321:]),
        )


def present_private(
    mint_public: MintPublicKeyPS,
    cred: Credential,
    rho: Optional[int] = None,
    binding: bytes = b"",
) -> Tuple[PrivatePresentation, int]:
    """Randomize the credential into a hidden-h presentation. Returns
    (presentation, o): the fresh blinding o is needed again at re-issuance
    time (blind_transfer_commit), so the caller must keep it."""
    if not 0 < cred.h < curve_order:
        raise ValueError("h must be in Fr* for a private presentation")
    if not 0 < cred.s < curve_order:
        raise ValueError("owner secret must be in Fr*")
    rho = rho or _random_scalar()
    if not 0 < rho < curve_order:
        raise ValueError("rho must be in Fr*")
    o = _random_scalar()
    u_r = cred.u * rho
    v_rr = _add_p1(cred.v * rho, u_r * o)
    kappa_h = _add_pk(mint_public.Y_h2 * cred.h, G2_PK * o)
    u_s = u_r * cred.s
    N = G_NULL * cred.s
    proof_s = prove_dlog_eq([G_NULL, u_r], [N, u_s], cred.s, PS_PRESENT_DST, binding)
    return (
        PrivatePresentation(
            u=u_r,
            v=v_rr,
            kappa_h=kappa_h,
            u_s=u_s,
            nullifier=N,
            proof_s=proof_s,
            keyset_id=cred.keyset_id,
        ),
        o,
    )


def verify_private_presentation(
    mint_public: MintPublicKeyPS, pres: PrivatePresentation, binding: bytes = b""
) -> bool:
    for p in (
        pres.u,
        pres.v,
        pres.kappa_h,
        pres.u_s,
        pres.nullifier,
    ):
        if p.is_infinity():
            return False
    if not verify_dlog_eq(
        [G_NULL, pres.u],
        [pres.nullifier, pres.u_s],
        pres.proof_s,
        PS_PRESENT_DST,
        binding,
    ):
        return False
    miller = pyblst.miller_loop(-pres.v.point, G2)
    miller = miller * pyblst.miller_loop(pres.u.point, mint_public.X2.point)
    miller = miller * pyblst.miller_loop(pres.u.point, pres.kappa_h.point)
    miller = miller * pyblst.miller_loop(pres.u_s.point, mint_public.Y_s2.point)
    return pyblst.final_verify(miller, pyblst.BlstFP12Element())


def _commit_statements(
    mint_public: MintPublicKeyPS, kappa_h: PublicKey, B: PublicKey, u2: PublicKey
) -> List[LinearStatement]:
    return [
        (kappa_h, [(mint_public.Y_h2, 0), (G2_PK, 1)]),
        (B, [(u2, 0), (G1, 2)]),
    ]


def blind_transfer_commit(
    mint_public: MintPublicKeyPS,
    h: int,
    o: int,
    kappa_h: PublicKey,
    u2: PublicKey,
    binding: bytes = b"",
) -> Tuple[PublicKey, int, LinearProof]:
    """Owner side of blind re-issuance: B = h * u2 + t * g1 plus one
    multi-witness proof (pi_eq) that the same h opens both kappa_h and B.
    Returns (B, t, proof); the owner keeps t to unblind the issued
    credential (unblind_issued)."""
    if u2.is_infinity():
        raise ValueError("u2 must not be the point at infinity")
    if not 0 < h < curve_order:
        raise ValueError("h must be in Fr*")
    if not 0 < o < curve_order:
        raise ValueError("o must be in Fr*")
    t = _random_scalar()
    B = _add_p1(u2 * h, G1 * t)
    proof = prove_linear(
        _commit_statements(mint_public, kappa_h, B, u2),
        [h, o, t],
        PS_COMMIT_DST,
        binding,
    )
    return B, t, proof


def verify_blind_transfer(
    mint_public: MintPublicKeyPS,
    pres: PrivatePresentation,
    B: PublicKey,
    proof: LinearProof,
    u2: PublicKey,
    binding: bytes = b"",
) -> bool:
    if u2.is_infinity() or B.is_infinity():
        return False
    if not verify_private_presentation(mint_public, pres, binding=binding):
        return False
    return verify_linear(
        _commit_statements(mint_public, pres.kappa_h, B, u2),
        proof,
        PS_COMMIT_DST,
        binding,
    )


def issue_blind(
    mint_key: MintPrivateKeyPS, k2: int, u2: PublicKey, B: PublicKey, S_new: PublicKey
) -> PublicKey:
    """v2_raw = x*u2 + y_h*B + (k2*y_s)*S_new, computed without learning h.
    B commits to h * u2, so y_h * B contributes y_h * h * u2 (the credential
    term) plus t * y_h * g1, which the owner strips with unblind_issued."""
    if not 0 < k2 < curve_order:
        raise ValueError("k2 must be in Fr*")
    for p in (u2, B, S_new):
        if p.is_infinity():
            raise ValueError("points must not be the point at infinity")
    return _add_p1(
        _add_p1(u2 * mint_key.x.scalar, B * mint_key.y_h.scalar),
        S_new * ((k2 * mint_key.y_s.scalar) % curve_order),
    )


def unblind_issued(
    v2_raw: PublicKey, t: int, mint_public: MintPublicKeyPS
) -> PublicKey:
    """Owner side: strip the blinding term, v2 = v2_raw - t * Y_h1."""
    if not 0 < t < curve_order:
        raise ValueError("t must be in Fr*")
    return _add_p1(v2_raw, _neg_p1(mint_public.Y_h1 * t))


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
    mint_public: MintPublicKeyPS,
    presentations: List[Presentation],
    binding: bytes = b"",
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
        for p in (pres.u, pres.v, pres.u_s, pres.nullifier):
            if p.is_infinity():
                return False
        if not verify_dlog_eq(
            [G_NULL, pres.u],
            [pres.nullifier, pres.u_s],
            pres.proof,
            PS_PRESENT_DST,
            binding,
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

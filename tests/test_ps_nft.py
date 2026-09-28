import pyblst
import pytest

from cashu.core.crypto.bls import PublicKey, curve_order
from cashu.core.crypto.ps import (
    G1,
    G_NULL,
    Credential,
    MintPrivateKeyPS,
    Presentation,
    hash_asset,
    issue,
    present,
    prove_dlog_eq,
    prove_owner_secret,
    verify_dlog_eq,
    verify_owner_secret,
    verify_presentation,
)


class NFTMint:
    """Minimal experimental mint state for the NFT flow: one credential per
    asset hash, a nullifier set for spent credentials, and an ownership
    registry mapping asset hash -> current owner commitment."""

    def __init__(self):
        self.key = MintPrivateKeyPS()
        self.issued: set[int] = set()
        self.nullifiers: set[bytes] = set()
        self.owners: dict[int, bytes] = {}

    @property
    def public_key(self):
        return self.key.public_key

    def mint_nft(self, asset: bytes, S, pok) -> Credential:
        h = hash_asset(asset)
        if h in self.issued:
            raise ValueError("asset already minted")
        if not verify_owner_secret(S, pok):
            raise ValueError("invalid owner secret proof")
        u, v = issue(self.key, h, S)
        self.issued.add(h)
        self.owners[h] = S.format()
        return Credential(u=u, v=v, h=h, s=0)  # s filled in by the owner

    def transfer(self, pres: Presentation, S_new, pok_new, asset: bytes) -> Credential:
        if hash_asset(asset) != pres.h:
            raise ValueError("asset does not match presentation")
        if pres.h not in self.issued:
            raise ValueError("unknown asset")
        if pres.nullifier.format() in self.nullifiers:
            raise ValueError("credential already spent")
        if self.owners[pres.h] != pres.owner_commitment.format():
            raise ValueError("not the registered owner")
        if not verify_presentation(self.public_key, pres):
            raise ValueError("invalid presentation")
        if not verify_owner_secret(S_new, pok_new):
            raise ValueError("invalid new owner secret proof")
        self.nullifiers.add(pres.nullifier.format())
        u, v = issue(self.key, pres.h, S_new)
        self.owners[pres.h] = S_new.format()
        return Credential(u=u, v=v, h=pres.h, s=0)


def make_credential(mint: NFTMint, asset: bytes, s: int) -> Credential:
    S, pok = prove_owner_secret(s)
    cred = mint.mint_nft(asset, S, pok)
    cred.s = s
    return cred


def test_issue_and_present():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    assert verify_presentation(mint.public_key, pres)


def test_presentations_are_unlinkable():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres1 = present(cred)
    pres2 = present(cred)
    assert pres1.u.format() != pres2.u.format()
    assert pres1.v.format() != pres2.v.format()
    assert pres1.u_s.format() != pres2.u_s.format()
    assert verify_presentation(mint.public_key, pres1)
    assert verify_presentation(mint.public_key, pres2)


def test_double_mint_rejected():
    mint = NFTMint()
    make_credential(mint, b"jpeg bytes", s=12345)
    with pytest.raises(ValueError, match="already minted"):
        make_credential(mint, b"jpeg bytes", s=67890)


def test_wrong_asset_hash_fails_pairing():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    pres.h = hash_asset(b"some other asset")
    assert not verify_presentation(mint.public_key, pres)


def test_rescaled_h_forgery_fails():
    # the attack on the naive C = a*h*B' construction: rescale a valid
    # credential from h1 to h2. With y_h kept out of G1 this cannot verify.
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    h2 = hash_asset(b"some other asset")
    h1_inv = pow(cred.h, -1, curve_order)
    pres.u = pres.u * ((h2 * h1_inv) % curve_order)
    pres.v = pres.v * ((h2 * h1_inv) % curve_order)
    pres.u_s = pres.u_s * ((h2 * h1_inv) % curve_order)
    pres.h = h2
    assert not verify_presentation(mint.public_key, pres)


def test_foreign_credential_fails():
    mint_a = NFTMint()
    mint_b = NFTMint()
    cred = make_credential(mint_a, b"jpeg bytes", s=12345)
    pres = present(cred)
    assert not verify_presentation(mint_b.public_key, pres)


def test_swapped_owner_commitment_fails():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    pres.owner_commitment = G1 * 999
    assert not verify_presentation(mint.public_key, pres)


def test_swapped_nullifier_fails():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    pres.nullifier = G_NULL * 999
    assert not verify_presentation(mint.public_key, pres)


def test_swapped_u_s_fails():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    pres.u_s = pres.u * 999
    assert not verify_presentation(mint.public_key, pres)


def test_unminted_asset_fails():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    # a credential self-issued under a different mint key for another asset
    other = NFTMint()
    cred2 = make_credential(other, b"unminted asset", s=12345)
    pres = present(cred2)
    pres.h = cred.h
    assert not verify_presentation(mint.public_key, pres)


def test_transfer_flow():
    mint = NFTMint()
    asset = b"jpeg bytes"
    cred_alice = make_credential(mint, asset, s=11111)

    # alice presents her credential to the mint for transfer to bob
    pres = present(cred_alice)
    S_bob, pok_bob = prove_owner_secret(22222)
    cred_bob = mint.transfer(pres, S_bob, pok_bob, asset)
    cred_bob.s = 22222

    # bob's new credential verifies and the registry points to him
    pres_bob = present(cred_bob)
    assert verify_presentation(mint.public_key, pres_bob)
    assert mint.owners[cred_bob.h] == S_bob.format()

    # alice's old credential is dead
    with pytest.raises(ValueError, match="already spent"):
        mint.transfer(present(cred_alice), *prove_owner_secret(33333), asset)


def test_transfer_rejects_non_owner():
    mint = NFTMint()
    asset = b"jpeg bytes"
    cred_alice = make_credential(mint, asset, s=11111)
    # mallory presents her own valid credential for a different asset and
    # tries to move alice's by lying about h
    cred_mallory = make_credential(mint, b"mallory asset", s=44444)
    pres = present(cred_mallory)
    pres.h = cred_alice.h
    with pytest.raises(
        ValueError, match="invalid presentation|not the registered owner"
    ):
        mint.transfer(pres, *prove_owner_secret(44444), asset)


def test_owner_secret_pok_required():
    mint = NFTMint()
    S = G1 * 12345
    bad_proof = prove_dlog_eq([G1], [S], 12345, b"wrong domain")
    assert not verify_owner_secret(S, bad_proof)
    with pytest.raises(ValueError, match="invalid owner secret proof"):
        mint.mint_nft(b"jpeg bytes", S, bad_proof)


def test_dlog_eq_wrong_secret_fails():
    s = 12345
    S = G1 * s
    proof = prove_dlog_eq([G1], [S], s + 1, b"dst")
    assert not verify_dlog_eq([G1], [S], proof, b"dst")


def test_infinity_rejected():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    pres = present(cred)
    pres.u = PublicKey(point=pyblst.BlstP1Element(), group="G1")
    assert not verify_presentation(mint.public_key, pres)


def test_zero_and_out_of_range_scalars_rejected():
    mint = NFTMint()
    cred = make_credential(mint, b"jpeg bytes", s=12345)
    cred.h = curve_order
    with pytest.raises(ValueError):
        present(cred)
    S, _ = prove_owner_secret(12345)
    with pytest.raises(ValueError):
        issue(mint.key, curve_order, S)

import pytest

from cashu.core.crypto.ps import (
    Credential,
    DlogEqProof,
    MintPrivateKeyPS,
    MintPublicKeyPS,
    Presentation,
    hash_asset,
    hash_asset_parts,
    issue,
    present,
    prove_owner_secret,
    verify_presentation,
    verify_presentation_keysets,
)


def make_cred(key: MintPrivateKeyPS, asset: bytes, s: int) -> Credential:
    S, _ = prove_owner_secret(s)
    u, v = issue(key, hash_asset(asset), S)
    return Credential(
        u=u, v=v, h=hash_asset(asset), s=s, keyset_id=key.public_key.keyset_id
    )


def test_proof_roundtrip():
    _, pok = prove_owner_secret(12345)
    assert DlogEqProof.from_bytes(pok.to_bytes()) == pok
    with pytest.raises(ValueError):
        DlogEqProof.from_bytes(b"\x00" * 63)


def test_credential_roundtrip():
    key = MintPrivateKeyPS()
    cred = make_cred(key, b"asset", 42)
    assert Credential.from_bytes(cred.to_bytes()) == cred
    with pytest.raises(ValueError):
        Credential.from_bytes(cred.to_bytes()[:-1])


def test_presentation_roundtrip_and_tamper():
    key = MintPrivateKeyPS()
    cred = make_cred(key, b"asset", 42)
    pres = present(cred)
    assert len(pres.to_bytes()) == 321
    restored = Presentation.from_bytes(pres.to_bytes())
    assert restored == pres
    assert verify_presentation(key.public_key, restored)
    tampered = bytearray(pres.to_bytes())
    tampered[100] ^= 1
    with pytest.raises(ValueError):
        Presentation.from_bytes(bytes(tampered))


def test_from_seed_is_deterministic():
    seed = b"0123456789abcdef"
    assert (
        MintPrivateKeyPS.from_seed(seed).public_key.to_bytes()
        == MintPrivateKeyPS.from_seed(seed).public_key.to_bytes()
    )
    assert (
        MintPrivateKeyPS.from_seed(seed).public_key.to_bytes()
        != MintPrivateKeyPS.from_seed(b"fedcba9876543210").public_key.to_bytes()
    )
    with pytest.raises(ValueError):
        MintPrivateKeyPS.from_seed(b"short")


def test_public_key_roundtrip_and_keyset_id():
    key = MintPrivateKeyPS.from_seed(b"0123456789abcdef")
    pub = key.public_key
    restored = MintPublicKeyPS.from_bytes(pub.to_bytes())
    assert restored.to_bytes() == pub.to_bytes()
    assert restored.keyset_id == pub.keyset_id
    assert len(pub.keyset_id) == 66 and pub.keyset_id.startswith("03")
    with pytest.raises(ValueError):
        MintPublicKeyPS.from_bytes(pub.to_bytes()[:-1])


def test_keyset_scoped_verification():
    key_old = MintPrivateKeyPS.from_seed(b"0123456789abcdef")
    key_new = MintPrivateKeyPS.from_seed(b"fedcba9876543210")
    cred = make_cred(key_old, b"asset", 42)
    pres = present(cred)
    keysets = {key_old.public_key.keyset_id: key_old.public_key}
    assert verify_presentation_keysets(keysets, pres)
    # after rotation the old keyset still verifies, the new one is not named
    rotated = {
        key_old.public_key.keyset_id: key_old.public_key,
        key_new.public_key.keyset_id: key_new.public_key,
    }
    assert verify_presentation_keysets(rotated, pres)
    pres_new = present(make_cred(key_new, b"asset", 43))
    assert verify_presentation_keysets(rotated, pres_new)
    assert not verify_presentation_keysets(keysets, pres_new)


def test_hash_asset_parts_matches_chunked_semantics():
    whole = hash_asset_parts([b"hello world, this is one asset"])
    chunked = hash_asset_parts([b"hello ", b"world, this is one asset"])
    assert whole != chunked  # chunk boundaries are part of the encoding
    assert hash_asset_parts([b"hello world, this is one asset"]) == whole
    assert hash_asset(b"x") != hash_asset_parts([b"x"])  # distinct encodings

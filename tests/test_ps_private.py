import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.bls import PublicKey
from cashu.core.crypto.ps import (
    G1,
    Credential,
    MintPrivateKeyPS,
    PrivatePresentation,
    blind_base_for_nullifier,
    blind_transfer_commit,
    hash_asset,
    issue,
    present,
    present_private,
    prove_owner_secret,
    unblind_issued,
    verify_blind_transfer,
    verify_presentation,
    verify_private_presentation,
)
from cashu.core.db import Database
from cashu.nft.api import NFT_API_PREFIX, create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.wallet import NFTClient, NFTWallet


@pytest.fixture(scope="function")
def service(tmp_path):
    ledger = PSLedger(
        Database("test_nft_private", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    import asyncio

    asyncio.run(ledger.migrate())
    return NFTClient(TestClient(create_app(ledger))), ledger


def test_private_presentation_roundtrip(service, tmp_path):
    client, ledger = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    cred = client.mint(wallet, b"jpeg")
    pres, _o = present_private(client.keyset, cred)
    assert len(pres.to_bytes()) == 385
    assert verify_private_presentation(client.keyset, pres)
    restored = PrivatePresentation.from_bytes(pres.to_bytes())
    assert restored == pres
    assert verify_private_presentation(client.keyset, restored)
    with pytest.raises(ValueError):
        PrivatePresentation.from_bytes(pres.to_bytes()[:-1])


def test_old_format_private_presentation_rejected(service, tmp_path):
    # the pre-commitment (U_h/proof_h) wire format was 401 bytes
    with pytest.raises(ValueError, match="385"):
        PrivatePresentation.from_bytes(b"\x00" * 401)


def test_private_transfer_hides_h(service, tmp_path):
    client, ledger = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    bob = NFTWallet(str(tmp_path / "bob.sqlite3"), seed=b"bob seed 0000001")
    asset = b"jpeg"
    h = hash_asset(asset)
    client.mint(alice, asset)
    alice_nullifier = alice.present(h).nullifier.format()

    ticket = bob.prepare_receive()
    u2, v2 = client.transfer_private(
        alice, h, ticket.commitment.format(), ticket.proof.to_bytes()
    )
    cred_bob = bob.store_credential(ticket, u2, v2, h, client.keyset_id)

    # bob's blindly-issued credential verifies both publicly and privately
    assert verify_presentation(client.keyset, present(cred_bob))
    pres_bob, _ = present_private(client.keyset, cred_bob)
    assert verify_private_presentation(client.keyset, pres_bob)

    # ownership moved to bob, observable via the nullifier spent set:
    # alice's generation is spent, bob's is the only unspent one
    assert client.check_state(alice_nullifier) == "SPENT"
    assert client.check_state(bob.present(h).nullifier.format()) == "UNSPENT"
    assert client.asset_status(h) == "active"

    # alice's credential is dead
    with pytest.raises(RuntimeError, match="409"):
        client.transfer_private(
            alice, h, ticket.commitment.format(), ticket.proof.to_bytes()
        )


def test_private_presentation_is_not_enumerable(service, tmp_path):
    """Regression test for the enumeration attack: the old U_h = h*u' let a
    mint with the list of minted h_i test U_h == h_i*u' directly. kappa_h is
    a Pedersen commitment, so no such test exists."""
    client, ledger = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    cred = client.mint(wallet, b"jpeg")
    ks = client.keyset

    # (1) two presentations of the SAME credential carry different kappa_h
    pres1, o1 = present_private(ks, cred)
    pres2, o2 = present_private(ks, cred)
    assert pres1.kappa_h != pres2.kappa_h
    assert o1 != o2

    # (2) for ANY candidate h_i, kappa_h - h_i*Y_h2 is a consistent
    # blinding opening (o_i = o + (h - h_i)*y_h would need y_h, which the
    # mint cannot extract from the commitment): both the right and a wrong
    # candidate yield ordinary-looking, non-infinity, unequal G2 points.
    # Enumeration is information-theoretically impossible, not just hard.
    h_wrong = hash_asset(b"some other asset")
    diff_right = PublicKey(
        point=pres1.kappa_h.point + (-(ks.Y_h2 * cred.h).point), group="G2"
    )
    diff_wrong = PublicKey(
        point=pres1.kappa_h.point + (-(ks.Y_h2 * h_wrong).point), group="G2"
    )
    assert pres1.kappa_h != ks.Y_h2 * cred.h  # blinded, never the bare h*Y_h2
    assert not diff_right.is_infinity()  # = o * g2
    assert not diff_wrong.is_infinity()
    assert diff_right != diff_wrong

    # (3) a B committing to the WRONG h cannot satisfy pi_eq against
    # kappa_h: the prover would need o' = o + (h - h')*y_h
    u2 = G1 * 7
    B_bad, _, proof_bad = blind_transfer_commit(
        ks, h_wrong, o1, pres1.kappa_h, u2
    )
    assert not verify_blind_transfer(ks, pres1, B_bad, proof_bad, u2)
    # ... while the honest commitment verifies
    B, t, proof = blind_transfer_commit(ks, cred.h, o1, pres1.kappa_h, u2)
    assert verify_blind_transfer(ks, pres1, B, proof, u2)

    # (4) full blind re-issuance round through the service: v2_raw minus
    # t * Y_h1 is a normal, fully verifiable credential under the new secret
    S_new, pok_new = prove_owner_secret(424242)
    pres4, o4 = present_private(ks, cred, binding=S_new.format())
    begin = client.http.post(
        f"{NFT_API_PREFIX}/transfer/private/begin",
        json={"nullifier": pres4.nullifier.format().hex()},
    ).json()
    u2_mint = PublicKey(compressed=bytes.fromhex(begin["u"]), group="G1")
    B2, t2, proof2 = blind_transfer_commit(
        ks, cred.h, o4, pres4.kappa_h, u2_mint, binding=S_new.format()
    )
    resp = client.http.post(
        f"{NFT_API_PREFIX}/transfer/private",
        json={
            "presentation": pres4.to_bytes().hex(),
            "b": B2.format().hex(),
            "proof": proof2.to_bytes().hex(),
            "new_owner_commitment": S_new.format().hex(),
            "new_proof": pok_new.to_bytes().hex(),
        },
    )
    assert resp.status_code == 200, resp.text
    v2_raw = PublicKey(compressed=bytes.fromhex(resp.json()["v"]), group="G1")
    v2 = unblind_issued(v2_raw, t2, ks)
    cred_new = Credential(
        u=u2_mint, v=v2, h=cred.h, s=424242, keyset_id=client.keyset_id
    )
    assert verify_presentation(ks, present(cred_new))
    # and the raw (still blinded) v2_raw does NOT verify on its own
    cred_blind = Credential(
        u=u2_mint, v=v2_raw, h=cred.h, s=424242, keyset_id=client.keyset_id
    )
    assert not verify_presentation(ks, present(cred_blind))


@pytest.mark.asyncio
async def test_private_transfer_unknown_owner(tmp_path):
    ledger = PSLedger(
        Database("test_nft_private2", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    await ledger.migrate()
    # a self-made credential that was never minted by this ledger
    rogue = MintPrivateKeyPS.from_seed(b"rogue key 000000")
    h = hash_asset(b"rogue asset")
    S, _ = prove_owner_secret(1)
    u, v = issue(rogue, h, S)
    cred = Credential(u=u, v=v, h=h, s=1, keyset_id=rogue.public_key.keyset_id)
    pres, o = present_private(rogue.public_key, cred)
    _, u2 = blind_base_for_nullifier(ledger.mint_key, pres.nullifier.format())
    B, _, proof = blind_transfer_commit(rogue.public_key, cred.h, o, pres.kappa_h, u2)
    S_new, pok_new = prove_owner_secret(2)
    with pytest.raises(Exception) as exc:
        await ledger.transfer_private(pres, B, proof, S_new, pok_new)
    assert exc.value is not None


def test_private_and_public_transfers_compose(service, tmp_path):
    client, _ = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    h = hash_asset(b"jpeg")
    client.mint(wallet, b"jpeg")
    # public transfer, then private, then public again
    client.transfer_to_self(wallet, h)
    client.transfer_private_to_self(wallet, h)
    cred = client.transfer_to_self(wallet, h)
    assert verify_presentation(client.keyset, present(cred))
    # three transfers happened: the first two nullifiers are spent, the
    # current credential's is not, and the asset is still active
    assert client.check_state(present(cred).nullifier.format()) == "UNSPENT"
    assert client.asset_status(h) == "active"

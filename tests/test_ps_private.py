import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    Credential,
    MintPrivateKeyPS,
    PrivatePresentation,
    blind_base_for_nullifier,
    hash_asset,
    present,
    present_private,
    prove_owner_secret,
    verify_presentation,
    verify_private_presentation,
)
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import AlreadySpentError, PSLedger, UnknownAssetError
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
    pres = present_private(cred)
    assert verify_private_presentation(client.keyset, pres)
    restored = PrivatePresentation.from_bytes(pres.to_bytes())
    assert restored == pres
    assert verify_private_presentation(client.keyset, restored)
    with pytest.raises(ValueError):
        PrivatePresentation.from_bytes(pres.to_bytes()[:-1])


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
    assert verify_private_presentation(client.keyset, present_private(cred_bob))

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
    from cashu.core.crypto.ps import issue

    u, v = issue(rogue, h, S)
    cred = Credential(u=u, v=v, h=h, s=1, keyset_id=rogue.public_key.keyset_id)
    pres = present_private(cred)
    k2, u2 = blind_base_for_nullifier(ledger.mint_key, pres.nullifier.format())
    from cashu.core.crypto.ps import blind_transfer_witness

    w_h, proof = blind_transfer_witness(cred, pres.u, u2)
    S_new, pok_new = prove_owner_secret(2)
    with pytest.raises((UnknownAssetError, AlreadySpentError, Exception)) as exc:
        await ledger.transfer_private(pres, w_h, proof, S_new, pok_new)
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

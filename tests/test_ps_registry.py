import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    G1,
    MintPrivateKeyPS,
    hash_asset,
)
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.registry import sign_registry_entry, verify_registry_entry
from cashu.nft.wallet import NFTClient, NFTWallet


@pytest.fixture(scope="function")
def service(tmp_path):
    ledger = PSLedger(
        Database("test_nft_registry", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    import asyncio

    asyncio.run(ledger.migrate())
    return NFTClient(TestClient(create_app(ledger)))


def test_entry_signature_unit():
    key = MintPrivateKeyPS.from_seed(b"test seed 012345")
    owner = (G1 * 42).format()
    sig = sign_registry_entry(key, 7, owner, 0)
    assert verify_registry_entry(key.public_key, 7, owner, 0, sig.format())
    # wrong epoch, wrong owner, wrong h all fail
    assert not verify_registry_entry(key.public_key, 7, owner, 1, sig.format())
    assert not verify_registry_entry(
        key.public_key, 7, (G1 * 43).format(), 0, sig.format()
    )
    assert not verify_registry_entry(key.public_key, 8, owner, 0, sig.format())


def test_registry_flow_offline_verification(service, tmp_path):
    client = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    h = hash_asset(b"jpeg")
    client.mint(wallet, b"jpeg")

    pres = wallet.present(h)
    entry = client.registry_entry(h)
    assert entry["epoch"] == 0
    assert client.verify_registered_owner(pres, entry)

    # transfer to self bumps the epoch and re-signs
    cred2 = client.transfer_to_self(wallet, h)
    entry2 = client.registry_entry(h)
    assert entry2["epoch"] == 1
    assert client.verify_registered_owner(wallet.present(h), entry2)

    # the old owner commitment no longer matches the current entry
    assert not client.verify_registered_owner(pres, entry2)
    # and a stale entry is cryptographically valid but superseded
    assert verify_registry_entry(
        client.keyset,
        pres.h,
        bytes.fromhex(entry["owner"]),
        entry["epoch"],
        bytes.fromhex(entry["signature"]),
    )
    assert cred2.h == h


def test_registry_entry_for_unknown_asset(service):
    client = service
    with pytest.raises(ValueError, match="unknown or burned"):
        client.registry_entry(hash_asset(b"never minted"))


def test_burned_asset_leaves_registry(service, tmp_path):
    client = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    h = hash_asset(b"jpeg")
    client.mint(wallet, b"jpeg")
    client.burn(wallet, h)
    with pytest.raises(ValueError, match="unknown or burned"):
        client.registry_entry(h)

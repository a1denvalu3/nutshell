import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    MintPrivateKeyPS,
    hash_asset,
)
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.wallet import NFTClient, NFTWallet


@pytest.fixture(scope="function")
def service(tmp_path):
    ledger = PSLedger(
        Database("test_nft_checkstate", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    import asyncio

    asyncio.run(ledger.migrate())
    return NFTClient(TestClient(create_app(ledger)))


def test_fresh_credential_unspent_and_active(service, tmp_path):
    client = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    h = hash_asset(b"jpeg")
    client.mint(wallet, b"jpeg")

    pres = wallet.present(h)
    assert client.check_state(pres.nullifier.format()) == "UNSPENT"
    assert client.asset_status(h) == "active"


def test_transfer_spends_old_nullifier(service, tmp_path):
    client = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    h = hash_asset(b"jpeg")
    client.mint(wallet, b"jpeg")
    old_nullifier = wallet.present(h).nullifier.format()

    cred2 = client.transfer_to_self(wallet, h)
    assert cred2.h == h

    # the old generation is spent, the new holder's nullifier is unspent
    assert client.check_state(old_nullifier) == "SPENT"
    new_nullifier = wallet.present(h).nullifier.format()
    assert client.check_state(new_nullifier) == "UNSPENT"
    assert client.asset_status(h) == "active"


def test_burn_marks_nullifier_spent_and_asset_burned(service, tmp_path):
    client = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    h = hash_asset(b"jpeg")
    client.mint(wallet, b"jpeg")
    nullifier = wallet.present(h).nullifier.format()

    client.burn(wallet, h)
    assert client.check_state(nullifier) == "SPENT"
    assert client.asset_status(h) == "burned"


def test_unknown_asset_and_nullifier(service):
    client = service
    assert client.asset_status(hash_asset(b"never minted")) == "unknown"
    assert client.check_state(b"\x0b" * 48) == "UNSPENT"

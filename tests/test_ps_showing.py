"""Purpose-bound showings: a published presentation verifies offline but
cannot be replayed into a spend (replay-theft regression tests)."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    MintPrivateKeyPS,
    Presentation,
    hash_asset,
    present,
    present_showing,
    prove_owner_secret,
    verify_showing,
)
from cashu.core.db import Database
from cashu.nft.api import NFT_API_PREFIX, create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.wallet import NFTClient, NFTWallet


@pytest.fixture(scope="function")
def service(tmp_path):
    ledger = PSLedger(
        Database("test_nft_showing", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    asyncio.run(ledger.migrate())
    return NFTClient(TestClient(create_app(ledger)))


def transfer_attempt(client: NFTClient, presentation: str, s_new: int):
    S_new, pok_new = prove_owner_secret(s_new)
    return client.http.post(
        f"{NFT_API_PREFIX}/transfer",
        json={
            "presentation": presentation,
            "new_owner_commitment": S_new.format().hex(),
            "new_proof": pok_new.to_bytes().hex(),
        },
    )


def burn_attempt(client: NFTClient, presentation: str):
    return client.http.post(
        f"{NFT_API_PREFIX}/burn", json={"presentation": presentation}
    )


def test_published_showing_cannot_be_stolen(service, tmp_path):
    client = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"a" * 32)
    mallory = NFTWallet(str(tmp_path / "mallory.sqlite3"), seed=b"m" * 32)
    cred = client.mint(alice, b"nft bytes")
    context = b"buyer-1234"

    # alice PUBLISHES a showing; mallory copies the blob
    showing = present_showing(cred, context).to_bytes().hex()
    pres = Presentation.from_bytes(bytes.fromhex(showing))
    assert verify_showing(client.keyset, pres, context)
    assert not verify_showing(client.keyset, pres, b"other context")

    # mallory replays it into /transfer with her own S_new -> rejected
    assert transfer_attempt(client, showing, 999).status_code == 403
    # ... and into /burn -> rejected
    assert burn_attempt(client, showing).status_code == 403
    # the asset is untouched
    assert client.check_state(pres.nullifier.format()) == "UNSPENT"
    assert client.asset_status(cred.h) == "active"
    assert mallory.assets() == []


def test_default_bound_presentation_cannot_spend(service, tmp_path):
    client = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"a" * 32)
    cred = client.mint(alice, b"nft bytes")
    blob = present(cred).to_bytes().hex()  # binding b""
    assert transfer_attempt(client, blob, 999).status_code == 403
    assert burn_attempt(client, blob).status_code == 403


def test_transfer_presentation_bound_to_exact_new_owner(service, tmp_path):
    client = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"a" * 32)
    cred = client.mint(alice, b"nft bytes")
    S_a, _ = prove_owner_secret(111)
    blob = present(cred, binding=S_a.format()).to_bytes().hex()
    # submitted with S_new_B -> binding mismatch
    assert transfer_attempt(client, blob, 222).status_code == 403
    # submitted with the exact S_new it was bound to -> accepted
    assert transfer_attempt(client, blob, 111).status_code == 200


def test_showing_blob_inspection_and_burn_flow(service, tmp_path):
    client = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"a" * 32)
    cred = client.mint(alice, b"nft bytes")
    h = cred.h

    blob = client.show(alice, h, b"sale-context")
    assert blob["context"] == b"sale-context".hex()

    # a third party inspects the blob: valid, unspent, active
    result = client.verify_showing_blob(blob)
    assert result == {
        "valid": True,
        "spent": False,
        "asset_status": "active",
        "asset_hash": h.to_bytes(32, "big").hex(),
    }

    # a tampered context fails the offline check
    tampered = dict(blob, context=b"evil-context".hex())
    assert client.verify_showing_blob(tampered)["valid"] is False

    # the showing cannot burn; the wallet burn flow works
    assert burn_attempt(client, blob["presentation"]).status_code == 403
    client.burn(alice, h)
    result = client.verify_showing_blob(blob)
    assert result["valid"] is True  # signature and context still check out
    assert result["spent"] is True
    assert result["asset_status"] == "burned"


def test_showing_goes_stale_after_transfer(service, tmp_path):
    client = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"a" * 32)
    client.mint(alice, b"nft bytes")
    h = hash_asset(b"nft bytes")
    blob = client.show(alice, h)  # random context
    assert client.verify_showing_blob(blob)["spent"] is False

    client.transfer_to_self(alice, h)
    # the old showing's nullifier is spent: the publisher no longer holds
    result = client.verify_showing_blob(blob)
    assert result["valid"] is True
    assert result["spent"] is True
    assert result["asset_status"] == "active"

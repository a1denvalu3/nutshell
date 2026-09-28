"""End-to-end integration: paid minting, public and private transfers
between independent wallets, offline third-party verification, batch
verification, signed registry entries, and burn — all through the HTTP
API with two service restarts (persistence) in between."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    MintPrivateKeyPS,
    batch_verify_presentations,
    hash_asset,
)
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.quotes import DevQuoteBackend
from cashu.nft.wallet import NFTClient, NFTWallet

MINT_SEED = b"mint seed for integ"


def paid_mint(client, wallet, asset, backend, description=""):
    quote = client.mint_quote(asset)
    client.dev_pay_quote(quote["quote"], backend.issue_dev_ticket(quote["quote"]))
    return client.mint(wallet, asset, quote=quote["quote"], description=description)


def make_service(path):
    verifier = DevQuoteBackend(b"operator secret!!")
    ledger = PSLedger(
        Database("test_nft_integ", str(path)),
        MintPrivateKeyPS.from_seed(MINT_SEED),
        quote_backend=verifier,
    )
    asyncio.run(ledger.migrate())
    return NFTClient(TestClient(create_app(ledger))), verifier


def test_full_nft_lifecycle(tmp_path):
    client, verifier = make_service(tmp_path / "mint")
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    bob = NFTWallet(str(tmp_path / "bob.sqlite3"), seed=b"bob seed 0000001")

    # --- paid minting of two assets by alice
    art1, art2 = b"first jpeg", b"second jpeg"
    h1, h2 = hash_asset(art1), hash_asset(art2)
    cred1 = paid_mint(client, alice, art1, verifier, description="first")
    cred2 = paid_mint(client, alice, art2, verifier)
    assert cred1.h == h1 and cred2.h == h2

    # --- service restart: everything survives
    client, verifier = make_service(tmp_path / "mint")
    assert client.registry_entry(h1)["epoch"] == 0

    # --- public transfer: art1 alice -> bob
    ticket = bob.prepare_receive()
    u, v = client.transfer(
        alice, h1, ticket.commitment.format(), ticket.proof.to_bytes()
    )
    cred1_bob = bob.store_credential(ticket, u, v, h1, client.keyset_id, "first")

    # --- private transfer: art2 alice -> bob (h never sent to the mint)
    ticket2 = bob.prepare_receive()
    u2, v2 = client.transfer_private(
        alice, h2, ticket2.commitment.format(), ticket2.proof.to_bytes()
    )
    bob.store_credential(ticket2, u2, v2, h2, client.keyset_id, "second")

    # --- a third party with only /v1/info verifies everything offline
    third_party, _ = make_service(tmp_path / "mint")
    pres1, pres2 = bob.present(h1), bob.present(h2)
    assert third_party.verify(pres1) and third_party.verify(pres2)
    assert batch_verify_presentations(third_party.keyset, [pres1, pres2])
    entry1 = third_party.registry_entry(h1)
    assert third_party.verify_registered_owner(pres1, entry1)
    assert entry1["epoch"] == 1

    # --- spent credentials are dead even after another restart
    with pytest.raises(RuntimeError, match="409"):
        client.transfer(alice, h1, ticket.commitment.format(), ticket.proof.to_bytes())

    # --- burn art1; art2 keeps working
    client.burn(bob, cred1_bob.h)
    with pytest.raises(ValueError, match="unknown or burned"):
        client.registry_entry(h1)
    assert third_party.verify(bob.present(h2))
    assert len(bob.assets()) == 1
    assert bob.assets()[0].description == "second"

import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import MintPrivateKeyPS, hash_asset, present
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.quotes import DevQuoteBackend
from cashu.nft.wallet import NFTClient, NFTWallet


@pytest.fixture(scope="function")
def service(tmp_path):
    verifier = DevQuoteBackend(b"operator secret!!")
    ledger = PSLedger(
        Database("test_nft_wallet", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
        quote_backend=verifier,
    )
    import asyncio

    asyncio.run(ledger.migrate())
    return NFTClient(TestClient(create_app(ledger))), verifier


def paid_mint(client, wallet, asset, description=""):
    quote = client.mint_quote(asset)
    client.dev_pay_quote(
        quote["quote"],
        DevQuoteBackend(b"operator secret!!").issue_dev_ticket(quote["quote"]),
    )
    return client.mint(wallet, asset, quote=quote["quote"], description=description)


def test_mint_with_wallet(service, tmp_path):
    client, verifier = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    asset = b"jpeg bytes"
    cred = paid_mint(client, wallet, asset, description="my nft")
    assert client.verify(wallet.present(cred.h))
    assert [(a.h, a.description) for a in wallet.assets()] == [(cred.h, "my nft")]


def test_wallet_restore_from_seed(service, tmp_path):
    client, verifier = service
    path = str(tmp_path / "alice.sqlite3")
    wallet = NFTWallet(path, seed=b"alice seed 00001")
    asset = b"jpeg bytes"
    cred = paid_mint(client, wallet, asset)

    restored = NFTWallet(str(tmp_path / "restored.sqlite3"), seed=b"alice seed 00001")
    ticket = restored.prepare_receive()  # index 0 == alice's first secret
    from cashu.core.crypto.ps import G1

    assert ticket.commitment == G1 * cred.s


def test_wallet_rejects_second_init_with_seed(service, tmp_path):
    path = str(tmp_path / "alice.sqlite3")
    NFTWallet(path, seed=b"alice seed 00001")
    with pytest.raises(ValueError, match="wallet exists"):
        NFTWallet(path, seed=b"alice seed 00001")
    NFTWallet(path)  # opening without seed is fine


def test_transfer_between_wallets(service, tmp_path):
    client, verifier = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    bob = NFTWallet(str(tmp_path / "bob.sqlite3"), seed=b"bob seed 0000001")
    asset = b"jpeg bytes"
    h = hash_asset(asset)
    paid_mint(client, alice, asset)

    ticket = bob.prepare_receive()
    u, v = client.transfer(
        alice, h, ticket.commitment.format(), ticket.proof.to_bytes()
    )
    cred_bob = bob.store_credential(ticket, u, v, h, client.keyset_id)
    assert client.verify(bob.present(cred_bob.h))

    # alice's credential is spent now
    with pytest.raises(RuntimeError, match="409"):
        client.transfer(alice, h, ticket.commitment.format(), ticket.proof.to_bytes())


def test_transfer_to_self_and_burn(service, tmp_path):
    client, verifier = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    asset = b"jpeg bytes"
    h = hash_asset(asset)
    paid_mint(client, wallet, asset)

    cred2 = client.transfer_to_self(wallet, h)
    assert client.verify(wallet.present(cred2.h))
    assert len(wallet.assets()) == 1  # replaced, not duplicated

    client.burn(wallet, h)
    assert wallet.assets() == []
    with pytest.raises(ValueError, match="no credential"):
        wallet.present(h)


def test_offline_verification_uses_fetched_keyset(service, tmp_path):
    client, verifier = service
    wallet = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    asset = b"jpeg bytes"
    cred = paid_mint(client, wallet, asset)
    pres = present(cred)
    assert client.verify(pres)
    pres.h = hash_asset(b"tampered")
    assert not client.verify(pres)


def test_token_send_receive(service, tmp_path):
    client, verifier = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    bob = NFTWallet(str(tmp_path / "bob.sqlite3"), seed=b"bob seed 0000001")
    asset = b"jpeg bytes"
    h = hash_asset(asset)
    paid_mint(client, alice, asset)

    token = client.send_token(alice, h)
    assert token.startswith("psnft1")
    assert alice.assets() == []

    cred = client.receive(bob, token, description="gift")
    assert cred.h == h
    assert client.verify(bob.present(h))

    # double receive: the nullifier is already spent
    with pytest.raises(RuntimeError, match="409"):
        client.receive(alice, token)


def test_receive_private(service, tmp_path):
    client, verifier = service
    alice = NFTWallet(str(tmp_path / "alice.sqlite3"), seed=b"alice seed 00001")
    bob = NFTWallet(str(tmp_path / "bob.sqlite3"), seed=b"bob seed 0000001")
    asset = b"jpeg bytes"
    h = hash_asset(asset)
    paid_mint(client, alice, asset)
    token = client.send_token(alice, h)
    cred = client.receive(bob, token, private=True)
    assert cred.h == h
    assert client.verify(bob.present(h))


def test_decode_token_garbage(service):
    client, _ = service
    with pytest.raises(ValueError, match="invalid NFT token"):
        client.decode_token("psnft1deadbeef")
    with pytest.raises(ValueError, match="invalid NFT token"):
        client.decode_token("cashuA123")

import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    G1,
    Credential,
    MintPrivateKeyPS,
    hash_asset,
    present,
    prove_owner_secret,
)
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.quotes import DevQuoteBackend


@pytest.fixture(scope="function")
def client(tmp_path):
    backend = DevQuoteBackend(b"operator secret!!")
    ledger = PSLedger(
        Database("test_nft_api", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
        quote_backend=backend,
    )
    import asyncio

    asyncio.run(ledger.migrate())
    return TestClient(create_app(ledger)), backend


def mint_via_api(client, backend, asset: bytes, s: int) -> Credential:
    h = hash_asset(asset)
    quote = client.post(
        "/v1/nft/mint/quote", json={"asset_hash": h.to_bytes(32, "big").hex()}
    ).json()
    pay = client.post(
        f"/v1/nft/mint/quote/{quote['quote']}/pay",
        json={"ticket": backend.issue_dev_ticket(quote["quote"]).hex()},
    )
    assert pay.json()["state"] == "paid"
    S, pok = prove_owner_secret(s)
    resp = client.post(
        "/v1/nft/mint",
        json={
            "asset_hash": h.to_bytes(32, "big").hex(),
            "owner_commitment": S.format().hex(),
            "proof": pok.to_bytes().hex(),
            "quote": quote["quote"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    from cashu.core.crypto.bls import PublicKey

    return Credential(
        u=PublicKey(compressed=bytes.fromhex(body["u"]), group="G1"),
        v=PublicKey(compressed=bytes.fromhex(body["v"]), group="G1"),
        h=h,
        s=s,
        keyset_id=body["keyset_id"],
    )


def transfer_via_api(client, cred: Credential, s_new: int) -> Credential:
    S_new, pok_new = prove_owner_secret(s_new)
    resp = client.post(
        "/v1/nft/transfer",
        json={
            "presentation": present(cred).to_bytes().hex(),
            "new_owner_commitment": S_new.format().hex(),
            "new_proof": pok_new.to_bytes().hex(),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    from cashu.core.crypto.bls import PublicKey

    return Credential(
        u=PublicKey(compressed=bytes.fromhex(body["u"]), group="G1"),
        v=PublicKey(compressed=bytes.fromhex(body["v"]), group="G1"),
        h=cred.h,
        s=s_new,
        keyset_id=body["keyset_id"],
    )


def test_info(client):
    c, _ = client
    resp = c.get("/v1/nft/info")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["keyset_id"]) == 66 and body["keyset_id"].startswith("03")
    assert body["payment_required"] is True
    assert len(body["public_key"]) == 576


def test_mint_and_verify_and_registry(client):
    c, backend = client
    cred = mint_via_api(c, backend, b"jpeg", 111)

    verify = c.post(
        "/v1/nft/verify", json={"presentation": present(cred).to_bytes().hex()}
    )
    assert verify.json() == {"valid": True, "registered": True, "owner_matches": True}

    reg = c.get(f"/v1/nft/registry/{cred.h.to_bytes(32, 'big').hex()}")
    assert reg.json()["owner"] == (G1 * 111).format().hex()


def test_mint_without_payment_is_402(client):
    c, _ = client
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    resp = c.post(
        "/v1/nft/mint",
        json={
            "asset_hash": h.to_bytes(32, "big").hex(),
            "owner_commitment": S.format().hex(),
            "proof": pok.to_bytes().hex(),
        },
    )
    assert resp.status_code == 402


def test_double_mint_is_409(client):
    c, backend = client
    mint_via_api(c, backend, b"jpeg", 111)
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(222)
    quote = c.post(
        "/v1/nft/mint/quote", json={"asset_hash": h.to_bytes(32, "big").hex()}
    ).json()
    c.post(
        f"/v1/nft/mint/quote/{quote['quote']}/pay",
        json={"ticket": backend.issue_dev_ticket(quote["quote"]).hex()},
    )
    resp = c.post(
        "/v1/nft/mint",
        json={
            "asset_hash": h.to_bytes(32, "big").hex(),
            "owner_commitment": S.format().hex(),
            "proof": pok.to_bytes().hex(),
            "quote": quote["quote"],
        },
    )
    assert resp.status_code == 409


def test_transfer_and_replay_is_409(client):
    c, backend = client
    cred = mint_via_api(c, backend, b"jpeg", 111)
    cred2 = transfer_via_api(c, cred, 222)
    verify = c.post(
        "/v1/nft/verify", json={"presentation": present(cred2).to_bytes().hex()}
    )
    assert verify.json()["owner_matches"] is True

    # replaying alice's spent presentation conflicts
    S3, pok3 = prove_owner_secret(333)
    resp = c.post(
        "/v1/nft/transfer",
        json={
            "presentation": present(cred).to_bytes().hex(),
            "new_owner_commitment": S3.format().hex(),
            "new_proof": pok3.to_bytes().hex(),
        },
    )
    assert resp.status_code == 409


def test_burn(client):
    c, backend = client
    cred = mint_via_api(c, backend, b"jpeg", 111)
    resp = c.post("/v1/nft/burn", json={"presentation": present(cred).to_bytes().hex()})
    assert resp.json() == {"status": "burned"}
    assert (
        c.get(f"/v1/nft/registry/{cred.h.to_bytes(32, 'big').hex()}").status_code == 404
    )
    verify = c.post(
        "/v1/nft/verify", json={"presentation": present(cred).to_bytes().hex()}
    )
    # the crypto still verifies, but the asset is gone from the registry
    assert verify.json() == {"valid": True, "registered": False, "owner_matches": False}


def test_malformed_inputs(client):
    c, _ = client
    assert c.post("/v1/nft/mint", json={"asset_hash": "zz"}).status_code == 422
    resp = c.post("/v1/nft/verify", json={"presentation": "abcd"})
    assert resp.status_code == 400
    assert c.get("/v1/nft/registry/00").status_code == 400

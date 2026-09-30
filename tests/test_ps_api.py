import pytest
from fastapi.testclient import TestClient

from cashu.core.crypto.ps import (
    PS_BURN_BINDING,
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
            "presentation": present(cred, binding=S_new.format()).to_bytes().hex(),
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
    assert len(body["public_key"]) == 672


def test_mint_and_verify_and_checkstate(client):
    c, backend = client
    cred = mint_via_api(c, backend, b"jpeg", 111)

    verify = c.post(
        "/v1/nft/verify", json={"presentation": present(cred).to_bytes().hex()}
    )
    assert verify.json() == {"valid": True, "spent": False}

    nullifier = present(cred).nullifier.format().hex()
    cs = c.post("/v1/nft/checkstate", json={"nullifiers": [nullifier]})
    assert cs.json() == {"states": [{"nullifier": nullifier, "state": "UNSPENT"}]}

    asset = c.get(f"/v1/nft/asset/{cred.h.to_bytes(32, 'big').hex()}")
    assert asset.json() == {
        "asset_hash": cred.h.to_bytes(32, "big").hex(),
        "status": "active",
    }


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
    assert verify.json() == {"valid": True, "spent": False}

    # replaying the spent presentation (bound to the same S_new) conflicts
    S2, pok2 = prove_owner_secret(222)
    resp = c.post(
        "/v1/nft/transfer",
        json={
            "presentation": present(cred, binding=S2.format()).to_bytes().hex(),
            "new_owner_commitment": S2.format().hex(),
            "new_proof": pok2.to_bytes().hex(),
        },
    )
    assert resp.status_code == 409


def test_burn(client):
    c, backend = client
    cred = mint_via_api(c, backend, b"jpeg", 111)
    resp = c.post(
        "/v1/nft/burn",
        json={"presentation": present(cred, binding=PS_BURN_BINDING).to_bytes().hex()},
    )
    assert resp.json() == {"status": "burned"}
    asset = c.get(f"/v1/nft/asset/{cred.h.to_bytes(32, 'big').hex()}")
    assert asset.json()["status"] == "burned"
    verify = c.post(
        "/v1/nft/verify", json={"presentation": present(cred).to_bytes().hex()}
    )
    # the crypto still verifies, but the nullifier is spent
    assert verify.json() == {"valid": True, "spent": True}


def test_malformed_inputs(client):
    c, _ = client
    assert c.post("/v1/nft/mint", json={"asset_hash": "zz"}).status_code == 422
    resp = c.post("/v1/nft/verify", json={"presentation": "abcd"})
    assert resp.status_code == 400
    assert c.get("/v1/nft/asset/00").status_code == 400
    # checkstate rejects non-hex and wrong-length nullifiers
    assert c.post("/v1/nft/checkstate", json={"nullifiers": ["zz"]}).status_code == 400
    assert (
        c.post("/v1/nft/checkstate", json={"nullifiers": ["abcd"]}).status_code == 400
    )

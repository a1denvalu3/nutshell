import pytest
from fastapi.testclient import TestClient

from cashu.nft.demo import create_demo_app


@pytest.fixture(scope="function")
def client(tmp_path):
    return TestClient(create_demo_app(str(tmp_path)))


def test_state(client):
    resp = client.get("/api/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["wallets"] == ["alice", "bob"]
    local = next(m for m in body["mints"] if m["id"] == "local")
    assert local["payment_required"] is False
    assert local["keyset_id"].startswith("03")
    assert "unreachable" not in local


def test_full_flow(client):
    # mint via JSON text (alice, local mint is free)
    resp = client.post(
        "/api/mint",
        json={"wallet": "alice", "mint": "local", "description": "note", "text": "hello nft"},
    )
    assert resp.status_code == 200, resp.text
    h = resp.json()["h"]
    assert len(h) == 64

    # alice's asset list shows it active
    assets = client.get("/api/assets", params={"wallet": "alice", "mint": "local"})
    assert [a["h"] for a in assets.json()] == [h]
    assert assets.json()[0]["asset_status"] == "active"
    assert assets.json()[0]["description"] == "note"

    # verify: valid, unspent, active
    v = client.post("/api/verify", json={"wallet": "alice", "mint": "local", "h": h})
    assert v.json() == {"valid": True, "spent": False, "asset_status": "active"}

    # send: alice's copy is gone, a bearer token comes out
    token = client.post(
        "/api/send", json={"wallet": "alice", "mint": "local", "h": h}
    ).json()["token"]
    assert token.startswith("psnft1")
    assert client.get("/api/assets", params={"wallet": "alice", "mint": "local"}).json() == []

    # bob receives (hidden-h swap by default)
    resp = client.post(
        "/api/receive",
        json={"wallet": "bob", "mint": "local", "token": token, "description": "from alice"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["h"] == h
    assets = client.get("/api/assets", params={"wallet": "bob", "mint": "local"})
    assert assets.json()[0]["asset_status"] == "active"

    # bob publishes a showing; a third party inspects it
    blob = client.post(
        "/api/show", json={"wallet": "bob", "mint": "local", "h": h, "context": "ctx-1"}
    ).json()
    assert set(blob.keys()) == {"context", "presentation"}
    result = client.post("/api/inspect", json={"mint": "local", "blob": blob}).json()
    assert result == {
        "valid": True,
        "spent": False,
        "asset_status": "active",
        "asset_hash": h,
    }

    # bob burns; the showing now reports spent + burned
    resp = client.post("/api/burn", json={"wallet": "bob", "mint": "local", "h": h})
    assert resp.json() == {"status": "burned"}
    result = client.post("/api/inspect", json={"mint": "local", "blob": blob}).json()
    assert result["spent"] is True
    assert result["asset_status"] == "burned"
    assert client.get("/api/assets", params={"wallet": "bob", "mint": "local"}).json() == []


def test_multipart_mint(client):
    resp = client.post(
        "/api/mint",
        data={"wallet": "alice", "mint": "local", "description": "file asset"},
        files={"file": ("a.txt", b"file bytes", "text/plain")},
    )
    assert resp.status_code == 200, resp.text
    h = resp.json()["h"]
    assets = client.get("/api/assets", params={"wallet": "alice", "mint": "local"})
    assert assets.json()[0]["h"] == h
    assert assets.json()[0]["description"] == "file asset"


def test_quote_on_free_mint(client):
    resp = client.post("/api/quote", json={"mint": "local", "text": "anything"})
    assert resp.json() == {"state": "free"}


def test_add_bogus_mint_rejected(client):
    resp = client.post(
        "/api/mints", json={"name": "bogus", "url": "http://127.0.0.1:1"}
    )
    assert resp.status_code == 400


def test_remove_local_mint_rejected(client):
    assert client.delete("/api/mints/local").status_code == 400


def test_index_page_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ps·nft lab" in resp.text


def test_raw_nft_api_mounted(client):
    resp = client.get("/v1/nft/info")
    assert resp.status_code == 200
    assert resp.json()["keyset_id"].startswith("03")

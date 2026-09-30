import pytest
from fastapi.testclient import TestClient

from cashu.nft.demo import create_demo_app
from cashu.nft.imgmeta import extract_token

# minimal valid PNG (1x1) with correct magic bytes
PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
    b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


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
    # text assets have no image preview
    assert assets.json()[0]["has_image"] is False
    assert client.get(f"/api/content/{h}").status_code == 404

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

    # bob publishes a showing token; a third party inspects it
    token = client.post(
        "/api/show", json={"wallet": "bob", "mint": "local", "h": h, "context": "ctx-1"}
    ).json()["token"]
    assert token.startswith("pshow1")
    result = client.post("/api/inspect", json={"mint": "local", "token": token}).json()
    assert result == {
        "valid": True,
        "spent": False,
        "asset_status": "active",
        "asset_hash": h,
    }

    # bob burns; the showing now reports spent + burned
    resp = client.post("/api/burn", json={"wallet": "bob", "mint": "local", "h": h})
    assert resp.json() == {"status": "burned"}
    result = client.post("/api/inspect", json={"mint": "local", "token": token}).json()
    assert result["spent"] is True
    assert result["asset_status"] == "burned"
    assert client.get("/api/assets", params={"wallet": "bob", "mint": "local"}).json() == []


def test_inspect_rejects_malformed_token(client):
    resp = client.post("/api/inspect", json={"mint": "local", "token": "garbage"})
    assert resp.status_code == 400


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
    # plain text content is not served as an image
    assert assets.json()[0]["has_image"] is False
    assert client.get(f"/api/content/{h}").status_code == 404


def test_image_content_served_and_shared(client):
    # multipart-mint a real PNG
    resp = client.post(
        "/api/mint",
        data={"wallet": "alice", "mint": "local", "description": "png"},
        files={"file": ("pix.png", PNG_BYTES, "image/png")},
    )
    assert resp.status_code == 200, resp.text
    h = resp.json()["h"]

    assets = client.get("/api/assets", params={"wallet": "alice", "mint": "local"})
    assert assets.json()[0]["has_image"] is True

    resp = client.get(f"/api/content/{h}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content == PNG_BYTES
    assert "immutable" in resp.headers["cache-control"]

    # after alice -> bob, the same content endpoint still serves the bytes
    token = client.post(
        "/api/send", json={"wallet": "alice", "mint": "local", "h": h}
    ).json()["token"]
    client.post("/api/receive", json={"wallet": "bob", "mint": "local", "token": token})
    assets = client.get("/api/assets", params={"wallet": "bob", "mint": "local"})
    assert assets.json()[0]["has_image"] is True
    assert client.get(f"/api/content/{h}").content == PNG_BYTES


def test_content_unknown_hash_404(client):
    h = "00" * 32
    assert client.get(f"/api/content/{h}").status_code == 404


def mint_png(client, wallet: str = "alice") -> str:
    resp = client.post(
        "/api/mint",
        data={"wallet": wallet, "mint": "local", "description": "pix"},
        files={"file": ("pix.png", PNG_BYTES, "image/png")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["h"]


def test_embed_showing_and_extract(client):
    h = mint_png(client)
    resp = client.post(
        "/api/embed",
        json={"wallet": "alice", "mint": "local", "h": h, "kind": "showing"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "image/png"
    assert "pix-proof.png" in resp.headers["content-disposition"]
    # the token is in the metadata, not the pixels; file still a valid PNG
    embedded = resp.content
    token = extract_token(embedded)
    assert token is not None and token.startswith("pshow1")

    resp = client.post(
        "/api/extract", files={"file": ("pix.png", embedded, "image/png")}
    )
    body = resp.json()
    assert body["found"] is True
    assert body["kind"] == "showing"
    assert body["result"] == {
        "valid": True,
        "spent": False,
        "asset_status": "active",
        "asset_hash": h,
    }


def test_embed_bearer_and_extract(client):
    h = mint_png(client)
    resp = client.post(
        "/api/embed",
        json={"wallet": "alice", "mint": "local", "h": h, "kind": "bearer"},
    )
    assert resp.status_code == 200, resp.text
    assert "pix-bearer.png" in resp.headers["content-disposition"]
    token = extract_token(resp.content)
    assert token is not None and token.startswith("psnft1")
    # bearer export does not remove the asset from the wallet
    assets = client.get("/api/assets", params={"wallet": "alice", "mint": "local"})
    assert [a["h"] for a in assets.json()] == [h]

    resp = client.post(
        "/api/extract", files={"file": ("pix.png", resp.content, "image/png")}
    )
    body = resp.json()
    assert body["found"] is True
    assert body["kind"] == "bearer"
    assert body["asset_hash"] == h
    assert body["spent"] is False


def test_embed_and_extract_errors(client):
    # unknown content hash
    resp = client.post(
        "/api/embed",
        json={"wallet": "alice", "mint": "local", "h": "00" * 32, "kind": "showing"},
    )
    assert resp.status_code == 404

    # stored but not JPEG/PNG (JSON text mint)
    resp = client.post(
        "/api/mint",
        json={"wallet": "alice", "mint": "local", "description": "t", "text": "plain"},
    )
    h_text = resp.json()["h"]
    resp = client.post(
        "/api/embed",
        json={"wallet": "alice", "mint": "local", "h": h_text, "kind": "showing"},
    )
    assert resp.status_code == 400

    # extract from a non-image
    resp = client.post(
        "/api/extract", files={"file": ("a.txt", b"hello", "text/plain")}
    )
    assert resp.status_code == 400

    # clean image without a token
    resp = client.post(
        "/api/extract", files={"file": ("pix.png", PNG_BYTES, "image/png")}
    )
    assert resp.json() == {"found": False}


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

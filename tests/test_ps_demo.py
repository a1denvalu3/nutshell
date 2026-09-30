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


def mint_text(client, text: str, description: str = "note") -> str:
    resp = client.post(
        "/api/mint",
        json={"mint": "local", "description": description, "text": text},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["h"]


def mint_png(client, description: str = "pix") -> str:
    resp = client.post(
        "/api/mint",
        data={"mint": "local", "description": description},
        files={"file": ("pix.png", PNG_BYTES, "image/png")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["h"]


def test_state(client):
    resp = client.get("/api/state")
    assert resp.status_code == 200
    body = resp.json()
    assert "wallets" not in body
    local = next(m for m in body["mints"] if m["id"] == "local")
    assert local["payment_required"] is False
    assert local["keyset_id"].startswith("03")
    assert "unreachable" not in local


def test_image_native_roundtrip(client):
    """Mint a PNG, download it with a bearer token embedded, re-upload the
    downloaded file: the asset swaps to a fresh secret and keeps its
    thumbnail."""
    h = mint_png(client, "roundtrip")

    assets = client.get("/api/assets", params={"mint": "local"}).json()
    assert assets[0]["h"] == h
    assert assets[0]["has_image"] is True
    assert assets[0]["asset_status"] == "active"

    # verify: valid, unspent, active
    v = client.post("/api/verify", json={"mint": "local", "h": h})
    assert v.json() == {"valid": True, "spent": False, "asset_status": "active"}

    # download with the bearer token embedded; the asset stays in the wallet
    resp = client.post(
        "/api/embed", json={"mint": "local", "h": h, "kind": "bearer"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "image/png"
    assert "roundtrip-bearer.png" in resp.headers["content-disposition"]
    embedded = resp.content
    token = extract_token(embedded)
    assert token is not None and token.startswith("psnft1")
    assert client.get("/api/assets", params={"mint": "local"}).json()[0]["h"] == h

    # re-upload the image: the token is extracted and swapped (same wallet
    # is fine for the demo), and the image bytes land in the content store
    resp = client.post(
        "/api/receive",
        files={"file": ("roundtrip-bearer.png", embedded, "image/png")},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["h"] == h
    assets = client.get("/api/assets", params={"mint": "local"}).json()
    assert assets[0]["h"] == h
    assert assets[0]["has_image"] is True
    assert assets[0]["description"] == "roundtrip-bearer.png"
    assert client.get(f"/api/content/{h}").status_code == 200

    # the embedded token is now spent: re-uploading the same file fails
    resp = client.post(
        "/api/receive",
        files={"file": ("roundtrip-bearer.png", embedded, "image/png")},
    )
    assert resp.status_code == 409

    # and the asset is still valid, unspent, active after the swap
    v = client.post("/api/verify", json={"mint": "local", "h": h})
    assert v.json() == {"valid": True, "spent": False, "asset_status": "active"}


def test_showing_via_image_and_extract(client):
    h = mint_png(client)
    resp = client.post(
        "/api/embed", json={"mint": "local", "h": h, "kind": "showing"}
    )
    assert resp.status_code == 200, resp.text
    assert "pix-proof.png" in resp.headers["content-disposition"]
    embedded = resp.content
    token = extract_token(embedded)
    assert token is not None and token.startswith("pshow1")

    resp = client.post(
        "/api/extract", files={"file": ("pix-proof.png", embedded, "image/png")}
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


def test_text_asset_token_file_flow(client):
    """Non-image assets get a .psnft.txt / .pshow.txt token attachment."""
    h = mint_text(client, "plain text asset")

    # content endpoint 404s for non-images; listing says no image
    assert client.get(f"/api/content/{h}").status_code == 404
    assets = client.get("/api/assets", params={"mint": "local"}).json()
    assert assets[0]["has_image"] is False

    # bearer download is a text file
    resp = client.post("/api/embed", json={"mint": "local", "h": h, "kind": "bearer"})
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/plain")
    assert "note-bearer.psnft.txt" in resp.headers["content-disposition"]
    token = resp.content.decode()
    assert token.startswith("psnft1")

    # receive the .psnft.txt (with an explicit description; otherwise the
    # filename becomes the label)
    resp = client.post(
        "/api/receive",
        data={"description": "note"},
        files={"file": ("note-bearer.psnft.txt", resp.content)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["h"] == h

    # showing token file -> extract reports the showing
    resp = client.post("/api/embed", json={"mint": "local", "h": h, "kind": "showing"})
    assert "note-proof.pshow.txt" in resp.headers["content-disposition"]
    resp = client.post(
        "/api/extract", files={"file": ("note-proof.pshow.txt", resp.content)}
    )
    body = resp.json()
    assert body["found"] is True
    assert body["kind"] == "showing"
    assert body["result"]["valid"] is True


def test_bearer_extract_flags_spendable(client):
    h = mint_png(client)
    resp = client.post("/api/embed", json={"mint": "local", "h": h, "kind": "bearer"})
    resp = client.post(
        "/api/extract", files={"file": ("pix.png", resp.content, "image/png")}
    )
    body = resp.json()
    assert body["found"] is True
    assert body["kind"] == "bearer"
    assert body["asset_hash"] == h
    assert body["spent"] is False


def test_receive_errors(client):
    # image without any token
    resp = client.post(
        "/api/receive", files={"file": ("clean.png", PNG_BYTES, "image/png")}
    )
    assert resp.status_code == 400
    assert "no token" in resp.json()["detail"]

    # garbage text file
    resp = client.post("/api/receive", files={"file": ("x.txt", b"hello world")})
    assert resp.status_code == 400

    # a showing token is not spendable
    h = mint_png(client)
    embedded = client.post(
        "/api/embed", json={"mint": "local", "h": h, "kind": "showing"}
    ).content
    resp = client.post(
        "/api/receive", files={"file": ("proof.png", embedded, "image/png")}
    )
    assert resp.status_code == 400
    assert "verify-only" in resp.json()["detail"]


def test_multipart_mint_stores_content(client):
    h = mint_png(client, "file asset")
    assets = client.get("/api/assets", params={"mint": "local"}).json()
    assert assets[0]["h"] == h
    assert assets[0]["description"] == "file asset"
    assert assets[0]["has_image"] is True
    resp = client.get(f"/api/content/{h}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content == PNG_BYTES
    assert "immutable" in resp.headers["cache-control"]


def test_content_unknown_hash_404(client):
    assert client.get(f"/api/content/{'00' * 32}").status_code == 404


def test_embed_unknown_hash_404(client):
    resp = client.post(
        "/api/embed", json={"mint": "local", "h": "00" * 32, "kind": "showing"}
    )
    assert resp.status_code == 404


def test_extract_garbage_and_clean(client):
    # unsupported binary type
    resp = client.post(
        "/api/extract", files={"file": ("anim.gif", b"GIF89a" + b"\x00" * 20)}
    )
    assert resp.status_code == 400
    # clean image without a token
    resp = client.post(
        "/api/extract", files={"file": ("pix.png", PNG_BYTES, "image/png")}
    )
    assert resp.json() == {"found": False}
    # text without a token
    resp = client.post("/api/extract", files={"file": ("x.txt", b"hello")})
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

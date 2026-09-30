"""Tests for the custodial JPG portfolio app (cashu/nft/portfolio.py)."""

import hashlib
import io
import secrets
import time
from typing import Iterator, Optional

import pytest
from coincurve import PrivateKey, PublicKeyXOnly
from fastapi.testclient import TestClient
from PIL import Image

from cashu.core.crypto.ps import hash_asset, present, prove_owner_secret
from cashu.nft.imgmeta import embed_token, extract_token
from cashu.nft.portfolio import (
    auth_message,
    claim_digest,
    create_portfolio_app,
)
from cashu.nft.portfolio_jpg import normalize_jpg, split_transfer_jpg, validate_jpg
from cashu.nft.wallet import TOKEN_PREFIX, NFTClient


def make_jpg(
    width: int = 32,
    height: int = 16,
    color=(200, 30, 30),
    exif: Optional[Image.Exif] = None,
) -> bytes:
    image = Image.new("RGB", (width, height), color)
    # A non-uniform pixel keeps orientation observable after transposition.
    image.putpixel((0, 0), (0, 0, 255))
    out = io.BytesIO()
    if exif is not None:
        image.save(out, format="JPEG", quality=90, exif=exif)
    else:
        image.save(out, format="JPEG", quality=90)
    return out.getvalue()


def noisy_jpg(size: int, quality: int = 95) -> bytes:
    image = Image.frombytes("RGB", (size, size), secrets.token_bytes(size * size * 3))
    out = io.BytesIO()
    image.save(out, format="JPEG", quality=quality)
    return out.getvalue()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Profile:
    """Python mirror of portfolio_web/src/api.mjs + crypto.mjs signing."""

    def __init__(self, client: TestClient, secret: Optional[bytes] = None):
        self.client = client
        self.secret = secret or secrets.token_bytes(32)
        self.key = PrivateKey(self.secret)
        self.pubkey = PublicKeyXOnly.from_secret(self.secret).format().hex()

    def sign(self, message: str, key: Optional[PrivateKey] = None) -> str:
        digest = hashlib.sha256(message.encode()).digest()
        return (key or self.key).sign_schnorr(digest).hex()

    def challenge(self, path: str, body: bytes = b"") -> dict:
        resp = self.client.post(
            "/api/auth/challenge",
            json={
                "pubkey": self.pubkey,
                "method": "POST",
                "path": path,
                "body_hash": sha(body),
            },
        )
        assert resp.status_code == 200, resp.text
        challenge = resp.json()
        expected = auth_message(
            self.pubkey,
            "POST",
            path,
            sha(body),
            challenge["nonce"],
            challenge["expires"],
        )
        assert challenge["message"] == expected
        return challenge

    def headers(self, challenge: dict, key: Optional[PrivateKey] = None) -> dict:
        return {
            "X-Portfolio-Challenge": challenge["nonce"],
            "X-Portfolio-Signature": self.sign(challenge["message"], key),
        }

    def post(self, path: str, body: bytes = b""):
        challenge = self.challenge(path, body)
        return self.client.post(path, content=body, headers=self.headers(challenge))

    @property
    def base(self) -> str:
        return f"/api/profiles/{self.pubkey}"

    def create(self, name: str = "Collector") -> dict:
        resp = self.post(self.base, f'{{"name": "{name}"}}'.encode())
        assert resp.status_code == 200, resp.text
        return resp.json()

    def mint(self, jpg: bytes, title: str = "Art"):
        return self.post(f"{self.base}/mint?title={title}", jpg)

    def claim(self, card: dict):
        body = (
            '{"signature":"%s","showing":"%s"}'
            % (
                self.key.sign_schnorr(claim_digest(card["showing"])).hex(),
                card["showing"],
            )
        ).encode()
        return self.post(f"{self.base}/cards/{card['id']}/claim", body)

    def export(self, card_id: str):
        return self.post(f"{self.base}/cards/{card_id}/export")

    def cancel(self, card_id: str):
        return self.post(f"{self.base}/cards/{card_id}/cancel")

    def receive(self, jpg: bytes, title: str = "Got"):
        return self.post(f"{self.base}/receive?title={title}", jpg)

    def get(self) -> dict:
        resp = self.client.get(self.base)
        assert resp.status_code == 200, resp.text
        return resp.json()


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:
    with TestClient(create_portfolio_app(str(tmp_path / "portfolio"))) as c:
        yield c


def minted_card(profile: Profile, jpg: Optional[bytes] = None) -> dict:
    resp = profile.mint(jpg or make_jpg())
    assert resp.status_code == 200, resp.text
    return resp.json()


def exported(profile: Profile, jpg: Optional[bytes] = None) -> tuple:
    card = minted_card(profile, jpg)
    assert profile.claim(card).status_code == 200
    resp = profile.export(card["id"])
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "image/jpeg"
    return card, resp.content


# --- (1) signed auth ------------------------------------------------------


def test_auth_valid_signature_creates_profile(client):
    alice = Profile(client)
    profile = alice.create("Alice")
    assert profile["pubkey"] == alice.pubkey
    assert profile["name"] == "Alice"
    assert profile["cards"] == []


def test_auth_wrong_key_rejected(client):
    alice = Profile(client)
    body = b'{"name":"x"}'
    challenge = alice.challenge(alice.base, body)
    other = PrivateKey(secrets.token_bytes(32))
    resp = client.post(
        alice.base, content=body, headers=alice.headers(challenge, other)
    )
    assert resp.status_code == 403
    assert client.get(alice.base).status_code == 404


def test_auth_challenge_for_other_profile_rejected(client):
    alice, bob = Profile(client), Profile(client)
    resp = client.post(
        "/api/auth/challenge",
        json={
            "pubkey": bob.pubkey,
            "method": "POST",
            "path": alice.base,
            "body_hash": sha(b""),
        },
    )
    assert resp.status_code == 400


def test_auth_replayed_challenge_rejected(client):
    alice = Profile(client)
    body = b'{"name":"x"}'
    challenge = alice.challenge(alice.base, body)
    headers = alice.headers(challenge)
    assert client.post(alice.base, content=body, headers=headers).status_code == 200
    assert client.post(alice.base, content=body, headers=headers).status_code == 401


def test_auth_expired_challenge_rejected(client, monkeypatch):
    alice = Profile(client)
    body = b'{"name":"x"}'
    challenge = alice.challenge(alice.base, body)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 121)
    resp = client.post(alice.base, content=body, headers=alice.headers(challenge))
    assert resp.status_code == 401


def test_auth_altered_body_rejected(client):
    alice = Profile(client)
    challenge = alice.challenge(alice.base, b'{"name":"x"}')
    resp = client.post(
        alice.base, content=b'{"name":"y"}', headers=alice.headers(challenge)
    )
    assert resp.status_code == 403
    assert client.get(alice.base).status_code == 404


def test_auth_altered_path_rejected(client):
    alice = Profile(client)
    alice.create()
    jpg = make_jpg()
    # Signed for profile creation, replayed against the mint endpoint.
    challenge = alice.challenge(alice.base, jpg)
    resp = client.post(
        f"{alice.base}/mint", content=jpg, headers=alice.headers(challenge)
    )
    assert resp.status_code == 403
    # Query string is part of the signed path.
    challenge = alice.challenge(f"{alice.base}/mint?title=a", jpg)
    resp = client.post(
        f"{alice.base}/mint?title=b", content=jpg, headers=alice.headers(challenge)
    )
    assert resp.status_code == 403
    assert alice.get()["cards"] == []


def test_auth_missing_or_garbage_signature_rejected(client):
    alice = Profile(client)
    challenge = alice.challenge(alice.base, b"{}")
    assert client.post(alice.base, content=b"{}").status_code == 401
    headers = {
        "X-Portfolio-Challenge": challenge["nonce"],
        "X-Portfolio-Signature": "zz",
    }
    assert client.post(alice.base, content=b"{}", headers=headers).status_code == 403


# --- claim ----------------------------------------------------------------


def test_claim_requires_matching_profile_signature(client):
    alice = Profile(client)
    alice.create()
    card = minted_card(alice)
    assert alice.export(card["id"]).status_code == 409  # not yet claimed
    bad_sig = (
        PrivateKey(secrets.token_bytes(32))
        .sign_schnorr(claim_digest(card["showing"]))
        .hex()
    )
    body = ('{"signature":"%s","showing":"%s"}' % (bad_sig, card["showing"])).encode()
    assert alice.post(f"{alice.base}/cards/{card['id']}/claim", body).status_code == 403
    resp = alice.claim(card)
    assert resp.status_code == 200, resp.text
    assert resp.json()["signature"]


# --- (2) public endpoints leak no secrets ---------------------------------


def test_public_endpoints_never_expose_credentials(client):
    alice = Profile(client)
    alice.create()
    card, transfer = exported(alice)
    _, token = split_transfer_jpg(transfer)
    assert token is not None and token.startswith(TOKEN_PREFIX)
    cred_hex = token[len(TOKEN_PREFIX) :]
    resp = client.get(alice.base)
    text = resp.text
    assert TOKEN_PREFIX not in text and cred_hex not in text
    for c in resp.json()["cards"]:
        assert "credential" not in c
        assert set(c) == {
            "id",
            "pubkey",
            "h",
            "title",
            "showing",
            "signature",
            "status",
            "created",
            "sent",
        }
    image = client.get(f"/api/images/{card['h']}.jpg")
    assert image.status_code == 200
    assert image.headers["content-type"] == "image/jpeg"
    assert TOKEN_PREFIX.encode() not in image.content
    assert extract_token(image.content) is None
    assert bytes.fromhex(cred_hex) not in image.content
    assert resp.headers["cache-control"] == "no-store"
    assert client.get("/api/images/" + "0" * 64 + ".jpg").status_code == 404
    assert client.get("/api/images/XYZ.jpg").status_code == 404


def test_minting_routes_not_exposed(client):
    assert client.post("/v1/nft/mint", json={}).status_code in (404, 405)
    assert client.post("/v1/nft/mint/quote", json={}).status_code in (404, 405)


# --- (3) JPG validation and normalization ---------------------------------


def test_rejects_non_jpg_and_malformed(client):
    alice = Profile(client)
    alice.create()
    png = io.BytesIO()
    Image.new("RGB", (8, 8)).save(png, format="PNG")
    assert alice.mint(png.getvalue()).status_code == 400
    assert alice.mint(b"\xff\xd8not really a jpeg").status_code == 400
    assert alice.mint(b"").status_code == 400
    # Header intact, scan data truncated: verify() passes, decoding fails.
    jpg = noisy_jpg(128)
    assert alice.mint(jpg[: len(jpg) // 2]).status_code == 400
    assert alice.mint(jpg[:-2]).status_code == 400
    assert alice.get()["cards"] == []


def test_validate_jpg_rejects_png_directly():
    png = io.BytesIO()
    Image.new("RGB", (8, 8)).save(png, format="PNG")
    with pytest.raises(ValueError):
        validate_jpg(png.getvalue())


def test_normalize_applies_orientation_and_strips_metadata():
    exif = Image.Exif()
    exif[0x0112] = 6  # Orientation: rotate 90 CW
    exif[0x010F] = "SecretCamMaker"  # Make
    exif[0x0131] = "leaky-software"  # Software
    src = make_jpg(40, 20, exif=exif)
    with Image.open(io.BytesIO(src)) as check:
        assert check.getexif().get(0x0112) == 6
    out = normalize_jpg(src)
    with Image.open(io.BytesIO(out)) as image:
        assert image.size == (20, 40)
        assert not image.getexif()
        assert "exif" not in image.info
    assert b"SecretCamMaker" not in out and b"leaky-software" not in out
    assert normalize_jpg(src) == out  # deterministic


def test_normalize_rejects_transfer_jpg():
    base = normalize_jpg(make_jpg())
    with pytest.raises(ValueError):
        normalize_jpg(embed_token(base, TOKEN_PREFIX + "00" * 10))


# --- (4) transfer envelope byte identity -----------------------------------


def test_envelope_embed_and_remove_preserves_bytes():
    exif = Image.Exif()
    exif[0x010F] = "UserMeta"
    for base in (normalize_jpg(make_jpg()), make_jpg(exif=exif)):
        token = TOKEN_PREFIX + "ab" * 50
        wrapped = embed_token(base, token)
        assert wrapped != base
        stripped, found = split_transfer_jpg(wrapped)
        assert found == token
        assert stripped == base
        assert split_transfer_jpg(base) == (base, None)


def test_envelope_duplicate_rejected():
    base = normalize_jpg(make_jpg())
    token = TOKEN_PREFIX + "cd" * 20
    once = embed_token(base, token)
    segment = once[2 : len(once) - len(base) + 2]
    twice = once[:2] + segment + once[2:]
    with pytest.raises(ValueError):
        split_transfer_jpg(twice)


def test_exported_jpg_strips_to_public_image(client):
    alice = Profile(client)
    alice.create()
    card, transfer = exported(alice)
    public = client.get(f"/api/images/{card['h']}.jpg").content
    stripped, token = split_transfer_jpg(transfer)
    assert stripped == public
    assert token is not None
    assert hash_asset(public).to_bytes(32, "big").hex() == card["h"]
    assert NFTClient.decode_token(token).h == hash_asset(public)


# --- (5) duplicate mint ------------------------------------------------------


def test_duplicate_mint_rejected(client):
    alice, bob = Profile(client), Profile(client)
    alice.create()
    bob.create()
    jpg = make_jpg()
    minted_card(alice, jpg)
    assert alice.mint(jpg).status_code == 409
    assert bob.mint(jpg).status_code == 409
    assert len(alice.get()["cards"]) == 1
    assert bob.get()["cards"] == []


# --- (6)(7) full flow and double redemption ----------------------------------


def test_full_transfer_flow_and_double_redeem(client):
    alice, bob, carol = Profile(client), Profile(client), Profile(client)
    for p in (alice, bob, carol):
        p.create()
    card, transfer = exported(alice)
    assert alice.get()["cards"][0]["status"] == "ready"

    resp = bob.receive(transfer)
    assert resp.status_code == 200, resp.text
    received = resp.json()
    assert received["h"] == card["h"] and received["status"] == "owned"
    assert received["pubkey"] == bob.pubkey

    sender = alice.get()["cards"]
    assert [c["status"] for c in sender] == ["sent"]
    assert sender[0]["sent"] is not None
    receiver = bob.get()["cards"]
    assert [c["id"] for c in receiver] == [received["id"]]

    # Second redemption (same or other receiver) fails and changes nothing.
    assert bob.receive(transfer).status_code == 409
    assert carol.receive(transfer).status_code == 409
    assert carol.get()["cards"] == []
    assert len(bob.get()["cards"]) == 1

    # Old owner can no longer act on the card.
    assert alice.export(card["id"]).status_code == 409
    assert alice.cancel(card["id"]).status_code == 409

    # Bob can pass it on.
    assert bob.claim(received).status_code == 200
    resp = bob.export(received["id"])
    assert resp.status_code == 200
    assert carol.receive(resp.content).status_code == 200
    assert [c["status"] for c in bob.get()["cards"]] == ["sent"]
    assert [c["status"] for c in carol.get()["cards"]] == ["owned"]


def test_receive_plain_jpg_without_token_rejected(client):
    alice, bob = Profile(client), Profile(client)
    alice.create()
    bob.create()
    card = minted_card(alice)
    public = client.get(f"/api/images/{card['h']}.jpg").content
    assert bob.receive(public).status_code == 400


def test_receive_requires_existing_profile(client):
    alice, bob = Profile(client), Profile(client)
    alice.create()
    card, transfer = exported(alice)
    assert bob.receive(transfer).status_code == 404
    # Nothing spent: alice's export remains redeemable after bob signs up.
    bob.create()
    assert bob.receive(transfer).status_code == 200


def test_bearer_redemption_reconciles_sender(client):
    """A transfer JPG redeemed via the public /v1/nft/transfer route marks the card sent."""
    alice = Profile(client)
    alice.create()
    card, transfer = exported(alice)
    _, token = split_transfer_jpg(transfer)
    assert token is not None
    cred = NFTClient.decode_token(token)
    commitment, proof = prove_owner_secret(12345)
    resp = client.post(
        "/v1/nft/transfer",
        json={
            "presentation": present(cred, binding=commitment.format()).to_bytes().hex(),
            "new_owner_commitment": commitment.format().hex(),
            "new_proof": proof.to_bytes().hex(),
        },
    )
    assert resp.status_code == 200, resp.text
    assert [c["status"] for c in alice.get()["cards"]] == ["sent"]
    assert alice.cancel(card["id"]).status_code == 409


# --- (8) cancel ------------------------------------------------------------


def test_cancel_invalidates_exported_jpg(client):
    alice, bob = Profile(client), Profile(client)
    alice.create()
    bob.create()
    card, transfer = exported(alice)
    resp = alice.cancel(card["id"])
    assert resp.status_code == 200, resp.text
    cancelled = resp.json()
    assert cancelled["status"] == "owned" and cancelled["signature"] is None
    assert cancelled["showing"] != card["showing"]
    assert alice.cancel(card["id"]).status_code == 409

    assert bob.receive(transfer).status_code == 409
    assert bob.get()["cards"] == []
    assert [c["status"] for c in alice.get()["cards"]] == ["owned"]

    # Alice can re-claim and export a fresh, valid transfer.
    assert alice.claim(cancelled).status_code == 200
    fresh = alice.export(card["id"])
    assert fresh.status_code == 200
    assert fresh.content != transfer
    assert bob.receive(fresh.content).status_code == 200


# --- (9) image/token mismatch -------------------------------------------------


def test_image_token_mismatch_rejected_before_spending(client):
    alice, bob = Profile(client), Profile(client)
    alice.create()
    bob.create()
    card, transfer = exported(alice)
    _, token = split_transfer_jpg(transfer)
    assert token is not None
    other = normalize_jpg(make_jpg(color=(10, 200, 10)))
    forged = embed_token(other, token)
    resp = bob.receive(forged)
    assert resp.status_code == 400
    assert "Nothing was redeemed" in resp.json()["detail"]
    assert bob.get()["cards"] == []
    assert [c["status"] for c in alice.get()["cards"]] == ["ready"]
    # The genuine transfer JPG is still redeemable.
    assert bob.receive(transfer).status_code == 200


def test_receive_garbage_token_rejected(client):
    alice = Profile(client)
    alice.create()
    base = normalize_jpg(make_jpg())
    assert alice.receive(embed_token(base, TOKEN_PREFIX + "zz")).status_code == 400
    assert alice.receive(embed_token(base, TOKEN_PREFIX + "00" * 8)).status_code == 400


# --- (10) quotas -----------------------------------------------------------------


def test_max_cards_limit(tmp_path):
    app = create_portfolio_app(str(tmp_path / "p"), max_cards=1)
    with TestClient(app) as client:
        alice, bob = Profile(client), Profile(client)
        alice.create()
        bob.create()
        minted_card(alice, make_jpg(color=(1, 2, 3)))
        assert alice.mint(make_jpg(color=(4, 5, 6))).status_code == 409
        assert len(alice.get()["cards"]) == 1
        # Receiving also counts against the limit, and must not spend.
        card, transfer = exported(bob, make_jpg(color=(7, 8, 9)))
        assert alice.receive(transfer).status_code == 409
        assert [c["status"] for c in bob.get()["cards"]] == ["ready"]


def test_max_jpg_bytes_limit(tmp_path):
    small = make_jpg(8, 8)
    app = create_portfolio_app(str(tmp_path / "p"), max_jpg_bytes=len(small) + 10)
    with TestClient(app) as client:
        alice = Profile(client)
        alice.create()
        assert alice.mint(noisy_jpg(128)).status_code == 413
        assert alice.get()["cards"] == []


def test_normalized_jpg_over_limit_rejected(tmp_path):
    # Upload fits, but the q95 re-encode grows beyond the limit.
    src = noisy_jpg(64, quality=30)
    assert len(normalize_jpg(src)) > len(src)
    app = create_portfolio_app(str(tmp_path / "p"), max_jpg_bytes=len(src))
    with TestClient(app) as client:
        alice = Profile(client)
        alice.create()
        assert alice.mint(src).status_code == 413


def test_storage_limit(tmp_path):
    app = create_portfolio_app(str(tmp_path / "p"), max_storage_bytes=1)
    with TestClient(app) as client:
        alice = Profile(client)
        alice.create()
        assert alice.mint(make_jpg()).status_code == 507
        assert alice.get()["cards"] == []


def test_mint_without_profile_rejected(client):
    alice = Profile(client)
    assert alice.mint(make_jpg()).status_code == 404


# --- (11) persistence ------------------------------------------------------------


def test_restart_persistence(tmp_path):
    data_dir = str(tmp_path / "p")
    with TestClient(create_portfolio_app(data_dir)) as client:
        keyset = client.get("/api/config").json()["keyset_id"]
        alice = Profile(client)
        alice.create("Persisted")
        card, transfer = exported(alice)
        secret = alice.secret
    with TestClient(create_portfolio_app(data_dir)) as client:
        assert client.get("/api/config").json()["keyset_id"] == keyset
        alice = Profile(client, secret)
        profile = alice.get()
        assert profile["name"] == "Persisted"
        assert [c["id"] for c in profile["cards"]] == [card["id"]]
        assert client.get(f"/api/images/{card['h']}.jpg").status_code == 200
        bob = Profile(client)
        bob.create()
        assert bob.receive(transfer).status_code == 200
    with TestClient(create_portfolio_app(str(tmp_path / "other"))) as client:
        assert client.get("/api/config").json()["keyset_id"] != keyset

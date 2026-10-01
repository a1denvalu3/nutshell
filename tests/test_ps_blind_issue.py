"""Blind issuance: proof binding, uniqueness, payment and session safety."""

import asyncio
import uuid

import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from cashu.core.crypto.bls import PublicKey
from cashu.core.crypto.ps import (
    G1,
    PS_BURN_BINDING,
    Credential,
    MintPrivateKeyPS,
    asset_tag,
    blind_base_for_issuance,
    blind_base_for_nullifier,
    blind_issue_commit,
    hash_asset,
    present,
    prove_owner_secret,
    unblind_issued,
    verify_blind_issue,
    verify_presentation,
)
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import (
    ISSUANCE_SESSION_TTL,
    AlreadyMintedError,
    AlreadySpentError,
    InvalidProofError,
    PaymentError,
    PSLedger,
)
from cashu.nft.quotes import DevQuoteBackend
from cashu.nft.wallet import NFTClient, NFTWallet


def point(raw):
    return PublicKey(compressed=bytes.fromhex(raw), group="G1")


def request(ledger, begin, h, s=111):
    u = point(begin["u"])
    tag, B, t, proof = blind_issue_commit(
        ledger.keyset, h, s, u, bytes.fromhex(begin["session"])
    )
    return tag, B, G1 * s, proof, t


async def finish(ledger, begin, h, s=111, quote=None):
    tag, B, S, proof, t = request(ledger, begin, h, s)
    u, raw = await ledger.issue_nft_blind(
        begin["session"], tag, B, S, proof, quote=quote
    )
    return Credential(
        u, unblind_issued(raw, t, ledger.keyset), h, s, ledger.keyset.keyset_id
    )


@pytest_asyncio.fixture
async def ledger(tmp_path):
    led = PSLedger(
        Database("test_blind_issue", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"blind issuance seed"),
    )
    await led.migrate()
    return led


@pytest.mark.asyncio
async def test_unblind_and_public_transfer_and_burn(ledger):
    h = hash_asset(b"jpeg")
    cred = await finish(ledger, await ledger.issue_nft_begin(), h)
    assert verify_presentation(ledger.keyset, present(cred))
    assert await ledger.asset_status(h) == "active"
    # Initial issuance persists only the tag, not the hash scalar.
    assert await ledger.db.fetchall("SELECT * FROM ps_assets") == []
    rows = await ledger.db.fetchall("SELECT tag FROM ps_asset_tags")
    assert [row["tag"] for row in rows] == ["tag:" + asset_tag(h).format().hex()]
    S, pok = prove_owner_secret(222)
    u, v = await ledger.transfer(present(cred, binding=S.format()), S, pok)
    new = Credential(u, v, h, 222, ledger.keyset.keyset_id)
    assert verify_presentation(ledger.keyset, present(new))
    await ledger.burn(present(new, binding=PS_BURN_BINDING))
    assert await ledger.asset_status(h) == "burned"
    with pytest.raises(AlreadyMintedError):
        await finish(ledger, await ledger.issue_nft_begin(), h, 333)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper", ["tag", "commitment", "owner", "base", "session", "keyset"]
)
async def test_proof_binds_every_issuance_parameter(ledger, tamper):
    begin = await ledger.issue_nft_begin()
    tag, B, S, proof, _ = request(ledger, begin, hash_asset(b"jpeg"))
    u, session, keyset = (
        point(begin["u"]),
        bytes.fromhex(begin["session"]),
        ledger.keyset,
    )
    if tamper == "tag":
        tag = asset_tag(hash_asset(b"another JPG"))
    elif tamper == "commitment":
        B = G1 * 123
    elif tamper == "owner":
        S = G1 * 222
    elif tamper == "base":
        u = G1 * 123
    elif tamper == "session":
        session = uuid.uuid4().bytes
    elif tamper == "keyset":
        keyset = MintPrivateKeyPS.from_seed(b"different mint seed").public_key
    assert not verify_blind_issue(keyset, tag, B, u, S, proof, session)


@pytest.mark.asyncio
async def test_forged_tag_does_not_consume_session(ledger):
    h = hash_asset(b"jpeg")
    begin = await ledger.issue_nft_begin()
    _, B, S, proof, _ = request(ledger, begin, h)
    with pytest.raises(InvalidProofError):
        await ledger.issue_nft_blind(begin["session"], asset_tag(h + 1), B, S, proof)
    assert verify_presentation(ledger.keyset, present(await finish(ledger, begin, h)))


@pytest.mark.asyncio
async def test_session_cannot_sign_another_hash_or_owner(ledger):
    begin = await ledger.issue_nft_begin()
    h = hash_asset(b"jpeg")
    await finish(ledger, begin, h)
    with pytest.raises(AlreadySpentError):
        await finish(ledger, begin, hash_asset(b"different"), 222)
    assert await ledger.asset_status(hash_asset(b"different")) == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", [False, True])
async def test_unknown_or_expired_session_cannot_issue(ledger, expired):
    begin = await ledger.issue_nft_begin()
    async with ledger.db.get_connection() as conn:
        if expired:
            await conn.execute(
                "UPDATE ps_issue_sessions SET created=created-:age",
                {"age": ISSUANCE_SESSION_TTL + 1},
            )
        else:
            await conn.execute("DELETE FROM ps_issue_sessions")
    with pytest.raises(InvalidProofError):
        await finish(ledger, begin, hash_asset(b"jpeg"))


@pytest.mark.asyncio
@pytest.mark.parametrize("same_session", [False, True])
async def test_racing_issuances_only_one_wins(ledger, same_session):
    begin = await ledger.issue_nft_begin()
    other = begin if same_session else await ledger.issue_nft_begin()
    h = hash_asset(b"jpeg")
    results = await asyncio.gather(
        finish(ledger, begin, h),
        finish(ledger, other, hash_asset(b"other") if same_session else h, 222),
        return_exceptions=True,
    )
    assert sum(isinstance(result, Credential) for result in results) == 1
    assert (
        sum(
            isinstance(result, (AlreadyMintedError, AlreadySpentError))
            for result in results
        )
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("blind_first", [False, True])
async def test_uniqueness_shared_with_legacy_issuance(ledger, blind_first):
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(222)
    if blind_first:
        await finish(ledger, await ledger.issue_nft_begin(), h)
        with pytest.raises(AlreadyMintedError):
            await ledger.issue_nft(h, S, pok)
    else:
        await ledger.issue_nft(h, S, pok)
        with pytest.raises(AlreadyMintedError):
            await finish(ledger, await ledger.issue_nft_begin(), h)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["active", "burned"])
async def test_migration_preserves_legacy_asset_uniqueness(ledger, status):
    h = hash_asset(b"old JPG")
    async with ledger.db.get_connection() as conn:
        await conn.execute(
            "INSERT INTO ps_assets(h,status,created) VALUES(:h,:status,'old')",
            {"h": h.to_bytes(32, "big").hex(), "status": status},
        )
    await ledger.migrate()
    assert await ledger.asset_status(h) == status
    with pytest.raises(AlreadyMintedError):
        await finish(ledger, await ledger.issue_nft_begin(), h)
    # Re-running migration cannot resurrect a burned legacy asset.
    async with ledger.db.get_connection() as conn:
        await conn.execute("UPDATE ps_asset_tags SET status='burned'")
    await ledger.migrate()
    assert await ledger.asset_status(h) == "burned"


@pytest.mark.asyncio
async def test_paid_tag_quote_bound_to_hidden_hash_and_rolls_back(ledger):
    backend = DevQuoteBackend(b"operator secret!!")
    ledger.quote_backend = backend
    h = hash_asset(b"jpeg")
    quote = await ledger.create_blind_quote(asset_tag(h))
    assert "asset_hash" not in quote
    begin = await ledger.issue_nft_begin()
    with pytest.raises(PaymentError, match="not paid"):
        await finish(ledger, begin, h, quote=quote["quote"])
    await ledger.dev_pay_quote(quote["quote"], backend.issue_dev_ticket(quote["quote"]))
    with pytest.raises(PaymentError, match="different asset"):
        await finish(ledger, begin, hash_asset(b"other"), quote=quote["quote"])
    assert (await ledger.get_quote(quote["quote"]))["state"] == "paid"
    await finish(ledger, begin, h, quote=quote["quote"])
    assert (await ledger.get_quote(quote["quote"]))["state"] == "used"
    duplicate_quote = await ledger.create_blind_quote(asset_tag(h))
    await ledger.dev_pay_quote(
        duplicate_quote["quote"], backend.issue_dev_ticket(duplicate_quote["quote"])
    )
    with pytest.raises(AlreadyMintedError):
        await finish(
            ledger, await ledger.issue_nft_begin(), h, quote=duplicate_quote["quote"]
        )
    assert (await ledger.get_quote(duplicate_quote["quote"]))["state"] == "paid"


def test_bases_are_domain_separated():
    key = MintPrivateKeyPS.from_seed(b"blind issuance seed")
    session = uuid.uuid4().bytes
    assert blind_base_for_issuance(key, session) == blind_base_for_issuance(
        key, session
    )
    assert blind_base_for_issuance(key, session) != blind_base_for_nullifier(
        key, session
    )
    assert asset_tag(123) != G1 * 123


def test_wallet_http_never_sends_hash_during_quote_or_issuance(tmp_path, monkeypatch):
    ledger = PSLedger(
        Database("test_blind_http", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"blind issuance seed"),
        DevQuoteBackend(b"operator secret!!"),
    )
    asyncio.run(ledger.migrate())
    http = TestClient(create_app(ledger))
    client = NFTClient(http)
    wallet = NFTWallet(str(tmp_path / "wallet.sqlite3"), seed=b"blind wallet seed")
    calls = []
    post = http.post

    def record(url, **kwargs):
        calls.append((url, kwargs.get("json", {})))
        return post(url, **kwargs)

    monkeypatch.setattr(http, "post", record)
    quote = client.mint_quote(b"jpeg")
    client.dev_pay_quote(
        quote["quote"],
        DevQuoteBackend(b"operator secret!!").issue_dev_ticket(quote["quote"]),
    )
    cred = client.mint(wallet, b"jpeg", quote=quote["quote"])
    assert verify_presentation(client.keyset, present(cred))
    assert all("asset_hash" not in body for _, body in calls)
    assert all(
        cred.h.to_bytes(32, "big").hex() not in body.values() for _, body in calls
    )
    assert [url for url, _ in calls if "/pay" not in url] == [
        "/v1/nft/mint/private/quote",
        "/v1/nft/mint/private/begin",
        "/v1/nft/mint/private",
    ]
    assert "asset_hash" not in client.get_quote(quote["quote"])


def test_wallet_rejects_malformed_blind_signature(tmp_path, monkeypatch):
    ledger = PSLedger(
        Database("test_bad_blind", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"blind issuance seed"),
    )
    asyncio.run(ledger.migrate())
    issue = ledger.issue_nft_blind

    async def corrupt(*args, **kwargs):
        u, _ = await issue(*args, **kwargs)
        return u, G1 * 123

    monkeypatch.setattr(ledger, "issue_nft_blind", corrupt)
    client = NFTClient(TestClient(create_app(ledger)))
    wallet = NFTWallet(str(tmp_path / "wallet.sqlite3"), seed=b"blind wallet seed")
    with pytest.raises(RuntimeError, match="invalid blind signature"):
        client.mint(wallet, b"jpeg")
    assert wallet.assets() == []


def test_lost_response_recovers_after_wallet_and_mint_restart(tmp_path, monkeypatch):
    key = MintPrivateKeyPS.from_seed(b"blind issuance seed")
    mint_dir = str(tmp_path / "mint")
    ledger = PSLedger(Database("test_recovery", mint_dir), key)
    asyncio.run(ledger.migrate())
    http = TestClient(create_app(ledger))
    client = NFTClient(http)
    wallet_path = str(tmp_path / "wallet.sqlite3")
    wallet = NFTWallet(wallet_path, seed=b"blind wallet seed")
    post = http.post
    captured = []

    def lose_response(url, **kwargs):
        response = post(url, **kwargs)
        if url == "/v1/nft/mint/private":
            assert response.status_code == 200
            captured.append((kwargs["json"], response.json()))
            raise httpx.ReadTimeout("response lost", request=response.request)
        return response

    monkeypatch.setattr(http, "post", lose_response)
    with pytest.raises(RuntimeError, match="retry-mint"):
        client.mint(wallet, b"jpeg", description="recover me")
    (session,) = wallet.pending_mint_sessions(client.keyset_id)
    assert wallet.assets() == []
    wallet.db.close()

    reopened = PSLedger(Database("test_recovery", mint_dir), key)
    asyncio.run(reopened.migrate())

    async def age_sessions():
        async with reopened.db.get_connection() as conn:
            await conn.execute(
                "UPDATE ps_issue_sessions SET created=created-:age",
                {"age": ISSUANCE_SESSION_TTL + 1},
            )
        # Cleanup must not delete an already-signed response.
        await reopened.issue_nft_begin()

    asyncio.run(age_sessions())
    recovered_client = NFTClient(TestClient(create_app(reopened)))
    recovered_wallet = NFTWallet(wallet_path)
    cred = recovered_client.retry_mint(recovered_wallet, session)
    assert verify_presentation(recovered_client.keyset, present(cred))
    assert recovered_wallet.assets()[0].description == "recover me"
    assert recovered_wallet.pending_mint_sessions(recovered_client.keyset_id) == []
    # An exact replay returns the same bytes, without another issuance.
    replay = recovered_client.http.post("/v1/nft/mint/private", json=captured[0][0])
    assert replay.json() == captured[0][1]
    assert len(asyncio.run(reopened.db.fetchall("SELECT * FROM ps_asset_tags"))) == 1


@pytest.mark.asyncio
async def test_cached_response_rejects_fresh_blinding_for_same_asset(ledger):
    begin = await ledger.issue_nft_begin()
    h = hash_asset(b"jpeg")
    await finish(ledger, begin, h)
    # Same h and owner, but a different B and proof: never return a signature
    # that the caller would incorrectly unblind with its fresh t.
    with pytest.raises(AlreadySpentError):
        await finish(ledger, begin, h)


@pytest.mark.parametrize("session", ["zz", "00", "FF" * 16])
def test_api_rejects_bad_session_encoding(tmp_path, session):
    ledger = PSLedger(
        Database("test_bad_session", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"blind issuance seed"),
    )
    asyncio.run(ledger.migrate())
    http = TestClient(create_app(ledger))
    response = http.post(
        "/v1/nft/mint/private",
        json={
            "session": session,
            "asset_tag": "",
            "b": "",
            "owner_commitment": "",
            "proof": "",
        },
    )
    assert response.status_code == 400

"""Deterministic hash commitments: privacy boundary, uniqueness and recovery."""

import asyncio
import uuid

import pytest
import pytest_asyncio

from cashu.core.crypto.ps import (
    G1,
    PS_BURN_BINDING,
    Credential,
    MintPrivateKeyPS,
    asset_tag,
    blind_issue_commit_v2,
    hash_asset,
    issue_commitment,
    present,
    prove_owner_secret,
    verify_issue_commitment,
    verify_presentation,
)
from cashu.core.db import Database
from cashu.nft.ledger import (
    AlreadyMintedError,
    AlreadySpentError,
    InvalidProofError,
    PSLedger,
)
from tests.test_ps_blind_issue import finish, finish_v2


@pytest_asyncio.fixture
async def ledger(tmp_path):
    result = PSLedger(
        Database("test_committed", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"committed issuance seed"),
    )
    await result.migrate()
    return result


def request(ledger, h, s=111, session=None):
    session = session or uuid.uuid4().hex
    tag, C, proof = issue_commitment(ledger.keyset, h, s, bytes.fromhex(session))
    return session, tag, C, G1 * s, proof


async def mint(ledger, h, s=111, session=None):
    u, v = await ledger.issue_nft_committed(*request(ledger, h, s, session))
    return Credential(u, v, h, s, ledger.keyset.keyset_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("h", [0, hash_asset(b"identical jpg")])
async def test_no_blinding_or_unblinding_and_duplicate_hash_rejected(ledger, h):
    a, b = request(ledger, h), request(ledger, h, s=222)
    assert a[1] == b[1] == asset_tag(h)
    assert a[2] == b[2] == ledger.keyset.Y_h1 * h
    assert len(a[4].responses) == 2  # knowledge of h,s; no t
    u, v = await ledger.issue_nft_committed(*a)
    cred = Credential(u, v, h, 111, ledger.keyset.keyset_id)
    assert verify_presentation(ledger.keyset, present(cred))  # raw response works
    with pytest.raises(AlreadyMintedError):
        await ledger.issue_nft_committed(*b)
    await ledger.burn(present(cred, binding=PS_BURN_BINDING))
    with pytest.raises(AlreadyMintedError):
        await mint(ledger, h, s=333)
    assert len(await ledger.db.fetchall("SELECT * FROM ps_asset_tags")) == 1
    assert await ledger.db.fetchall("SELECT * FROM ps_assets") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("other_version", [0, 1, 2])
@pytest.mark.parametrize("new_first", [False, True])
async def test_duplicate_hash_rejected_across_all_versions(
    ledger, other_version, new_first
):
    h = hash_asset(b"same jpg")

    async def older():
        if other_version == 0:
            S, proof = prove_owner_secret(222)
            return await ledger.issue_nft(h, S, proof)
        if other_version == 1:
            return await finish(ledger, await ledger.issue_nft_begin(), h, 222)
        return await finish_v2(ledger, h, 222)

    if new_first:
        await mint(ledger, h)
        with pytest.raises(AlreadyMintedError):
            await older()
    else:
        await older()
        with pytest.raises(AlreadyMintedError):
            await mint(ledger, h)


@pytest.mark.asyncio
@pytest.mark.parametrize("same_id", [False, True])
async def test_concurrent_duplicate_or_conflicting_requests_issue_once(ledger, same_id):
    h, session = hash_asset(b"jpg race"), uuid.uuid4().hex
    result = await asyncio.gather(
        mint(ledger, h, session=session),
        mint(
            ledger, h + 1 if same_id else h, s=222, session=session if same_id else None
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(r, Credential) for r in result) == 1
    assert (
        sum(isinstance(r, (AlreadyMintedError, AlreadySpentError)) for r in result) == 1
    )
    assert len(await ledger.db.fetchall("SELECT * FROM ps_asset_tags")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper", ["tag", "commitment", "owner", "session", "keyset", "version"]
)
async def test_proof_binds_hash_tag_owner_request_and_protocol(ledger, tamper):
    h = hash_asset(b"jpg")
    session, tag, C, S, proof = request(ledger, h)
    keyset = ledger.keyset
    if tamper == "tag":
        tag = asset_tag(h + 1)
    elif tamper == "commitment":
        C = ledger.keyset.Y_h1 * (h + 1)
    elif tamper == "owner":
        S = G1 * 222
    elif tamper == "session":
        session = uuid.uuid4().hex
    elif tamper == "keyset":
        keyset = MintPrivateKeyPS.from_seed(b"another issuer seed").public_key
    else:
        tag, C, _, proof = blind_issue_commit_v2(keyset, h, 111, bytes.fromhex(session))
    assert not verify_issue_commitment(keyset, tag, C, S, proof, bytes.fromhex(session))
    if tamper != "keyset":
        with pytest.raises(InvalidProofError):
            await ledger.issue_nft_committed(session, tag, C, S, proof)
        assert await ledger.db.fetchall("SELECT * FROM ps_asset_tags") == []
        assert await ledger.db.fetchall("SELECT * FROM ps_issue_sessions") == []


@pytest.mark.asyncio
async def test_exact_replay_recovers_signature_after_restart(ledger):
    args = request(ledger, hash_asset(b"jpg"))
    expected = await ledger.issue_nft_committed(*args)
    reopened = PSLedger(ledger.db, ledger.mint_key)
    await reopened.migrate()
    assert await reopened.issue_nft_committed(*args) == expected
    assert len(await ledger.db.fetchall("SELECT * FROM ps_asset_tags")) == 1
    session, tag, C, S, proof = args
    with pytest.raises(AlreadySpentError):
        await reopened.issue_nft_committed(session, tag, C, S, proof, quote="changed")
    with pytest.raises(AlreadySpentError):
        await mint(reopened, hash_asset(b"other jpg"), session=args[0])


@pytest.mark.asyncio
async def test_duplicate_tag_survives_mint_key_rotation(ledger):
    h = hash_asset(b"same jpg after rotation")
    await mint(ledger, h)
    rotated = PSLedger(ledger.db, MintPrivateKeyPS.from_seed(b"rotated issuer seed"))
    await rotated.migrate()
    assert request(ledger, h)[2] != request(rotated, h)[2]
    with pytest.raises(AlreadyMintedError):
        await mint(rotated, h)

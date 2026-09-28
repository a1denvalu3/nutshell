import asyncio

import pytest
import pytest_asyncio

from cashu.core.crypto.ps import (
    G1,
    Credential,
    DlogEqProof,
    MintPrivateKeyPS,
    hash_asset,
    present,
    prove_owner_secret,
    verify_presentation,
)
from cashu.core.db import Database
from cashu.nft.ledger import (
    AlreadyMintedError,
    AlreadySpentError,
    InvalidProofError,
    NotOwnerError,
    PSLedger,
    UnknownAssetError,
)


@pytest_asyncio.fixture(scope="function")
async def ledger(tmp_path):
    db = Database("test_nft", str(tmp_path))
    led = PSLedger(db, MintPrivateKeyPS.from_seed(b"test seed 012345"))
    await led.migrate()
    return led


async def mint_asset(led: PSLedger, asset: bytes, s: int) -> Credential:
    h = hash_asset(asset)
    S, pok = prove_owner_secret(s)
    u, v = await led.issue_nft(h, S, pok)
    return Credential(u=u, v=v, h=h, s=s, keyset_id=led.keyset.keyset_id)


@pytest.mark.asyncio
async def test_issue_and_owner_lookup(ledger):
    cred = await mint_asset(ledger, b"jpeg", 111)
    assert await ledger.get_owner(cred.h) == (G1 * 111).format()
    assert await ledger.get_owner(hash_asset(b"never minted")) is None


@pytest.mark.asyncio
async def test_double_mint_rejected(ledger):
    await mint_asset(ledger, b"jpeg", 111)
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(222)
    with pytest.raises(AlreadyMintedError):
        await ledger.issue_nft(h, S, pok)


@pytest.mark.asyncio
async def test_issue_rejects_bad_proof(ledger):
    h = hash_asset(b"jpeg")
    S, _ = prove_owner_secret(111)
    with pytest.raises(InvalidProofError):
        await ledger.issue_nft(h, S, DlogEqProof(challenge=1, response=1))


@pytest.mark.asyncio
async def test_persistence_across_reopens(tmp_path):
    db = Database("test_nft", str(tmp_path))
    key = MintPrivateKeyPS.from_seed(b"test seed 012345")
    led1 = PSLedger(db, key)
    await led1.migrate()
    cred = await mint_asset(led1, b"jpeg", 111)

    led2 = PSLedger(Database("test_nft", str(tmp_path)), key)
    await led2.migrate()
    assert await led2.get_owner(cred.h) == (G1 * 111).format()
    # a transfer issued against the reopened ledger verifies
    S_new, pok_new = prove_owner_secret(222)
    u2, v2 = await led2.transfer(present(cred), S_new, pok_new)
    cred2 = Credential(u=u2, v=v2, h=cred.h, s=222, keyset_id=cred.keyset_id)
    assert verify_presentation(led2.keyset, present(cred2))


@pytest.mark.asyncio
async def test_transfer_flow_and_double_spend(ledger):
    cred = await mint_asset(ledger, b"jpeg", 111)
    S_new, pok_new = prove_owner_secret(222)
    u2, v2 = await ledger.transfer(present(cred), S_new, pok_new)
    assert await ledger.get_owner(cred.h) == (G1 * 222).format()
    with pytest.raises(AlreadySpentError):
        await ledger.transfer(present(cred), S_new, pok_new)
    cred2 = Credential(u=u2, v=v2, h=cred.h, s=222, keyset_id=cred.keyset_id)
    S3, pok3 = prove_owner_secret(333)
    await ledger.transfer(present(cred2), S3, pok3)


@pytest.mark.asyncio
async def test_transfer_rejects_non_owner(ledger):
    cred = await mint_asset(ledger, b"jpeg", 111)
    evil = await mint_asset(ledger, b"other", 222)
    pres = present(evil)
    pres.h = cred.h
    S_new, pok_new = prove_owner_secret(222)
    with pytest.raises((InvalidProofError, NotOwnerError)):
        await ledger.transfer(pres, S_new, pok_new)


@pytest.mark.asyncio
async def test_transfer_unknown_asset(ledger):
    cred = await mint_asset(ledger, b"jpeg", 111)
    pres = present(cred)
    pres.h = hash_asset(b"never minted")
    S_new, pok_new = prove_owner_secret(222)
    with pytest.raises((InvalidProofError, UnknownAssetError)):
        await ledger.transfer(pres, S_new, pok_new)


@pytest.mark.asyncio
async def test_concurrent_transfers_only_one_wins(ledger):
    cred = await mint_asset(ledger, b"jpeg", 111)
    S_new, pok_new = prove_owner_secret(222)
    S_alt, pok_alt = prove_owner_secret(333)

    async def t1():
        return await ledger.transfer(present(cred), S_new, pok_new)

    async def t2():
        return await ledger.transfer(present(cred), S_alt, pok_alt)

    results = await asyncio.gather(t1(), t2(), return_exceptions=True)
    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], AlreadySpentError)


@pytest.mark.asyncio
async def test_burn(ledger):
    cred = await mint_asset(ledger, b"jpeg", 111)
    await ledger.burn(present(cred))
    assert await ledger.get_owner(cred.h) is None
    with pytest.raises(AlreadySpentError):
        await ledger.burn(present(cred))
    S_new, pok_new = prove_owner_secret(222)
    with pytest.raises((InvalidProofError, UnknownAssetError, AlreadySpentError)):
        await ledger.transfer(present(cred), S_new, pok_new)

import pytest
import pytest_asyncio

from cashu.core.crypto.ps import MintPrivateKeyPS, hash_asset, prove_owner_secret
from cashu.core.db import Database
from cashu.nft.ledger import (
    AlreadyMintedError,
    AlreadySpentError,
    PaymentError,
    PSLedger,
    UnknownQuoteError,
)
from cashu.nft.quotes import DevQuoteBackend

SECRET = b"operator secret!!"


@pytest_asyncio.fixture(scope="function")
async def paid_ledger(tmp_path):
    backend = DevQuoteBackend(SECRET)
    led = PSLedger(
        Database("test_nft_quotes", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
        quote_backend=backend,
    )
    await led.migrate()
    return led, backend


@pytest.mark.asyncio
async def test_mint_requires_quote(paid_ledger):
    led, _ = paid_ledger
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    with pytest.raises(PaymentError, match="mint quote required"):
        await led.issue_nft(h, S, pok)


@pytest.mark.asyncio
async def test_quote_lifecycle(paid_ledger):
    led, backend = paid_ledger
    h = hash_asset(b"jpeg")
    quote = await led.create_quote(h)
    assert quote["state"] == "unpaid"
    assert quote["amount"] == 21
    assert (await led.get_quote(quote["quote"]))["state"] == "unpaid"

    # minting against an unpaid quote fails
    S, pok = prove_owner_secret(111)
    with pytest.raises(PaymentError, match="not paid"):
        await led.issue_nft(h, S, pok, quote=quote["quote"])

    # wrong ticket fails, right ticket settles
    with pytest.raises(PaymentError, match="invalid payment ticket"):
        await led.dev_pay_quote(quote["quote"], b"\x00" * 32)
    await led.dev_pay_quote(quote["quote"], backend.issue_dev_ticket(quote["quote"]))
    assert (await led.get_quote(quote["quote"]))["state"] == "paid"

    # mint consumes the quote exactly once
    await led.issue_nft(h, S, pok, quote=quote["quote"])
    assert (await led.get_quote(quote["quote"]))["state"] == "used"
    S2, pok2 = prove_owner_secret(222)
    with pytest.raises((AlreadySpentError, AlreadyMintedError)):
        await led.issue_nft(h, S2, pok2, quote=quote["quote"])


@pytest.mark.asyncio
async def test_quote_is_asset_specific(paid_ledger):
    led, backend = paid_ledger
    h1, h2 = hash_asset(b"one"), hash_asset(b"two")
    quote = await led.create_quote(h1)
    await led.dev_pay_quote(quote["quote"], backend.issue_dev_ticket(quote["quote"]))
    S, pok = prove_owner_secret(111)
    with pytest.raises(PaymentError, match="different asset"):
        await led.issue_nft(h2, S, pok, quote=quote["quote"])


@pytest.mark.asyncio
async def test_unknown_quote(paid_ledger):
    led, backend = paid_ledger
    with pytest.raises(UnknownQuoteError):
        await led.get_quote("nonexistent")
    # a correctly-authenticated ticket for a quote that does not exist
    with pytest.raises(UnknownQuoteError):
        await led.dev_pay_quote("nonexistent", backend.issue_dev_ticket("nonexistent"))


@pytest.mark.asyncio
async def test_free_mint_without_backend(tmp_path):
    led = PSLedger(
        Database("test_nft_free", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    await led.migrate()
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    await led.issue_nft(h, S, pok)
    with pytest.raises(PaymentError, match="does not require quotes"):
        await led.create_quote(h)

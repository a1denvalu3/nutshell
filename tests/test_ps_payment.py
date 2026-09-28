import pytest
import pytest_asyncio

from cashu.core.crypto.ps import MintPrivateKeyPS, hash_asset, prove_owner_secret
from cashu.core.db import Database
from cashu.nft.ledger import PaymentError, PSLedger
from cashu.nft.payment import DevPaymentVerifier


@pytest_asyncio.fixture(scope="function")
async def paid_ledger(tmp_path):
    verifier = DevPaymentVerifier(b"operator secret!!")
    led = PSLedger(
        Database("test_nft_pay", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
        payment_verifier=verifier,
    )
    await led.migrate()
    return led, verifier


@pytest.mark.asyncio
async def test_mint_requires_payment(paid_ledger):
    led, _ = paid_ledger
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    with pytest.raises(PaymentError, match="payment required"):
        await led.issue_nft(h, S, pok)


@pytest.mark.asyncio
async def test_mint_rejects_wrong_ticket(paid_ledger):
    led, verifier = paid_ledger
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    with pytest.raises(PaymentError, match="invalid payment ticket"):
        await led.issue_nft(h, S, pok, payment=b"\x00" * 32)
    # a ticket for a different asset does not pay for this one
    other_ticket = verifier.issue_ticket(hash_asset(b"other asset"))
    with pytest.raises(PaymentError, match="invalid payment ticket"):
        await led.issue_nft(h, S, pok, payment=other_ticket)


@pytest.mark.asyncio
async def test_mint_with_valid_ticket(paid_ledger):
    led, verifier = paid_ledger
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    ticket = verifier.issue_ticket(h)
    u, v = await led.issue_nft(h, S, pok, payment=ticket)
    assert not u.is_infinity() and not v.is_infinity()


@pytest.mark.asyncio
async def test_free_mint_without_verifier(tmp_path):
    led = PSLedger(
        Database("test_nft_free", str(tmp_path)),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    await led.migrate()
    h = hash_asset(b"jpeg")
    S, pok = prove_owner_secret(111)
    await led.issue_nft(h, S, pok)  # no payment, no error

import pytest
import pytest_asyncio
from cashu.core.base import MintQuoteState
from cashu.core.models import PostMintQuoteRequest
from cashu.wallet.wallet import Wallet
from cashu.mint.ledger import Ledger
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_fake, pay_if_regtest, assert_err

@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_batch",
        name="wallet_batch",
    )
    await wallet.load_mint()
    yield wallet

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_batch_check_mint_quotes(wallet: Wallet, ledger: Ledger):
    # Disable auto-payment
    from cashu.core.settings import settings
    settings.fakewallet_brr = False
    
    try:
        # Request multiple mint quotes
        quote1 = await wallet.request_mint(100)
        quote2 = await wallet.request_mint(200)
        
        # Verify initial state
        q1_db = await wallet.get_mint_quote(quote1.quote)
        q2_db = await wallet.get_mint_quote(quote2.quote)
        assert q1_db.state == MintQuoteState.unpaid
        assert q2_db.state == MintQuoteState.unpaid
        
        # Pay one of them manually
        from cashu.core.base import Method, Unit
        backend = ledger.backends[Method.bolt11][Unit.sat]
        invoice = next(i for i in backend.created_invoices if i.payment_hash == quote1.checking_id)
        await backend.mark_invoice_paid(invoice, delay=False)
        
        # Check states in batch
        updated_quotes = await wallet.check_all_mint_quotes()
        
        # Verify results
        assert len(updated_quotes) >= 1
        # Find our quotes in the updated list
        q1_updated = next((q for q in updated_quotes if q.quote == quote1.quote), None)
        
        # Quote 1 should be updated to paid
        assert q1_updated
        assert q1_updated.state == MintQuoteState.paid
        
        # Quote 2 should remain unpaid
        q2_db_after = await wallet.get_mint_quote(quote2.quote)
        assert q2_db_after.state == MintQuoteState.unpaid
        
    finally:
        settings.fakewallet_brr = True

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_batch_mint_success(wallet: Wallet, ledger: Ledger):
    # Ensure BRR is on for easy payment
    from cashu.core.settings import settings
    settings.fakewallet_brr = True
    
    # Request quotes
    quote1 = await wallet.request_mint(100)
    quote2 = await wallet.request_mint(200)
    
    # Pay both
    await pay_if_regtest(quote1.request)
    await pay_if_regtest(quote2.request)
    
    # Update states to PAID so mint_batch can be called
    await wallet.check_all_mint_quotes()
    
    # Fetch the paid quote objects
    q1 = await wallet.get_mint_quote(quote1.quote)
    q2 = await wallet.get_mint_quote(quote2.quote)
    
    assert q1.state == MintQuoteState.paid
    assert q2.state == MintQuoteState.paid
    
    # Mint in batch
    initial_balance = wallet.available_balance
    proofs = await wallet.mint_batch([q1, q2])
    
    # Verify proofs
    assert len(proofs) > 0
    assert sum(p.amount for p in proofs) == 300
    assert wallet.available_balance == initial_balance + 300
    
    # Verify mint side state
    mint_q1 = await ledger.get_mint_quote(quote1.quote)
    mint_q2 = await ledger.get_mint_quote(quote2.quote)
    assert mint_q1.issued
    assert mint_q2.issued

@pytest.mark.skipif(not is_fake, reason="only for FakeWallet")
@pytest.mark.asyncio
async def test_batch_mint_partial_failure(wallet: Wallet, ledger: Ledger):
    from cashu.core.settings import settings
    settings.fakewallet_brr = False
    
    try:
        # Request quotes
        quote1 = await wallet.request_mint(100)
        quote2 = await wallet.request_mint(200)
        
        # Pay ONLY quote 1 manually
        from cashu.core.base import Method, Unit
        backend = ledger.backends[Method.bolt11][Unit.sat]
        invoice = next(i for i in backend.created_invoices if i.payment_hash == quote1.checking_id)
        await backend.mark_invoice_paid(invoice, delay=False)
        
        # Fake the wallet state to think quote 2 is paid (to test API rejection)
        from cashu.wallet.crud import update_bolt11_mint_quote
        import time
        await update_bolt11_mint_quote(wallet.db, quote1.quote, MintQuoteState.paid, int(time.time()))
        await update_bolt11_mint_quote(wallet.db, quote2.quote, MintQuoteState.paid, int(time.time()))
        
        q1 = await wallet.get_mint_quote(quote1.quote)
        q2 = await wallet.get_mint_quote(quote2.quote)
        
        # Attempt batch mint - should fail because quote 2 is not actually paid on mint
        await assert_err(
            wallet.mint_batch([q1, q2]),
            "Quote is not paid"
        )
        
        # Verify quote 1 is NOT issued on mint (atomicity)
        mint_q1 = await ledger.get_mint_quote(quote1.quote)
        assert not mint_q1.issued
        assert mint_q1.paid
        
    finally:
        settings.fakewallet_brr = True

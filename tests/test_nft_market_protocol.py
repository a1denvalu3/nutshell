"""Protocol gate for the NFT marketplace (cashu/nft/MARKETPLACE_PLAN.md).

Cash leg: real NUT-14 HTLCs with SIG_ALL at the test Nutshell mint. Proves
that a buyer's refund and a seller's claim can both be signed in advance for
fixed outputs, that the mint enforces the hashlock and the locktime, that
outputs cannot be redirected, and that outcomes and lost replies are
recoverable from the mint alone.

NFT leg: the PS ledger's contract registry and public reissue. Proves the
buyer recovers a usable credential from the mint's issuance without the
seller learning the new owner secret, that locks bind every spend route, and
that the preimage escrow and receipts are purpose-bound.
"""

import asyncio
import hashlib
import json
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple

import httpx
import pytest
import pytest_asyncio
from coincurve import PrivateKey as SecpKey
from fastapi.testclient import TestClient

from cashu.core.crypto.bls import PublicKey as G1Point
from cashu.core.crypto.ps import (
    G1,
    PS_BURN_BINDING,
    Credential,
    MintPrivateKeyPS,
    blind_transfer_commit,
    present,
    present_private,
    prove_dlog_eq,
    prove_owner_secret,
    verify_presentation,
)
from cashu.core.db import Database
from cashu.core.htlc import HTLCSecret
from cashu.core.migrations import migrate_databases
from cashu.core.secret import SecretKind, Tags
from cashu.nft import market_cash
from cashu.nft import market_protocol as mp
from cashu.nft.api import LOCK_RECEIVE_DST, create_app
from cashu.nft.ledger import (
    LOCK_BINDING,
    REFUND_BINDING,
    AlreadySpentError,
    InvalidProofError,
    LockedError,
    NFTContract,
    PSLedger,
)
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest, use_v2_keyset

WEB = Path(__file__).resolve().parent.parent / "cashu" / "nft" / "portfolio_web"


# --- cash leg fixtures -------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def buyer_wallet():
    wallet = await Wallet.with_db(
        SERVER_ENDPOINT, f"test_data/market_buyer_{secrets.token_hex(4)}", "buyer"
    )
    await migrate_databases(wallet.db, migrations)
    await wallet.load_mint()
    await use_v2_keyset(wallet)
    quote = await wallet.request_mint(256)
    await pay_if_regtest(quote.request)
    await wallet.mint(256, quote_id=quote.quote)
    yield wallet


def keypair() -> Tuple[SecpKey, str]:
    key = SecpKey(secrets.token_bytes(32))
    return key, key.public_key.format().hex()


def htlc_lock(
    hashlock: str, claim_pub: str, refund_pub: str, locktime: int
) -> HTLCSecret:
    tags = Tags()
    tags["pubkeys"] = [claim_pub]
    tags["refund"] = [refund_pub]
    tags["locktime"] = str(locktime)
    tags["sigflag"] = "SIG_ALL"
    return HTLCSecret(kind=SecretKind.HTLC.value, data=hashlock, tags=tags)


async def fund_htlc(wallet: Wallet, amount: int, lock: HTLCSecret) -> List[Dict]:
    _, sent = await wallet.swap_to_send(wallet.proofs, amount, secret_lock=lock)
    return [
        {"amount": p.amount, "id": p.id, "secret": p.secret, "C": p.C} for p in sent
    ]


def keys_of(wallet: Wallet, keyset_id: str) -> Dict[int, str]:
    return {
        a: k.format().hex() for a, k in wallet.keysets[keyset_id].public_keys.items()
    }


def presign(key: SecpKey, proofs: List[Dict], outputs: List[Dict]) -> str:
    digest = mp.sigall_digest(
        [(p["secret"], p["C"]) for p in proofs],
        [(o["amount"], o["B_"]) for o in outputs],
    )
    return key.sign_schnorr(digest).hex()


class Offer:
    """Everything a buyer prepares for one funded offer (cash side)."""

    def __init__(self, wallet: Wallet, amount: int, locktime: int):
        self.preimage = secrets.token_bytes(32)
        self.hashlock = hashlib.sha256(self.preimage).hexdigest()
        self.claim_key, self.claim_pub = keypair()
        self.refund_key, self.refund_pub = keypair()
        self.locktime = locktime
        self.wallet = wallet
        self.amount = amount

    async def fund(self) -> None:
        lock = htlc_lock(self.hashlock, self.claim_pub, self.refund_pub, self.locktime)
        self.proofs = await fund_htlc(self.wallet, self.amount, lock)
        self.keyset_id = self.proofs[0]["id"]
        self.keys = keys_of(self.wallet, self.keyset_id)
        # Both parties fix their outputs and sign before anything is executable.
        self.refund_outputs = market_cash.blind_outputs(self.amount, self.keyset_id)
        self.refund_sig = presign(
            self.refund_key, self.proofs, self.refund_outputs.public()
        )
        self.claim_outputs = market_cash.blind_outputs(self.amount, self.keyset_id)
        self.claim_sig = presign(
            self.claim_key, self.proofs, self.claim_outputs.public()
        )

    async def refund(self, client: httpx.AsyncClient):
        inputs = market_cash.swap_inputs(self.proofs, self.refund_sig)
        return await market_cash.submit_swap(
            client, SERVER_ENDPOINT, inputs, self.refund_outputs.public()
        )

    async def claim(self, client: httpx.AsyncClient, preimage: bytes = b""):
        inputs = market_cash.swap_inputs(
            self.proofs, self.claim_sig, (preimage or self.preimage).hex()
        )
        return await market_cash.submit_swap(
            client, SERVER_ENDPOINT, inputs, self.claim_outputs.public()
        )


async def assert_spendable(client: httpx.AsyncClient, proofs: List[Dict]) -> None:
    states = await market_cash.proof_states(
        client, SERVER_ENDPOINT, [p["secret"] for p in proofs]
    )
    assert all(s["state"] == "UNSPENT" for s in states)


# --- cash leg ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_presigned_before_preimage_wins_and_refund_waits(buyer_wallet):
    offer = Offer(buyer_wallet, 64, int(time.time()) + 3600)
    await offer.fund()
    async with httpx.AsyncClient() as client:
        # The buyer's refund is signed now but the mint holds it to the locktime.
        with pytest.raises(market_cash.MintRejected):
            await offer.refund(client)
        # The seller signed the claim before the preimage existed for them;
        # appending the released preimage makes it valid.
        sigs = await offer.claim(client)
        paid = market_cash.unblind(offer.claim_outputs, sigs, offer.keys)
        assert sum(p["amount"] for p in paid) == 64
        await assert_spendable(client, paid)
        states = await market_cash.proof_states(
            client, SERVER_ENDPOINT, [p["secret"] for p in offer.proofs]
        )
        assert market_cash.spent_by(states) == "claim"
        with pytest.raises(market_cash.MintRejected):
            await offer.refund(client)


@pytest.mark.asyncio
async def test_presigned_refund_executes_after_locktime_and_beats_late_claim(
    buyer_wallet,
):
    offer = Offer(buyer_wallet, 32, int(time.time()) + 2)
    await offer.fund()
    async with httpx.AsyncClient() as client:
        with pytest.raises(market_cash.MintRejected):
            await offer.refund(client)
        await asyncio.sleep(3.2)
        sigs = await offer.refund(client)
        refunded = market_cash.unblind(offer.refund_outputs, sigs, offer.keys)
        assert sum(p["amount"] for p in refunded) == 32
        await assert_spendable(client, refunded)
        states = await market_cash.proof_states(
            client, SERVER_ENDPOINT, [p["secret"] for p in offer.proofs]
        )
        assert market_cash.spent_by(states) == "refund"
        # The hashlock path stays valid after the locktime, but only one spend wins.
        with pytest.raises(market_cash.MintRejected):
            await offer.claim(client)


@pytest.mark.asyncio
async def test_hashlock_path_still_valid_after_locktime_until_refunded(buyer_wallet):
    offer = Offer(buyer_wallet, 16, int(time.time()) + 1)
    await offer.fund()
    await asyncio.sleep(2.2)
    async with httpx.AsyncClient() as client:
        sigs = await offer.claim(client)
        assert (
            sum(
                p["amount"]
                for p in market_cash.unblind(offer.claim_outputs, sigs, offer.keys)
            )
            == 16
        )
        with pytest.raises(market_cash.MintRejected):
            await offer.refund(client)


@pytest.mark.asyncio
async def test_presigned_outputs_cannot_be_redirected(buyer_wallet):
    offer = Offer(buyer_wallet, 16, int(time.time()) + 3600)
    await offer.fund()
    thief = market_cash.blind_outputs(16, offer.keyset_id)
    async with httpx.AsyncClient() as client:
        inputs = market_cash.swap_inputs(
            offer.proofs, offer.claim_sig, offer.preimage.hex()
        )
        with pytest.raises(market_cash.MintRejected):
            await market_cash.submit_swap(
                client, SERVER_ENDPOINT, inputs, thief.public()
            )
        # Changing an amount breaks the SIG_ALL transcript as well.
        bent = offer.claim_outputs.public()
        bent[0] = {**bent[0], "amount": bent[0]["amount"] // 2 or 1}
        with pytest.raises(market_cash.MintRejected):
            await market_cash.submit_swap(client, SERVER_ENDPOINT, inputs, bent)
        await assert_spendable(client, offer.proofs)


@pytest.mark.asyncio
async def test_wrong_preimage_and_wrong_key_rejected(buyer_wallet):
    offer = Offer(buyer_wallet, 16, int(time.time()) + 3600)
    await offer.fund()
    async with httpx.AsyncClient() as client:
        with pytest.raises(market_cash.MintRejected):
            await offer.claim(client, preimage=secrets.token_bytes(32))
        # The refund key is not a claim key, even with the right preimage.
        wrong = presign(offer.refund_key, offer.proofs, offer.claim_outputs.public())
        inputs = market_cash.swap_inputs(offer.proofs, wrong, offer.preimage.hex())
        with pytest.raises(market_cash.MintRejected):
            await market_cash.submit_swap(
                client, SERVER_ENDPOINT, inputs, offer.claim_outputs.public()
            )
        await assert_spendable(client, offer.proofs)


@pytest.mark.asyncio
async def test_lost_swap_reply_is_recovered_with_restore(buyer_wallet):
    offer = Offer(buyer_wallet, 64, int(time.time()) + 3600)
    await offer.fund()
    async with httpx.AsyncClient() as client:
        assert (
            await market_cash.restore(
                client, SERVER_ENDPOINT, offer.claim_outputs.public()
            )
            == []
        )
        await offer.claim(client)  # reply "lost": the executor keeps nothing
        sigs = await market_cash.restore(
            client, SERVER_ENDPOINT, offer.claim_outputs.public()
        )
        paid = market_cash.unblind(offer.claim_outputs, sigs, offer.keys)
        assert sum(p["amount"] for p in paid) == 64
        await assert_spendable(client, paid)
        # Retrying the exact same swap is refused; restore is the recovery path.
        with pytest.raises(market_cash.MintRejected):
            await offer.claim(client)


@pytest.mark.asyncio
async def test_signature_check_matches_the_mint(buyer_wallet):
    offer = Offer(buyer_wallet, 8, int(time.time()) + 3600)
    await offer.fund()
    pairs = (
        [(p["secret"], p["C"]) for p in offer.proofs],
        [(o["amount"], o["B_"]) for o in offer.claim_outputs.public()],
    )
    assert mp.verify_sigall(*pairs, offer.claim_sig, offer.claim_pub)
    assert not mp.verify_sigall(*pairs, offer.claim_sig, offer.refund_pub)
    assert not mp.verify_sigall(
        pairs[0],
        pairs[1][:-1] or [(1, pairs[1][0][1])],
        offer.claim_sig,
        offer.claim_pub,
    )


def manifest_for(offer: Offer, **changes) -> Dict:
    manifest = {
        "hashlock": offer.hashlock,
        "claim_pubkey": offer.claim_pub,
        "refund_pubkey": offer.refund_pub,
        "cash_deadline": offer.locktime,
        "payment": {
            "keyset_id": offer.keyset_id,
            "amount": offer.amount,
            "unit": "sat",
        },
    }
    manifest.update(changes)
    return manifest


@pytest.mark.asyncio
async def test_payment_proof_terms_are_checked_exactly(buyer_wallet):
    offer = Offer(buyer_wallet, 16, int(time.time()) + 3600)
    await offer.fund()
    assert mp.check_payment_proofs(offer.proofs, manifest_for(offer)) == 16
    for change in (
        {"hashlock": "00" * 32},
        {"claim_pubkey": keypair()[1]},
        {"refund_pubkey": keypair()[1]},
        {"cash_deadline": offer.locktime + 1},
        {"payment": {"keyset_id": offer.keyset_id, "amount": 17, "unit": "sat"}},
        {"payment": {"keyset_id": "00ffffffffffffff", "amount": 16, "unit": "sat"}},
    ):
        with pytest.raises(mp.ProtocolError):
            mp.check_payment_proofs(offer.proofs, manifest_for(offer, **change))
    # SIG_INPUTS, a second claim key or missing refund keys are not acceptable HTLCs.
    weak = htlc_lock(offer.hashlock, offer.claim_pub, offer.refund_pub, offer.locktime)
    weak.tags = Tags([t for t in weak.tags.root if t[0] != "sigflag"])
    with pytest.raises(mp.ProtocolError):
        mp.check_htlc_secret(weak.serialize(), mp.htlc_terms(manifest_for(offer)))
    extra = htlc_lock(offer.hashlock, offer.claim_pub, offer.refund_pub, offer.locktime)
    extra.tags["pubkeys"] = [keypair()[1]]
    with pytest.raises(mp.ProtocolError):
        mp.check_htlc_secret(extra.serialize(), mp.htlc_terms(manifest_for(offer)))
    duplicate = offer.proofs + offer.proofs[:1]
    with pytest.raises(mp.ProtocolError):
        mp.check_payment_proofs(duplicate, manifest_for(offer))


# --- NFT leg -------------------------------------------------------------------


@pytest_asyncio.fixture
async def ledger(tmp_path):
    db = Database("nft", str(tmp_path))
    led = PSLedger(db, MintPrivateKeyPS.from_seed(secrets.token_bytes(32)))
    await led.migrate()
    yield led
    await db.engine.dispose()


async def mint_nft(ledger: PSLedger) -> Credential:
    h = int.from_bytes(secrets.token_bytes(31), "big") + 1
    s = int.from_bytes(secrets.token_bytes(31), "big") + 1
    S, pok = prove_owner_secret(s)
    u, v = await ledger.issue_nft(h, S, pok)
    return Credential(u=u, v=v, h=h, s=s, keyset_id=ledger.keyset.keyset_id)


def usable(ledger: PSLedger, cred: Credential) -> bool:
    return verify_presentation(
        ledger.keyset, present(cred, binding=b"probe"), binding=b"probe"
    )


class Delivery:
    def __init__(self, cred: Credential, deadline: int):
        self.seller = cred
        self.preimage = secrets.token_bytes(32)
        self.hashlock = hashlib.sha256(self.preimage).hexdigest()
        self.mhash = hashlib.sha256(
            secrets.token_bytes(32)
        ).digest()  # stands in for the manifest
        self.s_new = int.from_bytes(secrets.token_bytes(31), "big") + 1
        self.S_new, self.receive_proof = mp.prove_receive(self.s_new, self.mhash)
        nullifier = present(cred).nullifier.format()
        self.contract = NFTContract(
            contract_id=secrets.token_hex(16),
            nullifier=nullifier,
            h=cred.h,
            hashlock=self.hashlock,
            destination=self.S_new,
            deadline=deadline,
        )

    def presentation(self):
        return present(self.seller, binding=mp.delivery_binding(self.mhash, self.S_new))


@pytest.mark.asyncio
async def test_atomic_delivery_gives_the_buyer_a_usable_credential(ledger):
    seller = await mint_nft(ledger)
    d = Delivery(seller, int(time.time()) + 3600)
    assert mp.verify_receive(d.S_new, d.receive_proof, d.mhash)
    async with ledger.db.get_connection() as conn:
        await ledger.install_lock(
            conn, d.presentation(), d.contract, mp.delivery_binding(d.mhash, d.S_new)
        )
        u, v = await ledger.claim_lock(conn, d.contract.contract_id, d.preimage)
    buyer = Credential(
        u=u, v=v, h=seller.h, s=d.s_new, keyset_id=ledger.keyset.keyset_id
    )
    assert usable(ledger, buyer)
    # The seller saw only S'; without s' the issued (u, v) is useless to them.
    assert not usable(
        ledger, Credential(u=u, v=v, h=seller.h, s=seller.s, keyset_id=seller.keyset_id)
    )
    assert await ledger.is_spent(d.contract.nullifier)
    # Lost reply: claiming again returns the exact same issuance.
    async with ledger.db.get_connection() as conn:
        assert await ledger.claim_lock(conn, d.contract.contract_id, d.preimage) == (
            u,
            v,
        )
    # And the buyer can move it on like any other NFT.
    S2, pok2 = prove_owner_secret(5)
    await ledger.transfer(present(buyer, binding=S2.format()), S2, pok2)


@pytest.mark.asyncio
async def test_delivery_rejects_wrong_binding_destination_and_preimage(ledger):
    seller = await mint_nft(ledger)
    d = Delivery(seller, int(time.time()) + 3600)
    good = mp.delivery_binding(d.mhash, d.S_new)
    other_S, _ = prove_owner_secret(7)
    async with ledger.db.get_connection() as conn:
        # A presentation meant for another destination or offer cannot lock this one.
        with pytest.raises(InvalidProofError):
            await ledger.install_lock(
                conn,
                present(seller, binding=mp.delivery_binding(d.mhash, other_S)),
                d.contract,
                good,
            )
        with pytest.raises(InvalidProofError):
            await ledger.install_lock(
                conn, present(seller, binding=b"Cashu_PS_Showing_v1"), d.contract, good
            )
    with pytest.raises(InvalidProofError):
        async with ledger.db.get_connection() as conn:
            await ledger.install_lock(conn, d.presentation(), d.contract, good)
            await ledger.claim_lock(
                conn, d.contract.contract_id, secrets.token_bytes(32)
            )
    # The failed transaction rolled back: no lock, nothing spent, credential usable.
    assert (await ledger.lock_states([d.contract.nullifier]))[0]["lock"] is None
    assert not await ledger.is_spent(d.contract.nullifier)
    S2, pok2 = prove_owner_secret(9)
    await ledger.transfer(present(seller, binding=S2.format()), S2, pok2)


@pytest.mark.asyncio
async def test_locked_credential_blocks_every_spend_route(ledger):
    seller = await mint_nft(ledger)
    d = Delivery(seller, int(time.time()) + 3600)
    binding = LOCK_BINDING + d.contract.digest()
    async with ledger.db.get_connection() as conn:
        await ledger.install_lock(
            conn, present(seller, binding=binding), d.contract, binding
        )
    S2, pok2 = prove_owner_secret(11)
    with pytest.raises(LockedError):
        await ledger.transfer(present(seller, binding=S2.format()), S2, pok2)
    with pytest.raises(LockedError):
        await ledger.burn(present(seller, binding=PS_BURN_BINDING))
    u2 = await ledger.transfer_private_begin(d.contract.nullifier)
    pres, o = present_private(ledger.keyset, seller, binding=S2.format())
    B, _t, proof = blind_transfer_commit(
        ledger.keyset, seller.h, o, pres.kappa_h, u2, binding=S2.format()
    )
    with pytest.raises(LockedError):
        await ledger.transfer_private(pres, B, proof, S2, pok2)
    other = NFTContract(**{**d.contract.__dict__, "contract_id": secrets.token_hex(16)})
    with pytest.raises(LockedError):
        async with ledger.db.get_connection() as conn:
            await ledger.install_lock(
                conn,
                present(seller, binding=LOCK_BINDING + other.digest()),
                other,
                LOCK_BINDING + other.digest(),
            )
    state = (await ledger.lock_states([d.contract.nullifier]))[0]
    assert state["state"] == "UNSPENT" and state["lock"]["state"] == "locked"


@pytest.mark.asyncio
async def test_refund_branch_only_after_deadline_and_never_restores_old_credential(
    ledger,
):
    seller = await mint_nft(ledger)
    deadline = int(time.time()) + 3600
    d = Delivery(seller, deadline)
    binding = LOCK_BINDING + d.contract.digest()
    async with ledger.db.get_connection() as conn:
        await ledger.install_lock(
            conn, present(seller, binding=binding), d.contract, binding
        )
    s_back = 13
    S_back, pok_back = prove_owner_secret(s_back)
    refund_binding = REFUND_BINDING + d.contract.digest() + S_back.format()
    async with ledger.db.get_connection() as conn:
        with pytest.raises(InvalidProofError):
            await ledger.refund_lock(
                conn,
                d.contract.contract_id,
                present(seller, binding=refund_binding),
                S_back,
                pok_back,
                now=deadline,
            )
        u, v = await ledger.refund_lock(
            conn,
            d.contract.contract_id,
            present(seller, binding=refund_binding),
            S_back,
            pok_back,
            now=deadline + 1,
        )
    back = Credential(u=u, v=v, h=seller.h, s=s_back, keyset_id=seller.keyset_id)
    assert usable(ledger, back)
    assert await ledger.is_spent(
        d.contract.nullifier
    )  # the old bearer credential is dead
    async with ledger.db.get_connection() as conn:
        with pytest.raises(AlreadySpentError):
            await ledger.claim_lock(conn, d.contract.contract_id, d.preimage)
    S3, pok3 = prove_owner_secret(15)
    with pytest.raises(AlreadySpentError):
        await ledger.transfer(present(seller, binding=S3.format()), S3, pok3)


def test_receive_proof_is_bound_to_one_manifest():
    mhash = hashlib.sha256(b"offer").digest()
    S, proof = mp.prove_receive(99, mhash)
    assert mp.verify_receive(S, proof, mhash)
    assert not mp.verify_receive(S, proof, hashlib.sha256(b"other").digest())
    # The generic issuance proof is not a receive authorization.
    S2, generic = prove_owner_secret(99)
    assert not mp.verify_receive(S2, generic, mhash)


def test_escrow_envelope_binds_manifest_and_version():
    seed = secrets.token_bytes(32)
    key = mp.EscrowKey(seed)
    assert (
        mp.EscrowKey(seed).public_key == key.public_key
    )  # derived, stable across restarts
    mhash = hashlib.sha256(b"m").digest()
    preimage = secrets.token_bytes(32)
    env = mp.seal_preimage(key.public_key, key.version, preimage, mhash)
    assert preimage.hex() not in json.dumps(env)
    assert key.open(env, mhash) == preimage
    with pytest.raises(mp.ProtocolError):
        key.open(env, hashlib.sha256(b"other").digest())
    with pytest.raises(mp.ProtocolError):
        key.open({**env, "v": "esc0"}, mhash)
    with pytest.raises(mp.ProtocolError):
        mp.EscrowKey(secrets.token_bytes(32)).open(env, mhash)
    tampered = {**env, "ct": ("0" if env["ct"][0] != "0" else "1") + env["ct"][1:]}
    with pytest.raises(mp.ProtocolError):
        key.open(tampered, mhash)


def test_receipts_are_signed_by_the_pinned_key():
    rk = mp.ReceiptKey(secrets.token_bytes(32))
    receipt = {"v": mp.RECEIPT_PROTOCOL, "offer_id": "ab" * 16, "u": "01", "v_": "02"}
    sig = rk.sign(receipt)
    assert mp.verify_receipt(receipt, sig, rk.public_key)
    assert not mp.verify_receipt({**receipt, "offer_id": "cd" * 16}, sig, rk.public_key)
    assert not mp.verify_receipt(
        receipt, sig, mp.ReceiptKey(secrets.token_bytes(32)).public_key
    )


def test_mint_url_normalization():
    assert (
        mp.normalize_mint_url("HTTPS://Mint.Minibits.Cash/Bitcoin/")
        == "https://mint.minibits.cash/Bitcoin"
    )
    assert (
        mp.normalize_mint_url("https://testnut.cashu.space")
        == "https://testnut.cashu.space"
    )
    for bad in (
        "http://mint.example",
        "https://user:pw@mint.example",
        "https://mint.example/?q=1",
        "https://mint.example/a/../b",
        "ftp://x",
    ):
        with pytest.raises(mp.ProtocolError):
            mp.normalize_mint_url(bad)
    assert (
        mp.normalize_mint_url("http://localhost:3338", allow_http=True)
        == "http://localhost:3338"
    )


# --- mint API for NFT contracts ----------------------------------------------


@pytest.mark.asyncio
async def test_lock_api_enforces_contract_on_public_routes(ledger):
    seller = await mint_nft(ledger)
    client = TestClient(create_app(ledger))
    preimage = secrets.token_bytes(32)
    s_new = 21
    S_new = G1 * s_new
    contract = NFTContract(
        contract_id=secrets.token_hex(16),
        nullifier=present(seller).nullifier.format(),
        h=seller.h,
        hashlock=hashlib.sha256(preimage).hexdigest(),
        destination=S_new,
        deadline=int(time.time()) + 600,
    )
    dest_proof = prove_dlog_eq(
        [G1], [S_new], s_new, LOCK_RECEIVE_DST, contract.digest()
    )
    body = {
        "presentation": present(seller, binding=LOCK_BINDING + contract.digest())
        .to_bytes()
        .hex(),
        "contract_id": contract.contract_id,
        "hashlock": contract.hashlock,
        "destination": S_new.format().hex(),
        "destination_proof": dest_proof.to_bytes().hex(),
        "deadline": contract.deadline,
    }
    # A destination proof for another contract is not an authorization.
    wrong = prove_dlog_eq([G1], [S_new], s_new, LOCK_RECEIVE_DST, b"other")
    assert (
        client.post(
            "/v1/nft/lock", json={**body, "destination_proof": wrong.to_bytes().hex()}
        ).status_code
        == 403
    )
    assert client.post("/v1/nft/lock", json=body).status_code == 200
    state = client.post(
        "/v1/nft/lockstate", json={"nullifiers": [contract.nullifier.hex()]}
    ).json()["states"][0]
    assert (
        state["state"] == "UNSPENT"
        and state["lock"]["state"] == "locked"
        and state["lock"]["witness"] is None
    )
    # Existing clients still see the credential as unspent, but cannot move it.
    assert (
        client.post(
            "/v1/nft/checkstate", json={"nullifiers": [contract.nullifier.hex()]}
        ).json()["states"][0]["state"]
        == "UNSPENT"
    )
    S2, pok2 = prove_owner_secret(23)
    blocked = client.post(
        "/v1/nft/transfer",
        json={
            "presentation": present(seller, binding=S2.format()).to_bytes().hex(),
            "new_owner_commitment": S2.format().hex(),
            "new_proof": pok2.to_bytes().hex(),
        },
    )
    assert blocked.status_code == 423
    assert (
        client.post(
            "/v1/nft/lock/claim",
            json={"contract_id": contract.contract_id, "preimage": "00" * 32},
        ).status_code
        == 403
    )
    claimed = client.post(
        "/v1/nft/lock/claim",
        json={"contract_id": contract.contract_id, "preimage": preimage.hex()},
    )
    assert claimed.status_code == 200
    issued = claimed.json()
    buyer = Credential(
        u=G1Point(compressed=bytes.fromhex(issued["u"]), group="G1"),
        v=G1Point(compressed=bytes.fromhex(issued["v"]), group="G1"),
        h=seller.h,
        s=s_new,
        keyset_id=ledger.keyset.keyset_id,
    )
    assert usable(ledger, buyer)
    state = client.post(
        "/v1/nft/lockstate", json={"nullifiers": [contract.nullifier.hex()]}
    ).json()["states"][0]
    assert (
        state["state"] == "SPENT"
        and state["lock"]["state"] == "claimed"
        and state["lock"]["witness"] == preimage.hex()
    )


# --- Python / TypeScript parity ---------------------------------------------


@pytest.mark.skipif(
    shutil.which("node") is None or not (WEB / "node_modules").exists(),
    reason="node frontend not installed",
)
def test_typescript_sigall_digest_and_escrow_match_python():
    key = mp.EscrowKey(secrets.token_bytes(32))
    preimage = secrets.token_bytes(32)
    mhash = hashlib.sha256(b"parity").digest()
    inputs = [
        (
            json.dumps(["HTLC", {"nonce": "aa", "data": "bb", "tags": []}]),
            "02" + "11" * 32,
        )
    ]
    outputs = [(8, "03" + "22" * 32), (2, "02" + "33" * 32)]
    # ESM resolves packages relative to the script, so run it inside the app.
    script = WEB / f".parity-{secrets.token_hex(4)}.mjs"
    script.write_text(
        f"""
import {{ SigAll }} from '@cashu/cashu-ts';
import {{ sealPreimage }} from './src/market/escrow.mjs';
const inputs = {json.dumps([{"secret": s, "C": c} for s, c in inputs])};
const outputs = {json.dumps([{"amount": a, "id": "00aa", "B_": b} for a, b in outputs])};
const digest = SigAll.computeDigests(inputs, outputs).v0;
const env = await sealPreimage('{key.public_key}', '{key.version}', Uint8Array.from(Buffer.from('{preimage.hex()}', 'hex')), Uint8Array.from(Buffer.from('{mhash.hex()}', 'hex')));
console.log(JSON.stringify({{ digest, env }}));
"""
    )
    try:
        out = subprocess.run(
            ["node", str(script)], cwd=WEB, capture_output=True, text=True, timeout=60
        )
    finally:
        script.unlink()
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["digest"] == mp.sigall_digest(inputs, outputs).hex()
    assert key.open(data["env"], mhash) == preimage

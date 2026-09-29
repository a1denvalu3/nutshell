import asyncio

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

import cashu.nft.cli as nft_cli
from cashu.core.crypto.ps import MintPrivateKeyPS
from cashu.core.db import Database
from cashu.nft.api import create_app
from cashu.nft.ledger import PSLedger
from cashu.nft.wallet import NFTClient
from cashu.wallet.cli.cli import cli


@pytest.fixture(scope="function")
def runner(tmp_path, monkeypatch):
    ledger = PSLedger(
        Database("test_nft_cli", str(tmp_path / "mint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
    )
    asyncio.run(ledger.migrate())
    app_client = NFTClient(TestClient(create_app(ledger)))
    monkeypatch.setattr(nft_cli, "_make_client", lambda url: app_client)
    monkeypatch.setattr(
        nft_cli, "_default_wallet_path", lambda: str(tmp_path / "nft.sqlite3")
    )
    return CliRunner(), tmp_path


def invoke(runner, *args, wallet=None):
    r, _ = runner
    full = ["nft"]
    if wallet:
        full += ["--wallet-db", wallet]
    full += list(args)
    result = r.invoke(cli, full, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return result.output


def test_cli_full_flow(runner, tmp_path):
    r, _ = runner
    alice = str(tmp_path / "alice.sqlite3")
    bob = str(tmp_path / "bob.sqlite3")
    asset = tmp_path / "art.jpg"
    asset.write_bytes(b"\xff\xd8 fake jpeg")

    out = invoke(runner, "init", wallet=alice)
    assert "seed (back this up):" in out
    invoke(runner, "init", wallet=bob)

    # init refuses to overwrite
    result = r.invoke(cli, ["nft", "--wallet-db", alice, "init"])
    assert result.exit_code != 0

    out = invoke(runner, "info", wallet=alice)
    assert "keyset id:" in out

    out = invoke(runner, "mint", str(asset), "-d", "art.jpg", wallet=alice)
    h_full = out.strip().split("minted: ")[1]
    assert len(h_full) == 64

    out = invoke(runner, "list", wallet=alice)
    assert h_full in out and "art.jpg" in out

    # double mint rejected by the mint
    result = r.invoke(cli, ["nft", "--wallet-db", alice, "mint", str(asset)])
    assert result.exit_code != 0

    # mint with neither file nor quote is a usage error
    result = r.invoke(cli, ["nft", "--wallet-db", alice, "mint"])
    assert result.exit_code != 0
    assert "give a file" in result.output

    # offline send alice -> bob, then bob swaps the token at the mint
    out = invoke(runner, "send", h_full[:12], wallet=alice)
    token = out.strip().splitlines()[-1]
    assert token.startswith("psnft1")
    assert "no assets" in invoke(runner, "list", wallet=alice)

    out = invoke(runner, "receive", token, "-d", "art.jpg", wallet=bob)
    assert f"received: {h_full}" in out

    out = invoke(runner, "verify", h_full[:12], wallet=bob)
    assert "credential valid: True" in out
    assert "nullifier spent: False" in out
    assert "asset status:    active" in out

    # receiving the same token twice fails: the nullifier is spent
    result = r.invoke(cli, ["nft", "--wallet-db", alice, "receive", token])
    assert result.exit_code != 0

    # private receive: bob sends offline, alice swaps with h hidden
    token2 = invoke(runner, "send", h_full[:12], wallet=bob).strip().splitlines()[-1]
    invoke(runner, "receive", token2, "--private", wallet=alice)
    out = invoke(runner, "verify", h_full[:12], wallet=alice)
    assert "nullifier spent: False" in out
    assert "asset status:    active" in out

    # burn
    out = invoke(runner, "burn", h_full[:12], wallet=alice)
    assert f"burned: {h_full}" in out
    assert "no assets" in invoke(runner, "list", wallet=alice)
    # the asset is gone from the wallet, so verify cannot resolve it anymore
    result = r.invoke(cli, ["nft", "--wallet-db", alice, "verify", h_full])
    assert result.exit_code != 0


def test_cli_wallet_not_initialized(runner, tmp_path):
    r, _ = runner
    result = r.invoke(
        cli, ["nft", "--wallet-db", str(tmp_path / "nope.sqlite3"), "list"]
    )
    assert result.exit_code != 0
    assert "nft init" in result.output


def test_cli_quote_flow(runner, tmp_path, monkeypatch):
    from cashu.nft.quotes import DevQuoteBackend

    backend = DevQuoteBackend(b"operator secret!!")
    ledger = PSLedger(
        Database("test_nft_cli_paid", str(tmp_path / "paidmint")),
        MintPrivateKeyPS.from_seed(b"test seed 012345"),
        quote_backend=backend,
    )
    asyncio.run(ledger.migrate())
    monkeypatch.setattr(
        nft_cli, "_make_client", lambda url: NFTClient(TestClient(create_app(ledger)))
    )
    r, _ = runner
    asset = tmp_path / "art.jpg"
    asset.write_bytes(b"\xff\xd8 fake jpeg")
    wallet = str(tmp_path / "payer.sqlite3")
    invoke(runner, "init", wallet=wallet)

    # minting without a quote is refused with a helpful message
    result = r.invoke(cli, ["nft", "--wallet-db", wallet, "mint", str(asset)])
    assert result.exit_code != 0
    assert "nft quote" in result.output

    out = invoke(runner, "quote", str(asset), wallet=wallet)
    quote_id = out.split("quote:  ")[1].splitlines()[0].strip()
    assert "amount: 21 sat" in out

    # still unpaid: the mint rejects it
    result = r.invoke(
        cli, ["nft", "--wallet-db", wallet, "mint", str(asset), "--quote", quote_id]
    )
    assert result.exit_code != 0

    out = invoke(
        runner, "dev-pay", quote_id, "--secret", "operator secret!!", wallet=wallet
    )
    assert "state: paid" in out
    out = invoke(runner, "mint", str(asset), "--quote", quote_id, wallet=wallet)
    assert "minted: " in out

    # second asset: mint from the settled quote alone -- no file needed,
    # the mint already knows the asset hash for the quote
    asset2 = tmp_path / "art2.jpg"
    asset2.write_bytes(b"\xff\xd8 another fake jpeg")
    out = invoke(runner, "quote", str(asset2), wallet=wallet)
    quote_id2 = out.split("quote:  ")[1].splitlines()[0].strip()
    assert "asset:  " in out
    invoke(runner, "dev-pay", quote_id2, "--secret", "operator secret!!", wallet=wallet)
    out = invoke(runner, "mint", "--quote", quote_id2, wallet=wallet)
    h2 = out.strip().split("minted: ")[1]
    assert len(h2) == 64
    out = invoke(runner, "list", wallet=wallet)
    assert h2 in out

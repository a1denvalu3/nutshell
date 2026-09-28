"""CLI for the experimental PS-credential NFT wallet.

Registered as the `nft` command group of the main cashu CLI. All state
lives in a local sqlite wallet (default: <cashu_dir>/nft.sqlite3) and on
the NFT service (default http://127.0.0.1:8338, override with --mint-url
or NFT_MINT_URL).

Typical flow:
    cashu nft init                       # create wallet, prints the seed
    cashu nft mint my.jpg                # mint an NFT for a file
    cashu nft list                       # show owned assets
    cashu nft ticket                     # receiver: print a receive ticket
    cashu nft send <h> --ticket '<json>' # sender: transfer, prints a package
    cashu nft claim '<package>'          # receiver: store the credential
    cashu nft verify <h>                 # offline ownership check
    cashu nft burn <h>                   # retire the asset
"""

import json
import os
import secrets
from typing import Optional

import click
import httpx

from ..core.crypto.bls import PublicKey
from ..core.crypto.ps import hash_asset
from ..core.settings import settings
from .payment import DevPaymentVerifier
from .wallet import NFTClient, NFTWallet

DEFAULT_MINT_URL = "http://127.0.0.1:8338"


def _default_wallet_path() -> str:
    return os.path.join(settings.cashu_dir, "nft.sqlite3")


def _open_wallet(path: str, seed: Optional[bytes] = None) -> NFTWallet:
    if seed is not None:
        return NFTWallet(path, seed=seed)
    if not os.path.exists(path):
        raise click.UsageError(f"no NFT wallet at {path} -- run `cashu nft init` first")
    return NFTWallet(path)


def _make_client(mint_url: str) -> NFTClient:
    return NFTClient(httpx.Client(base_url=mint_url, timeout=30.0))


def _resolve_h(wallet: NFTWallet, h_arg: str) -> int:
    """Resolve an asset hash argument, accepting any unique prefix of a
    locally held asset."""
    candidates = [
        a.h
        for a in wallet.assets()
        if a.h.to_bytes(32, "big").hex().startswith(h_arg.lower())
    ]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise click.UsageError(f"ambiguous asset hash prefix: {h_arg}")
    if len(h_arg) == 64:
        try:
            return int(h_arg, 16)
        except ValueError:
            pass
    raise click.UsageError(f"no local asset matching {h_arg}")


@click.group("nft", help="Experimental PS-credential NFT wallet.")
@click.option(
    "--mint-url",
    envvar="NFT_MINT_URL",
    default=DEFAULT_MINT_URL,
    help=f"NFT mint URL (default: {DEFAULT_MINT_URL}).",
)
@click.option(
    "--wallet-db",
    "wallet_db",
    default=None,
    help="Wallet database path (default: <cashu_dir>/nft.sqlite3).",
)
@click.pass_context
def nft(ctx: click.Context, mint_url: str, wallet_db: Optional[str]):
    ctx.ensure_object(dict)
    ctx.obj["NFT_MINT_URL"] = mint_url
    ctx.obj["NFT_WALLET_DB"] = wallet_db or _default_wallet_path()


@nft.command("init", help="Create the NFT wallet and print its seed.")
@click.option("--seed", "seed_hex", default=None, help="Restore from a hex seed.")
@click.pass_context
def nft_init(ctx: click.Context, seed_hex: Optional[str]):
    path = ctx.obj["NFT_WALLET_DB"]
    if os.path.exists(path):
        raise click.UsageError(f"wallet already exists at {path}")
    seed = bytes.fromhex(seed_hex) if seed_hex else secrets.token_bytes(32)
    NFTWallet(path, seed=seed)
    print(f"wallet created at {path}")
    print(f"seed (back this up): {seed.hex()}")


@nft.command("info", help="Show mint keyset information.")
@click.pass_context
def nft_info(ctx: click.Context):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    print(f"mint:             {ctx.obj['NFT_MINT_URL']}")
    print(f"keyset id:        {client.keyset_id}")
    print(f"payment required: {client.payment_required}")


@nft.command("mint", help="Mint an NFT for a file.")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--payment", "payment_hex", default=None, help="Payment ticket (hex).")
@click.option("--description", "-d", default="", help="Asset description.")
@click.pass_context
def nft_mint(
    ctx: click.Context, file: str, payment_hex: Optional[str], description: str
):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    if client.payment_required and not payment_hex:
        raise click.UsageError("this mint requires a payment ticket (--payment <hex>)")
    with open(file, "rb") as f:
        asset = f.read()
    cred = client.mint(
        wallet,
        asset,
        payment=bytes.fromhex(payment_hex) if payment_hex else None,
        description=description or os.path.basename(file),
    )
    print(f"minted: {cred.h.to_bytes(32, 'big').hex()}")


@nft.command("list", help="List owned NFTs.")
@click.pass_context
def nft_list(ctx: click.Context):
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    assets = wallet.assets()
    if not assets:
        print("no assets")
        return
    for a in assets:
        print(f"{a.h.to_bytes(32, 'big').hex()}  {a.description}")


@nft.command("ticket", help="Print a receive ticket for an incoming transfer.")
@click.pass_context
def nft_ticket(ctx: click.Context):
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    ticket = wallet.prepare_receive()
    print(
        json.dumps(
            {
                "commitment": ticket.commitment.format().hex(),
                "proof": ticket.proof.to_bytes().hex(),
            }
        )
    )


@nft.command("send", help="Transfer an NFT to a receive ticket.")
@click.argument("asset_hash", type=str)
@click.option("--ticket", "ticket_json", required=True, help="Receive ticket JSON.")
@click.option(
    "--private",
    "private",
    is_flag=True,
    default=False,
    help="Hide the asset hash from the mint.",
)
@click.pass_context
def nft_send(ctx: click.Context, asset_hash: str, ticket_json: str, private: bool):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    ticket = json.loads(ticket_json)
    commitment = bytes.fromhex(ticket["commitment"])
    proof = bytes.fromhex(ticket["proof"])
    if private:
        u, v = client.transfer_private(wallet, h, commitment, proof)
    else:
        u, v = client.transfer(wallet, h, commitment, proof)
    wallet.delete_asset(h)
    print("transferred. give this package to the receiver:")
    print(
        json.dumps(
            {
                "h": h.to_bytes(32, "big").hex(),
                "u": u.format().hex(),
                "v": v.format().hex(),
                "commitment": commitment.hex(),
                "keyset_id": client.keyset_id,
            }
        )
    )


@nft.command("claim", help="Store a credential received via `nft send`.")
@click.argument("package_json", type=str)
@click.option("--description", "-d", default="", help="Asset description.")
@click.pass_context
def nft_claim(ctx: click.Context, package_json: str, description: str):
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    package = json.loads(package_json)
    cred = wallet.claim_credential(
        commitment=bytes.fromhex(package["commitment"]),
        u=PublicKey(compressed=bytes.fromhex(package["u"]), group="G1"),
        v=PublicKey(compressed=bytes.fromhex(package["v"]), group="G1"),
        h=int(package["h"], 16),
        keyset_id=package["keyset_id"],
        description=description,
    )
    print(f"claimed: {cred.h.to_bytes(32, 'big').hex()}")


@nft.command("verify", help="Verify ownership of an NFT offline.")
@click.argument("asset_hash", type=str)
@click.pass_context
def nft_verify(ctx: click.Context, asset_hash: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    pres = wallet.present(h)
    print(f"credential valid: {client.verify(pres)}")
    try:
        entry = client.registry_entry(h)
        print(f"registered owner: {client.verify_registered_owner(pres, entry)}")
        print(f"registry epoch:   {entry['epoch']}")
    except ValueError:
        print("registered owner: asset not in registry (burned or unknown)")


@nft.command("registry", help="Show the mint-signed registry entry for an asset.")
@click.argument("asset_hash", type=str)
@click.pass_context
def nft_registry(ctx: click.Context, asset_hash: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    entry = client.registry_entry(h)
    print(json.dumps(entry, indent=2))


@nft.command("burn", help="Retire an NFT.")
@click.argument("asset_hash", type=str)
@click.pass_context
def nft_burn(ctx: click.Context, asset_hash: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    client.burn(wallet, h)
    print(f"burned: {h.to_bytes(32, 'big').hex()}")


@nft.command("pay-ticket", help="Dev only: issue a payment ticket for a file.")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--secret",
    "secret",
    envvar="NFT_PAYMENT_SECRET",
    required=True,
    help="Operator payment secret (or NFT_PAYMENT_SECRET).",
)
def nft_pay_ticket(file: str, secret: str):
    with open(file, "rb") as f:
        asset = f.read()
    ticket = DevPaymentVerifier(secret.encode()).issue_ticket(hash_asset(asset))
    print(ticket.hex())

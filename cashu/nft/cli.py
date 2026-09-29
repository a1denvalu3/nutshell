"""CLI for the experimental PS-credential NFT wallet.

Registered as the `nft` command group of the main cashu CLI. All state
lives in a local sqlite wallet (default: <cashu_dir>/nft.sqlite3) and on
the NFT service (default http://127.0.0.1:8338, override with --mint-url
or NFT_MINT_URL).

Typical flow (cashu-style, sending is offline):
    cashu nft init                       # create wallet, prints the seed
    cashu nft mint my.jpg                # mint an NFT for a file
    cashu nft quote my.jpg               # (paid mints) request a mint quote
    cashu nft mint --quote <id>          # mint once the quote is settled
    cashu nft list                       # show owned assets
    cashu nft send <h>                   # print a bearer token for the receiver
    cashu nft receive <token>            # receiver: swap the token at the mint
    cashu nft verify <h>                 # offline verify + mint spent/status check
    cashu nft show <h>                   # publish a verify-only showing
    cashu nft inspect <blob>             # third party: check a showing
    cashu nft burn <h>                   # retire the asset

The mint URL defaults to settings.mint_url (the same default as every
other cashu command); override with --mint-url or NFT_MINT_URL.
"""

import functools
import json
import os
import secrets
from typing import Optional

import click
import httpx

from ..core.settings import settings
from .quotes import DevQuoteBackend
from .wallet import NFTClient, NFTWallet

# same default the rest of the cashu CLI uses (settings.mint_url, i.e.
# http://<mint_host>:<mint_port>, 127.0.0.1:3338 unless configured)
DEFAULT_MINT_URL = settings.mint_url or "http://127.0.0.1:3338"


def _cli_errors(func):
    """Turn connection and mint errors into clean CLI messages instead of
    tracebacks."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except click.ClickException:
            raise
        except httpx.ConnectError as e:
            raise click.ClickException(
                f"cannot reach the NFT mint ({e.request.url}) -- is it running? "
                "Start it with `poetry run python -m cashu.nft` "
                "or point --mint-url elsewhere."
            )
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as e:
            raise click.ClickException(str(e))

    return wrapper


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
@_cli_errors
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
@_cli_errors
def nft_info(ctx: click.Context):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    print(f"mint:             {ctx.obj['NFT_MINT_URL']}")
    print(f"keyset id:        {client.keyset_id}")
    print(f"payment required: {client.payment_required}")
    if client.payment_required:
        print(f"mint price:       {client.mint_price_sats} sat")


@nft.command("quote", help="Request a mint quote for a file.")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
@_cli_errors
def nft_quote(ctx: click.Context, file: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    with open(file, "rb") as f:
        asset = f.read()
    quote = client.mint_quote(asset)
    print(f"quote:  {quote['quote']}")
    print(f"asset:  {quote['asset_hash']}")
    print(f"amount: {quote['amount']} sat")
    print(f"state:  {quote['state']}")
    print(f"request: {quote['request']}")


@nft.command("dev-pay", help="Dev only: settle a mint quote with the operator secret.")
@click.argument("quote_id", type=str)
@click.option(
    "--secret",
    "secret",
    envvar="NFT_PAYMENT_SECRET",
    required=True,
    help="Operator payment secret (or NFT_PAYMENT_SECRET).",
)
@click.pass_context
@_cli_errors
def nft_dev_pay(ctx: click.Context, quote_id: str, secret: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    backend = DevQuoteBackend(secret.encode())
    client.dev_pay_quote(quote_id, backend.issue_dev_ticket(quote_id))
    print(f"paid: {quote_id} (state: {client.quote_state(quote_id)})")


@nft.command("mint", help="Mint an NFT for a file, or for a settled quote.")
@click.argument("file", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--quote", "quote_id", default=None, help="Settled mint quote id.")
@click.option("--description", "-d", default="", help="Asset description.")
@click.pass_context
@_cli_errors
def nft_mint(
    ctx: click.Context, file: Optional[str], quote_id: Optional[str], description: str
):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    if client.payment_required and not quote_id:
        raise click.UsageError(
            "this mint requires a paid quote -- run `cashu nft quote <file>` first"
        )
    if file:
        with open(file, "rb") as f:
            asset = f.read()
        cred = client.mint(
            wallet,
            asset,
            quote=quote_id,
            description=description or os.path.basename(file),
        )
    else:
        if not quote_id:
            raise click.UsageError(
                "give a file to mint, or --quote to mint from a settled quote "
                "(the mint already knows the asset hash for the quote)"
            )
        quote = client.get_quote(quote_id)
        cred = client.mint_h(
            wallet,
            int(quote["asset_hash"], 16),
            quote=quote_id,
            description=description,
        )
    print(f"minted: {cred.h.to_bytes(32, 'big').hex()}")


@nft.command("list", help="List owned NFTs.")
@click.pass_context
@_cli_errors
def nft_list(ctx: click.Context):
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    assets = wallet.assets()
    if not assets:
        print("no assets")
        return
    for a in assets:
        print(f"{a.h.to_bytes(32, 'big').hex()}  {a.description}")


@nft.command("send", help="Send an NFT offline as a bearer token.")
@click.argument("asset_hash", type=str)
@click.pass_context
@_cli_errors
def nft_send(ctx: click.Context, asset_hash: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    token = client.send_token(wallet, h)
    print("send this token to the receiver (bearer instrument, keep it safe):")
    print(token)


@nft.command("receive", help="Swap a received token at the mint.")
@click.argument("token", type=str)
@click.option("--description", "-d", default="", help="Asset description.")
@click.option(
    "--public",
    "public",
    is_flag=True,
    default=False,
    help="Reveal the asset hash to the mint during the swap (default: hidden).",
)
@click.pass_context
@_cli_errors
def nft_receive(ctx: click.Context, token: str, description: str, public: bool):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    cred = client.receive(wallet, token, description=description, private=not public)
    print(f"received: {cred.h.to_bytes(32, 'big').hex()}")


@nft.command("verify", help="Verify ownership of an NFT.")
@click.argument("asset_hash", type=str)
@click.pass_context
@_cli_errors
def nft_verify(ctx: click.Context, asset_hash: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    pres = wallet.present(h)
    print(f"credential valid: {client.verify(pres)}")
    # the only unspent nullifier belongs to the current holder, so the
    # mint's spent check doubles as the ownership check -- a third party
    # shown this presentation can ask the mint the same two questions
    print(f"nullifier spent: {client.check_state(pres.nullifier.format()) == 'SPENT'}")
    print(f"asset status:    {client.asset_status(h)}")


@nft.command("show", help="Publish a verify-only showing for an NFT.")
@click.argument("asset_hash", type=str)
@click.option(
    "--context",
    "context",
    default=None,
    help="Context the showing is bound to (default: random nonce).",
)
@click.pass_context
@_cli_errors
def nft_show(ctx: click.Context, asset_hash: str, context: Optional[str]):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    blob = client.show(wallet, h, context.encode() if context else b"")
    print("showing (verify-only, bound to context; cannot be spent):")
    print(json.dumps(blob))


@nft.command("inspect", help="Third-party check of a showing blob.")
@click.argument("blob_json", type=str)
@click.pass_context
@_cli_errors
def nft_inspect(ctx: click.Context, blob_json: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    try:
        blob = json.loads(blob_json)
    except ValueError:
        raise click.UsageError("blob must be the JSON printed by `cashu nft show`")
    result = client.verify_showing_blob(blob)
    print(f"asset hash:               {result['asset_hash']}")
    print(f"signature valid:          {result['valid']}")
    print(f"publisher knows the secret: {result['valid']}")
    print(f"nullifier spent:          {result['spent']}")
    print(f"asset status:             {result['asset_status']}")


@nft.command("burn", help="Retire an NFT.")
@click.argument("asset_hash", type=str)
@click.pass_context
@_cli_errors
def nft_burn(ctx: click.Context, asset_hash: str):
    client = _make_client(ctx.obj["NFT_MINT_URL"])
    wallet = _open_wallet(ctx.obj["NFT_WALLET_DB"])
    h = _resolve_h(wallet, asset_hash)
    client.burn(wallet, h)
    print(f"burned: {h.to_bytes(32, 'big').hex()}")

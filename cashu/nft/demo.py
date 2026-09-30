"""Demo web UI for the experimental PS-NFT wallet.

    poetry run python -m cashu.nft.demo

Serves a single-page demo (cashu/nft/demo.html) plus a small JSON API that
drives two local wallets (alice/bob) against a selectable mint: an embedded
local mint (free, no quotes) or any external PS-NFT service URL. The raw NFT
API of the embedded mint is also mounted at /v1/nft.

Environment:
    NFT_DEMO_PORT  listen port (default 8400)
    NFT_DEMO_DIR   data directory (default data/nft-demo)
    NFT_DEMO_SEED  embedded mint key seed (default "demo local mint seed")
"""

import asyncio
import json
import os
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from loguru import logger
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.testclient import TestClient

from ..core.crypto.bls import curve_order
from ..core.crypto.ps import MintPrivateKeyPS
from ..core.db import Database
from .api import create_app, create_router
from .ledger import PSLedger
from .wallet import NFTClient, NFTWallet

LOCAL_MINT_ID = "local"
WALLETS = ["alice", "bob"]
DEMO_HTML = os.path.join(os.path.dirname(__file__), "demo.html")


class Demo:
    """Holds the demo state: embedded mint, wallet files, external mints."""

    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.data_dir = data_dir
        self.lock = threading.Lock()

        self.seeds = self._load_or_create_seeds()
        for name in WALLETS:
            path = self._wallet_path(name)
            if not os.path.exists(path):
                wallet = NFTWallet(path, seed=bytes.fromhex(self.seeds[name]))
                wallet.db.close()

        seed = os.environ.get("NFT_DEMO_SEED", "demo local mint seed")
        self.ledger = PSLedger(
            Database("demo_local", os.path.join(data_dir, "mint")),
            MintPrivateKeyPS.from_seed(seed.encode()),
            quote_backend=None,
        )
        asyncio.run(self.ledger.migrate())

        self.mints: List[Dict[str, str]] = self._load_mints()
        self.clients: Dict[str, NFTClient] = {
            LOCAL_MINT_ID: NFTClient(TestClient(create_app(self.ledger)))
        }

    # --- persistence --------------------------------------------------

    def _load_or_create_seeds(self) -> Dict[str, str]:
        path = os.path.join(self.data_dir, "seeds.json")
        if os.path.exists(path):
            with open(path) as f:
                return dict(json.load(f))
        seeds = {name: os.urandom(32).hex() for name in WALLETS}
        with open(path, "w") as f:
            json.dump(seeds, f, indent=2)
        return seeds

    def _load_mints(self) -> List[Dict[str, str]]:
        path = os.path.join(self.data_dir, "mints.json")
        if os.path.exists(path):
            with open(path) as f:
                return list(json.load(f))
        return []

    def _save_mints(self) -> None:
        with open(os.path.join(self.data_dir, "mints.json"), "w") as f:
            json.dump(self.mints, f, indent=2)

    def _wallet_path(self, name: str) -> str:
        return os.path.join(self.data_dir, f"{name}.sqlite3")

    # --- helpers ------------------------------------------------------

    @contextmanager
    def open_wallet(self, name: str) -> Iterator[NFTWallet]:
        """Open a wallet for one operation. sqlite3 connections are bound
        to the creating thread, so wallets are opened (and closed) inside
        the worker thread that uses them."""
        if name not in self.seeds:
            raise HTTPException(400, f"unknown wallet: {name}")
        wallet = NFTWallet(self._wallet_path(name))
        try:
            yield wallet
        finally:
            wallet.db.close()

    def client(self, mint_id: str) -> NFTClient:
        if mint_id in self.clients:
            return self.clients[mint_id]
        mint = next((m for m in self.mints if m["id"] == mint_id), None)
        if mint is None:
            raise HTTPException(404, f"unknown mint: {mint_id}")
        try:
            client = NFTClient(httpx.Client(base_url=mint["url"], timeout=30.0))
        except Exception as e:
            raise HTTPException(400, f"cannot reach mint {mint['url']}: {e}")
        self.clients[mint_id] = client
        return client

    @staticmethod
    def parse_h(raw: str) -> int:
        try:
            h = int(raw, 16)
        except ValueError:
            raise HTTPException(400, "h must be hex")
        if len(raw) != 64 or not 0 <= h < curve_order:
            raise HTTPException(400, "h must be a 64-hex-char scalar")
        return h

    # --- operations (blocking; run via run_in_threadpool) --------------

    def state(self) -> Dict[str, Any]:
        mints = [
            {"id": LOCAL_MINT_ID, "name": "local (embedded)", "url": ""}
        ] + list(self.mints)
        return {
            "mints": [{**m, **self._mint_info(m["id"])} for m in mints],
            "wallets": list(WALLETS),
        }

    def _mint_info(self, mint_id: str) -> Dict[str, Any]:
        try:
            client = self.client(mint_id)
        except HTTPException:
            return {"unreachable": True}
        return {
            "keyset_id": client.keyset_id,
            "payment_required": client.payment_required,
            "mint_price_sats": client.mint_price_sats,
        }

    def add_mint(self, name: str, url: str) -> Dict[str, Any]:
        if not name or not url:
            raise HTTPException(400, "name and url are required")
        url = url.rstrip("/")
        mint = {"id": uuid.uuid4().hex[:8], "name": name, "url": url}
        try:
            client = NFTClient(httpx.Client(base_url=url, timeout=30.0))
        except Exception as e:
            raise HTTPException(400, f"cannot reach mint {url}: {e}")
        self.mints.append(mint)
        self.clients[mint["id"]] = client
        self._save_mints()
        return {**mint, **self._mint_info(mint["id"])}

    def remove_mint(self, mint_id: str) -> Dict[str, str]:
        if mint_id == LOCAL_MINT_ID:
            raise HTTPException(400, "cannot remove the local mint")
        mint = next((m for m in self.mints if m["id"] == mint_id), None)
        if mint is None:
            raise HTTPException(404, f"unknown mint: {mint_id}")
        self.mints.remove(mint)
        client = self.clients.pop(mint_id, None)
        if client is not None:
            client.http.close()
        self._save_mints()
        return {"status": "removed"}

    def assets(self, wallet: str, mint_id: str) -> List[Dict[str, Any]]:
        client = self.client(mint_id)
        with self.lock, self.open_wallet(wallet) as w:
            assets = w.assets()
        result = []
        for a in assets:
            try:
                status = client.asset_status(a.h)
            except Exception:
                status = "unknown"
            result.append(
                {
                    "h": a.h.to_bytes(32, "big").hex(),
                    "description": a.description,
                    "asset_status": status,
                }
            )
        return result

    def mint(
        self,
        wallet: str,
        mint_id: str,
        description: str,
        asset: bytes,
        quote: Optional[str],
    ) -> Dict[str, Any]:
        client = self.client(mint_id)
        if client.payment_required and not quote:
            raise HTTPException(400, "this mint requires a paid quote")
        with self.lock, self.open_wallet(wallet) as w:
            cred = client.mint(w, asset, quote=quote, description=description)
        return {
            "h": cred.h.to_bytes(32, "big").hex(),
            "description": description,
        }

    def quote(self, mint_id: str, asset: bytes) -> Dict[str, Any]:
        client = self.client(mint_id)
        if not client.payment_required:
            return {"state": "free"}
        return client.mint_quote(asset)  # type: ignore[no-any-return]

    def quote_state(self, mint_id: str, quote_id: str) -> Dict[str, Any]:
        return self.client(mint_id).get_quote(quote_id)  # type: ignore[no-any-return]

    def send(self, wallet: str, mint_id: str, h: int) -> Dict[str, str]:
        client = self.client(mint_id)
        with self.lock, self.open_wallet(wallet) as w:
            token = client.send_token(w, h)
        return {"token": token}

    def receive(
        self, wallet: str, mint_id: str, token: str, description: str, public: bool
    ) -> Dict[str, str]:
        client = self.client(mint_id)
        with self.lock, self.open_wallet(wallet) as w:
            cred = client.receive(w, token, description=description, private=not public)
        return {"h": cred.h.to_bytes(32, "big").hex()}

    def show(self, wallet: str, mint_id: str, h: int, context: str) -> Dict[str, str]:
        client = self.client(mint_id)
        with self.lock, self.open_wallet(wallet) as w:
            token = client.show(w, h, context.encode() if context else b"")
        return {"token": token}

    def inspect(self, mint_id: str, token: str) -> Dict[str, Any]:
        client = self.client(mint_id)
        try:
            return client.verify_showing_token(token)  # type: ignore[no-any-return]
        except ValueError as e:
            raise HTTPException(400, str(e))

    def verify(self, wallet: str, mint_id: str, h: int) -> Dict[str, Any]:
        client = self.client(mint_id)
        with self.lock, self.open_wallet(wallet) as w:
            pres = w.present(h)
        return {
            "valid": client.verify(pres),
            "spent": client.check_state(pres.nullifier.format()) == "SPENT",
            "asset_status": client.asset_status(h),
        }

    def burn(self, wallet: str, mint_id: str, h: int) -> Dict[str, str]:
        client = self.client(mint_id)
        with self.lock, self.open_wallet(wallet) as w:
            client.burn(w, h)
        return {"status": "burned"}


async def _asset_payload(
    request: Request,
) -> Tuple[Dict[str, Any], bytes]:
    """Read an asset operation body: either multipart (file upload and/or
    text field) or JSON with a "text" field. Returns (fields, asset)."""
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        file = form.get("file")
        text = form.get("text")
        if isinstance(file, UploadFile) and file.filename:
            asset = await file.read()
        elif text:
            asset = str(text).encode()
        else:
            raise HTTPException(400, "give text or upload a file")
        fields = {k: str(v) for k, v in form.items() if isinstance(v, str)}
        return fields, asset
    fields = dict(await request.json())
    text = fields.get("text", "")
    if not text:
        raise HTTPException(400, "give text or upload a file")
    return fields, str(text).encode()


def create_demo_app(data_dir: str) -> FastAPI:
    demo = Demo(data_dir)
    app = FastAPI(title="cashu PS-NFT demo")
    app.include_router(create_router(demo.ledger), prefix="/v1/nft", tags=["NFT"])

    @app.get("/")
    async def index():
        return FileResponse(DEMO_HTML)

    @app.get("/api/state")
    async def get_state():
        return await run_in_threadpool(demo.state)

    @app.post("/api/mints")
    async def add_mint(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.add_mint, str(body.get("name", "")), str(body.get("url", ""))
        )

    @app.delete("/api/mints/{mint_id}")
    async def remove_mint(mint_id: str):
        return await run_in_threadpool(demo.remove_mint, mint_id)

    @app.get("/api/assets")
    async def get_assets(wallet: str, mint: str):
        return await run_in_threadpool(demo.assets, wallet, mint)

    @app.post("/api/mint")
    async def post_mint(request: Request):
        fields, asset = await _asset_payload(request)
        return await run_in_threadpool(
            demo.mint,
            str(fields.get("wallet", "")),
            str(fields.get("mint", "")),
            str(fields.get("description", "")),
            asset,
            fields.get("quote") or None,
        )

    @app.post("/api/quote")
    async def post_quote(request: Request):
        fields, asset = await _asset_payload(request)
        return await run_in_threadpool(demo.quote, str(fields.get("mint", "")), asset)

    @app.get("/api/quote/{mint_id}/{quote_id}")
    async def get_quote(mint_id: str, quote_id: str):
        return await run_in_threadpool(demo.quote_state, mint_id, quote_id)

    @app.post("/api/send")
    async def post_send(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.send,
            str(body.get("wallet", "")),
            str(body.get("mint", "")),
            Demo.parse_h(str(body.get("h", ""))),
        )

    @app.post("/api/receive")
    async def post_receive(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.receive,
            str(body.get("wallet", "")),
            str(body.get("mint", "")),
            str(body.get("token", "")),
            str(body.get("description", "")),
            bool(body.get("public", False)),
        )

    @app.post("/api/show")
    async def post_show(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.show,
            str(body.get("wallet", "")),
            str(body.get("mint", "")),
            Demo.parse_h(str(body.get("h", ""))),
            str(body.get("context", "")),
        )

    @app.post("/api/inspect")
    async def post_inspect(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.inspect, str(body.get("mint", "")), str(body.get("token", ""))
        )

    @app.post("/api/verify")
    async def post_verify(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.verify,
            str(body.get("wallet", "")),
            str(body.get("mint", "")),
            Demo.parse_h(str(body.get("h", ""))),
        )

    @app.post("/api/burn")
    async def post_burn(request: Request):
        body = await request.json()
        return await run_in_threadpool(
            demo.burn,
            str(body.get("wallet", "")),
            str(body.get("mint", "")),
            Demo.parse_h(str(body.get("h", ""))),
        )

    return app


def main() -> None:
    data_dir = os.environ.get("NFT_DEMO_DIR", "data/nft-demo")
    port = int(os.environ.get("NFT_DEMO_PORT", "8400"))
    logger.info(f"PS-NFT demo on http://127.0.0.1:{port} (data: {data_dir})")
    uvicorn.run(create_demo_app(data_dir), host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()

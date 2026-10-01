"""Network boundary for server-side calls to payment mints chosen by users.

Payment mint URLs come from buyers, so every request from the settlement
worker goes through ``GuardedMintClient``:

* HTTPS only, except explicitly configured development mints;
* DNS is resolved here and every address must be public (no private,
  loopback, link-local, metadata, CGNAT, multicast or reserved ranges);
* the connection goes to the validated IP while TLS keeps the original host
  for SNI and certificate checks, so a second DNS answer cannot rebind it;
* no redirects, bounded response bodies and timeouts.

This protects the worker's network position. It is not a mint allowlist:
sellers still decide whether to trust each offer's mint.
"""

import asyncio
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional
from urllib.parse import urlsplit

import httpx

from .market_protocol import ProtocolError, normalize_mint_url

MAX_BODY = 512 * 1024
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


class BlockedDestination(ProtocolError):
    """The mint URL points at a destination the worker must not contact."""


def is_public_address(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4 and ip in SHARED_ADDRESS_SPACE:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


@dataclass
class MintNetPolicy:
    """``dev_mints`` are exact normalized URLs allowed over plain HTTP to
    local addresses; empty in production."""

    dev_mints: FrozenSet[str] = field(default_factory=frozenset)
    max_body: int = MAX_BODY

    def check_url(self, url: str) -> str:
        if url in self.dev_mints:
            return url
        return normalize_mint_url(url)


class GuardedResponse:
    def __init__(self, status_code: int, body: bytes):
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return json.loads(self._body)


async def _resolve(host: str, port: int) -> List[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise httpx.ConnectError(f"cannot resolve {host}") from exc
    return sorted({str(info[4][0]) for info in infos})


class GuardedMintClient:
    """Drop-in for the subset of ``httpx.AsyncClient`` the settlement code
    uses (``post``/``get`` returning ``status_code`` and ``json()``)."""

    def __init__(self, policy: Optional[MintNetPolicy] = None):
        self.policy = policy or MintNetPolicy()
        self._client = httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=False, trust_env=False
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "GuardedMintClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def _target(self, url: str) -> Dict[str, Any]:
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}{parts.path.rsplit('/v1/', 1)[0]}"
        dev = base in self.policy.dev_mints
        if not dev:
            self.policy.check_url(base)
            if parts.scheme != "https":
                raise BlockedDestination("mint URL must use https")
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses = await _resolve(host, port)
        if not addresses:
            raise BlockedDestination("mint host has no address")
        if not dev and not all(is_public_address(a) for a in addresses):
            # Reject if any answer is internal: a mixed answer is a rebinding attempt.
            raise BlockedDestination("mint host resolves to a non-public address")
        ip = addresses[0]
        literal = f"[{ip}]" if ":" in ip else ip
        pinned = parts._replace(netloc=f"{literal}:{port}").geturl()
        return {"url": pinned, "host": parts.netloc, "sni": host}

    async def _send(
        self, method: str, url: str, body: Optional[Dict[str, Any]]
    ) -> GuardedResponse:
        target = await self._target(url)
        request = self._client.build_request(
            method,
            target["url"],
            json=body,
            headers={"Host": target["host"], "Accept": "application/json"},
            extensions={"sni_hostname": target["sni"]},
        )
        response = await self._client.send(request, stream=True)
        try:
            if 300 <= response.status_code < 400:
                raise BlockedDestination("mint redirects are not followed")
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > self.policy.max_body:
                    raise httpx.ReadError("mint response too large")
                chunks.append(chunk)
            return GuardedResponse(response.status_code, b"".join(chunks))
        finally:
            await response.aclose()

    async def post(
        self, url: str, json: Optional[Dict[str, Any]] = None
    ) -> GuardedResponse:
        return await self._send("POST", url, json)

    async def get(self, url: str) -> GuardedResponse:
        return await self._send("GET", url, None)

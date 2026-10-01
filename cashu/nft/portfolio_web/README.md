# Cashu NFT portfolio

A multiuser web app for minting JPGs as PS NFT credentials, showing them on a
public profile, and passing them on as transfer JPGs. It is separate from the
Alice/Bob demo (`python -m cashu.nft`, port 8400) and keeps its own data.

## Run it locally

```bash
# 1. Build the frontend (from cashu/nft/portfolio_web)
npm ci
npm run build

# 2. Start the app (from the repository root)
poetry install
poetry run python -m cashu.nft.portfolio
```

Open <http://127.0.0.1:8401>. For frontend development, run `npm run dev` in
this directory; Vite proxies `/api` and `/v1` to the backend on port 8401.

| Variable | Default | Purpose |
|---|---|---|
| `NFT_PORTFOLIO_DIR` | `data/nft-portfolio` | Database and persisted mint seed |
| `NFT_PORTFOLIO_HOST` / `NFT_PORTFOLIO_PORT` | `127.0.0.1` / `8401` | Listen address |
| `NFT_PORTFOLIO_MAX_JPG_BYTES` | 10 MB | Upload limit per JPG |
| `NFT_PORTFOLIO_MAX_CARDS` | 100 | Active NFTs per profile |
| `NFT_PORTFOLIO_MAX_STORAGE_BYTES` | 1 GB | Total image storage |
| `NFT_PORTFOLIO_TRUSTED_PROXY` | unset | Reverse proxy address (e.g. `127.0.0.1`) whose `X-Forwarded-For` is trusted for rate limiting |
| `VITE_MINT_KEYSET_ID` (build time) | unset | Pin the expected mint keyset in the bundle |

Back up `NFT_PORTFOLIO_DIR`: the mint seed in it defines the mint's identity.
Losing it invalidates every issued credential; replacing it makes browsers that
already pinned the old keyset refuse to load the app.

## Tests

```bash
npm test                                          # browser verifier vs Python-generated showings
npm run typecheck                                # browser wallet types
poetry run pytest tests/test_nft_portfolio.py -q  # backend
```

## Trust model

- **Profile keys** are secp256k1 keys generated and kept in the browser's local
  storage. They never reach the server. There is no reset: lose the key and you
  lose the profile. Use "Back up key", and "Import key" on another browser.
- **Browser custody.** The browser constructs blind issuance and private
  transfer proofs, unblinds signatures, generates public showings, and
  embeds or extracts JPG bearer tokens. Spending secrets are encrypted in
  local IndexedDB and in mint backups using AES-256-GCM. HKDF derives a
  separate encryption key from the profile private key and mint keyset;
  associated data binds the collector, keyset and card or operation. The
  backend stores public JPGs, public proofs and ciphertext. Owner requests
  require single-use Schnorr authorization. Exporting never asks the backend
  for a plaintext credential; receiving uploads only the clean JPG.
- **Recovery.** Importing the same profile key recovers encrypted credentials
  from the mint. Encrypted operation backups are saved before issuance or
  transfer. Exact retries return the same cached signature after connection
  loss or restart. Issued jobs must be recovered; only unissued expired jobs
  or lost transfer races can be discarded. Browser Web Locks serialize
  operations across tabs. Keep a private backup of your profile key.
- **Existing collections.** On opening an owner profile, legacy cards rotate
  through private transfers to new browser secrets before saving encrypted
  credentials. Their card IDs, pictures and titles remain. The previous
  backend-known credential becomes spent, including older transfer JPGs.
- **Issuer and frontend trust.** Encryption prevents spending by a backend
  that has only stored records and public proofs. The issuer can still forge
  credentials, and malicious JavaScript served by the host can steal an
  unlocked key. Browser custody does not remove those trust assumptions.
- **Ownership proofs.** Each card carries a PS showing bound to
  `(profile pubkey, JPG hash, keyset)` and a profile-key signature over that
  showing. Visitors verify both in their browser, then ask the mint whether the
  showing's nullifier is still unspent. Outcomes: "Verified owner",
  "Transferred" (spent), "Verification unavailable" (mint unreachable) and
  "Verification failed" (invalid proof).
- **Mint identity** is pinned on first visit (trust on first use) in local
  storage, or at build time with `VITE_MINT_KEYSET_ID`. The page itself is
  served by the mint, so a malicious server could also serve a different
  verifier; the pin protects against a keyset swap, not a compromised host.

## JPG identity and transfers

The browser wallet uses [blind hash issuance](../BLIND_ISSUANCE.md).
The mint checks a public deterministic duplicate tag instead of receiving
the raw hash scalar in that issuance call. The portfolio still knows the
public JPG and its hash; spending secrets remain in the browser.

## cashu-ts and Coco integration

The frontend pins cashu-ts `5.0.0-rc.11` and Coco core/IndexedDB `2.0.0`.
An npm override makes Coco use the same cashu-ts release. The `cashu-ps-nft`
Coco plugin registers `manager.ext.nft`, uses Coco's durable counters and a
profile/keyset-derived 64-byte seed, and keeps encrypted NFT records in a
separate IndexedDB vault. Normal ecash watchers and processors are disabled
because this app serves PS NFT endpoints.

cashu-ts supplies BLS scalar generation and strict subgroup point decoding.
The extension adds PS commitments, proof transcripts, unblinding,
presentations, private swaps and EXIF transfer tokens. PS credentials are
not standard NUT-00 proofs or cashu tokens; ordinary cashu-ts wallet methods
cannot spend them. This remains an experimental cryptographic extension.

For an isolated backend during frontend testing, set `NFT_PORTFOLIO_API` to
its URL when starting Vite. The production bundle always uses same-origin
routes. The previous custodial mint/receive/export/cancel HTTP endpoints
return `410`; use the signed `/api/profiles/{pubkey}/wallet/…` workflow.

## JPG handling

- Uploads must be JPGs. Before minting, the app applies EXIF orientation,
  removes EXIF/XMP, keeps the colour profile, and hashes the resulting bytes.
  Exact byte duplicates cannot be minted twice; visually identical images with
  different bytes can.
- "Download transfer JPG" embeds the bearer token in a dedicated EXIF segment.
  The card stays in the collection as "Transfer ready".
- Receiving strips only that segment, checks the remaining bytes against the
  credential's asset hash, then redeems. The first successful redemption wins;
  the sender's card moves to the public Sent shelf.
- "Cancel transfer" rotates the credential, invalidating every exported
  transfer JPG.
- Send the **original file**. Screenshots, edits, recompression or metadata
  stripping (common in chat apps) break the transfer.
- Public image downloads and "Download public proof" never contain the token.

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
| `VITE_MINT_KEYSET_ID` (build time) | unset | Pin the expected mint keyset in the bundle |

Back up `NFT_PORTFOLIO_DIR`: the mint seed in it defines the mint's identity.
Losing it invalidates every issued credential; replacing it makes browsers that
already pinned the old keyset refuse to load the app.

## Tests

```bash
npm test                                          # browser verifier vs Python-generated showings
poetry run pytest tests/test_nft_portfolio.py -q  # backend
```

## Trust model

- **Profile keys** are secp256k1 keys generated and kept in the browser's local
  storage. They never reach the server. There is no reset: lose the key and you
  lose the profile. Use "Back up key", and "Import key" on another browser.
- **Custody.** The mint stores each JPG and the bearer credential that owns it.
  Owner actions (mint, receive, export, cancel, claim signing) require a
  Schnorr signature from the profile key over a single-use server challenge.
  The operator could still move NFTs; this app does not protect against a
  malicious mint.
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

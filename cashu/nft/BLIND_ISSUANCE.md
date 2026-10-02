# Hash-hidden NFT issuance

The Python NFT wallet and portfolio browser wallet send a deterministic
commitment to the JPG hash scalar `h`, rather than the scalar itself. New
issuance takes one request and response, with no asset blinding factor or
unblinding step. Global byte-identity uniqueness remains enforced by the
existing public duplicate tag; there is no independent tag service.

## Protocol

All scalars are in BLS12-381 Fr. `G_ASSET` is a domain-separated hash-to-G1
point, distinct from the signature generator `G1` and owner nullifier base
`G_NULL`. Public parameters and the final credential format are unchanged.

1. The wallet chooses a random 16-byte request ID (the `session` field),
   calculates `h = hash_asset(canonical JPG)` and chooses its owner secret `s`.
   Using the published `Y_h1 = y_h G1`, it constructs:

   ```text
   D = h G_ASSET
   C = h Y_h1
   S = s G1
   ```

   A noninteractive multi-witness Schnorr proof establishes knowledge of `h`
   and `s` satisfying all three equations. The same `h` must open both the
   duplicate tag and commitment. Its Fiat–Shamir transcript binds the request
   ID, keyset, points, bases and witness indices under
   `Cashu_PS_CommittedIssue_v3`. The proof has two witnesses, with no `t`.
   Proof randomness is still fresh; the asset commitment is deterministic.
2. One `POST /v1/nft/mint/private` sends `version: 3`, `session`, `asset_tag`
   (`D`), `b` (`C`), `owner_commitment` (`S`), the proof and an optional paid
   quote ID. There is no `/begin` request or preallocated issuance base.
   Neither `h`, `s` nor JPG bytes are sent to this endpoint.
3. The mint verifies the proof, consumes any paid quote and inserts the tag
   into the shared uniqueness registry. It chooses a fresh secret `k` and
   returns the finished credential signature:

   ```text
   u = k G1
   v = k (x G1 + C + y_s S) = (x + y_h h + y_s s) u
   ```

   The wallet verifies `(u, v)` against its local `h, s` and public mint key
   before storing it. No unblinding occurs. Mint-chosen signature randomness
   and the proofs of knowledge remain essential.
4. The full response and exact request digest are persisted in the same
   transaction as payment and duplicate registration. A `v3:` prefix isolates
   these receipts from older protocol versions. Exact retries recover the
   original bytes after restart; they do not issue a second NFT. Changing the
   request after successful issuance fails. Failed proof, payment or duplicate
   checks do not consume the request ID or payment.

A fresh request for a previously minted hash fails, even with a different
owner, request ID, protocol version or mint key. Burned assets also remain in
the duplicate registry. The key-independent `D` preserves uniqueness across
mint key rotations; `C` alone would change when `Y_h1` changes.

This uses the PS signing-committed-messages approach; see
[Pointcheval–Sanders, section 6.1](https://eprint.iacr.org/2015/525.pdf).
Payment quotes, key discovery, portfolio JPG uploads, encrypted backups and
publication are separate from the single cryptographic issuance exchange.

## Compatibility and recovery

`/info` advertises `committed_issuance_versions: [3]` and the supported legacy
`blind_issuance_versions: [1, 2]`. An omitted request version still selects
version 1. New wallets explicitly request version 3.

Existing randomized issuance remains supported for older clients and saved
operations. Version 1 uses `/begin`, `B = h u + t G1` and removes `t Y_h1`.
Version 2 uses `C = h Y_h1 + t G1` and removes `t u`. Their proof domains,
receipt namespaces and recovery rules are unchanged. All issuance versions,
including legacy clear-h issuance, share the duplicate registry.

Before issuance, the wallet saves its original request and owner-secret
recovery material. Version 3 requires no blinding material. The Python wallet
can list pending operations with `cashu nft retry-mint`, then recover one with
`cashu nft retry-mint <session>`. Browser wallets recover through encrypted
operation backups. Existing records containing `t` still use their original
unblinding rule. Recovery material is retired only after storing the credential.

Quotes use `POST /v1/nft/mint/private/quote` with `asset_tag`. The CLI keeps the
hash locally so a later `mint --quote` can work without re-reading the file.
Previously created clear-h quotes remain redeemable.

Existing `ps_asset_tags` and `ps_issue_sessions` tables suffice; no additional
schema migration is required. Startup retains legacy asset records, including
burned assets. Images, collections, mint keys and spent nullifiers are unchanged.

## Privacy boundary

Recovering an arbitrary scalar `h` from `C = h Y_h1` requires solving a discrete
logarithm. This hides the raw scalar, not the identity of known images: both
`C` and `D` are deterministic and permit offline candidate-JPG matching. This
is intentional. The mint could already perform that matching through `D` in
the randomized protocol, so randomizing `C` offered no protection against it.

The portfolio receives and hosts the public JPG and therefore knows its hash.
Public showings and public transfers also reveal `h`. Private transfers keep
their existing randomized hiding commitments and do not send the issuance tag;
this simplification applies only to issuance.

Browser wallet credentials remain encrypted at the portfolio backend. The
owner's spending secret never enters that backend during new minting or
receiving. See [the browser wallet documentation](portfolio_web/README.md)
for recovery and the distinction between encrypted portfolio storage and trust
in the NFT issuer or browser-served code.

These experimental cryptographic changes require human review before
production use.

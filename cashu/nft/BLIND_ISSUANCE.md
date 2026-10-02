# Blind NFT issuance

The Python NFT wallet and the portfolio's browser wallet use blind issuance
of the JPG hash scalar `h`. Global byte-identity uniqueness remains enforced by
a public deterministic duplicate tag. There is no independent tag service.

## Protocol

All scalars are in BLS12-381 Fr. `G_ASSET` is a domain-separated hash-to-G1
point, distinct from the signature generator `G1` and owner nullifier base
`G_NULL`. The mint's existing public parameters and credential format do not
change.

1. The wallet chooses a random 16-byte request ID (the `session` field),
   calculates `h = hash_asset(canonical JPG)`, and chooses its owner secret
   `s` and fresh blinding scalar `t`. Using the published `Y_h1 = y_h G1`:

   ```text
   D = h G_ASSET
   C = h Y_h1 + t G1
   S = s G1
   ```

   A noninteractive multi-witness Schnorr proof establishes knowledge of
   `h, t, s` satisfying all three equations. Its Fiat–Shamir transcript binds
   the request ID, keyset, points, bases and witness indices under
   `Cashu_PS_BlindIssue_v2`. The duplicate tag and commitment must contain
   the same hash. Fresh randomness makes `C` different for each attempt.
2. One `POST /v1/nft/mint/private` sends `version: 2`, `session`, `asset_tag`
   (`D`), `b` (`C`), `owner_commitment` (`S`), the proof and an optional paid
   quote ID. There is no `/begin` request or preallocated issuance base.
   Neither `h`, `s`, `t` nor JPG bytes are sent to this endpoint.
3. The mint verifies the proof, consumes any paid quote and inserts the tag
   into the shared uniqueness registry. It chooses a fresh secret `k` and
   returns:

   ```text
   u = k G1
   v_raw = k (x G1 + C + y_s S)
   ```

   The full response `(u, v_raw)` and exact request digest are persisted in
   the same transaction as payment and duplicate registration. A `v2:`
   prefix isolates these durable receipts from legacy session IDs. An exact
   retry returns the original bytes, including after restart; changing the
   request after successful issuance fails. Failed proof, payment or duplicate
   checks do not consume the request ID or payment. A fresh request for a hash
   that was already minted fails, regardless of owner, blinding or API version.
4. The wallet unblinds locally and verifies before storing the credential:

   ```text
   v = v_raw - t u = (x + y_h h + y_s s) u
   ```

This is the signing-committed-messages construction from
[Pointcheval–Sanders, section 6.1](https://eprint.iacr.org/2015/525.pdf), adapted
with the existing owner commitment and duplicate-tag equality proof. The mint
still controls signature randomness; the client does not choose the base.
Payment quotes, key discovery, portfolio JPG uploads, encrypted backups and
publication are separate from this single cryptographic issuance exchange.

Public showing, public transfer, private transfer, EXIF bearer tokens and
burning continue to use the existing credential format and proofs. Public
showings and public transfers reveal `h`; private transfers do not send this
issuance tag and keep their existing hiding commitments.

## Payment and compatibility

New wallet quotes use `POST /v1/nft/mint/private/quote` with `asset_tag` only.
Quote responses expose the tag rather than the hash. The CLI saves the hash
in its local wallet so a later `mint --quote` can work without re-reading the
file. A different wallet must supply the original file if it lacks that
local quote metadata.

Before sending issuance, the wallet persists the original request, secret
index and blinding value locally. If a response is lost, run
`cashu nft retry-mint` to list pending sessions, then
`cashu nft retry-mint <session>` to recover the original signature. Recovery
material is deleted in the same local transaction that stores the credential.
Minting a new request for the same JPG does not recover the old signature.

Legacy clear-h and two-request blind issuance remain available for existing
clients and pending operations. An omitted `version` selects the original
blind protocol; `/info` advertises `blind_issuance_versions: [1, 2]`. Old saved
wallet jobs retain their original unblinding rule (`v_raw - t Y_h1`). All
issuance versions share the same tag registry, preventing a
duplicate from bypassing the policy through the older endpoint. Previously
created clear-h quotes remain redeemable.

Startup ensures `ps_asset_tags` and `ps_issue_sessions` exist, and imports legacy
`ps_assets` rows, including burned rows, into the tag registry. Existing
credentials, spent nullifiers, images, collections and mint keys are retained.
Repeated startup does not overwrite tag status or resurrect burned assets.
Legacy hash records are retained as history; this does not erase hashes
previously disclosed to the mint.

## Privacy and custody

`D` is deterministic and publicly computable. The mint can recognize equal
hashes, test candidate JPGs offline, and link a public hash disclosure to its
issuance tag. This construction hides the raw scalar in issuance; it does
not provide anonymity for publicly known images.

The portfolio receives and hosts the public JPG, so it still knows its hash.
Its browser wallet constructs the blind commitments, unblinds the signatures,
and stores only authenticated encrypted credentials at the backend. Private
spending secrets never enter the backend during new minting or receiving.
See [the browser wallet documentation](portfolio_web/README.md) for recovery,
legacy migration, and the distinction between an encrypted portfolio backend
and trust in the issuer or in code served to the browser.

These are experimental cryptographic and schema changes requiring human
review before production use.

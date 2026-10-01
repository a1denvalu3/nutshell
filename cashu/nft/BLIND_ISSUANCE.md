# Blind NFT issuance

The Python NFT wallet and the portfolio's browser wallet use blind issuance
of the JPG hash scalar `h`. Global byte-identity uniqueness remains enforced by
a public deterministic duplicate tag. There is no independent tag service.

## Protocol

All scalars are in BLS12-381 Fr. `G_ASSET` is a domain-separated hash-to-G1
point, distinct from the signature generator `G1` and owner nullifier base
`G_NULL`. The mint's existing public parameters and credential format do not
change.

1. The wallet asks `POST /v1/nft/mint/private/begin` for a mint-controlled base
   `u = k G1`. The response contains a random 16-byte session ID, `u` and the
   keyset ID. The mint derives `k` using HMAC with a dedicated issuance domain
   and stores the session. Unused sessions expire after five minutes.
2. The wallet calculates `h = hash_asset(canonical JPG)`, chooses its owner
   secret `s` and fresh blinding scalar `t`, and constructs:

   ```text
   D = h G_ASSET
   B = h u + t G1
   S = s G1
   ```

   A single multi-witness Schnorr proof establishes knowledge of `h, t, s`
   satisfying all three equations. Its Fiat–Shamir transcript binds the
   session, keyset, points, bases and witness indices under a dedicated
   issuance domain. This prevents substituting a duplicate tag, owner, base
   or session.
3. `POST /v1/nft/mint/private` sends `session`, `asset_tag` (`D`), `b` (`B`),
   `owner_commitment` (`S`), the proof and an optional payment quote ID. It
   sends neither `h`, `s`, `t` nor JPG bytes. The mint verifies the proof,
   atomically consumes the session and any paid quote, inserts the tag in
   the uniqueness registry, and signs:

   ```text
   v_raw = x u + y_h B + (k y_s) S
   ```

   Each session may sign at most once, even for another asset or owner.
   Failed payment, proof or duplicate checks do not consume the session
   or payment. A valid session cannot be used with a user-chosen base.
   The exact original request can retrieve the cached signature, including
   after restart or expiry. Changing any request field is rejected after
   the session signs; retries never generate another signature.
4. The wallet unblinds and verifies before storing the credential:

   ```text
   v = v_raw - t Y_h1 = (x + y_h h + y_s s) u
   ```

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

Before completing issuance, the wallet persists the original request, secret
index and blinding value locally. If a response is lost, run
`cashu nft retry-mint` to list pending sessions, then
`cashu nft retry-mint <session>` to recover the original signature. Recovery
material is deleted in the same local transaction that stores the credential.
Minting a new request for the same JPG does not recover the old signature.

Legacy clear-h issuance and quote routes remain available for existing
clients. Both issuance routes share the same tag registry, preventing a
duplicate from bypassing the policy through the older endpoint. Previously
created clear-h quotes remain redeemable.

Startup adds `ps_asset_tags` and `ps_issue_sessions`, and imports all legacy
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

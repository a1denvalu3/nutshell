# Cashu NFT marketplace implementation plan

Implement a marketplace where collectors list JPG NFTs and receive funded offers
in ordinary Cashu ecash. Buyers may go offline after funding an offer. A seller
can later accept it, deliver the NFT to the buyer's preauthorized wallet, and
receive the ecash. Background workers execute narrowly authorized claims and
refunds; wallet spending keys remain with their owners.

This is the agreed implementation handoff following the planning interview.
The user approved all product decisions below. The marketplace itself has not
been implemented. Baseline: `feature/ps-nft-credentials`, commit `b3ebde0b`.
Reinspect the current branch before editing and preserve subsequent work.

## Execute in this order

1. Prove the offline settlement and refund constructions with protocol tests.
2. Implement NFT spend conditions and durable mint settlement receipts.
3. Implement the encrypted ordinary ecash wallet and recovery journal.
4. Implement listings, funded offers, settlement workers and notifications.
5. Build marketplace and wallet UI using the existing design system.
6. Complete failure, recovery, interoperability and browser acceptance tests.

The first step is a gate: write the precise transcripts and adversarial tests
before building marketplace screens. If offline delivery requires additional
trust, a weaker ownership guarantee, or exposing wallet secrets beyond this
plan, stop that protocol path and report the concrete incompatibility. Resolve
routine implementation choices autonomously within the approved design.

## Approved product behavior

| Area | Decision |
| --- | --- |
| Listings | Owners choose individual JPGs and set a positive integer asking price in sats. |
| Offers | Fund the offer when submitted. Amount must meet or exceed the ask applicable when the offer is created. Offers above ask are allowed. |
| Payment mints | Accept offers from any technically compatible mint. There is no seller-configured mint allowlist. The seller decides whether to trust each offer's mint when accepting. |
| Amount semantics | Ask and offer mean net seller proceeds. Buyer pays required funding and redemption fees, displayed before funding. No marketplace fee in v1. |
| Competing offers | Multiple funded offers per NFT; at most one accepted settlement can consume that NFT. Losing offers enter the refund flow. Early cooperative refunds are deferred. |
| Expiry | Default offer lifetime is 24 hours. Acceptance closes one hour before the cash refund deadline. Show both timestamps. |
| Offline buyer | Buyer may close the browser after the offer is fully funded, its recovery data is saved, and its refund job is registered. Acceptance does not require the buyer to reconnect. |
| Automatic refunds | A durable background executor submits the buyer's pre-signed refund after expiry and retries failures. The browser also recovers/submits the same operation when reopened. |
| Notifications | Private in-app inbox, unread badge and live updates while open; recover missed events on return. Email, web push and external messaging are deferred. |
| Privacy | Asking prices are public. Completed-sale activity shows NFT, buyer, seller and time. Actual offer amount, payment mint and settlement details are participant-only API data. |
| Wallet | Per-mint balances, token receive, Lightning top-up, token send/export and Lightning withdrawal. No automatic exchange between mints or mixed-mint payment within one offer. |
| Recovery | Same profile private key unlocks encrypted wallet and swap backups. Recovery requires the encrypted records; a seed alone is insufficient for every pending swap. |

An offer's signed terms remain immutable. Editing an ask affects new offers
only; existing offers retain their original terms. Unlisting stops new offers
and declines pending offers, whose locked funds still follow their refund
schedule. Disable listing edits once an acceptance is reserved until it either
settles or safely recovers.

Listing first rotates the NFT credential, invalidating previously exported
JPGs and transfer links. Preserve the card ID, image and collection history.
Disable ordinary export/send while listed; owners unlist before sending.
Listing is not itself the buyer-specific NFT HTLC. That contract is created
for the selected offer during acceptance.

## Trust and atomicity contract

Use **NFT-mint-assisted settlement**, not a claim of a generic trustless
two-party cross-mint swap. The NFT issuer already controls NFT issuance; this
design additionally trusts it to withhold an escrowed preimage until the
specified NFT is irrevocably delivered to the buyer's fixed destination.
An issuer that leaks the secret early to a seller can violate that ordering.

The marketplace relay receives no unrestricted ecash signing keys, NFT owner
secrets, output secrets or output blinding factors. Public-key encryption of
the preimage is specifically to the NFT issuer's settlement service, not to
an arbitrary marketplace relay. Use separate, versioned encryption keys and
authenticated envelopes from a reviewed construction. Bind the offer manifest,
recipient and key version, and authenticate/pin service and receipt keys with
the NFT mint identity. Define key retention/rotation for outstanding jobs.

Both issuers must enforce their advertised protocols. Settlement still relies
on the ecash mint being reachable before its refund deadline. Background
execution and long margins improve availability; they cannot guarantee payment
through arbitrary mint outages or misconduct. A mint-confirmed NFT delivery
and a mint-confirmed cash claim are separate facts and must be tracked as such.

The refund deadline enables a competing refund spend; it does not invalidate
the receiver's claim path. Only a confirmed spend establishes which path won.
Never equate a backend timer or an offer status with refunded money.

## Protocol gate and funded offer construction

Specify canonical, versioned terms including offer/listing IDs and revision,
asset hash and current NFT nullifier, both profile identities, NFT mint/keyset,
payment mint and sat unit, net price and exact proof/fee budget, hashlock,
claim/refund keys, deadlines, and the fixed buyer NFT destination. Parties sign
the relevant complete manifests with explicit purpose/domain separation.
IDs, amounts, URLs, keys and byte encodings must be unambiguous.

1. Buyer generates fresh 32-byte `r` and `H = SHA256(r)` for this offer only.
   Each competing offer has an independent secret. The cash HTLC has seller
   claim pubkey, buyer refund pubkey, `H`, cash deadline and `SIG_ALL`.
2. Buyer prepares a fresh NFT owner commitment and proof of knowledge. Bind
   the receive authorization to this NFT and exact destination; it is not a
   reusable authorization to spend or acquire arbitrary assets.
3. Persist encrypted funding intent, counters and complete output recovery
   material before spending the buyer's ordinary ecash. Fund the HTLC using
   cashu-ts and preserve change through the normal wallet accounting path.
4. From the actual issued HTLC proofs, construct and pre-sign a refund into
   fixed buyer-controlled blinded outputs, net of applicable refund fees.
   Save full recovery data encrypted. Register the restricted executor job
   durably before displaying the offer as fully submitted and safe to leave.
5. Encrypt `r` to the NFT issuer, authenticated against the complete offer
   manifest. Issuer validates it matches `H`. Offer inspection, failed
   registration, logging, lock preparation and losing-offer paths never expose
   the plaintext. An escrow-valid receipt does not reveal the secret.
6. Persist the funded offer, delivery authorization, encrypted recovery and
   executor receipt idempotently. A crash between funding and registration is
   a recoverable incomplete offer, not a reason to create new outputs blindly.

The gate must prove that the buyer can later recover the exact usable NFT
credential. Current PS private reissuance couples the old holder's proof with
the output blinding. Design the required blinding cooperation explicitly:
the seller must be able to prove the transfer, and the buyer must retain the
correct unblinding material, without disclosing the buyer's new owner secret.
A signature nominally addressed to the buyer but impossible to unblind is not
delivery. Test this using the actual Python and TypeScript implementations.

## Seller acceptance and offline delivery

1. Seller reviews the mint URL, test-value status, net amount, fees and times.
   Adding a mint to the buyer's wallet does not make it trusted by the seller.
   Capability-check and verify authentic HTLC proofs/DLEQ where applicable,
   units, keysets, amounts, conditions and live `UNSPENT` state. State lookup
   alone is not proof that a supplied signature is genuine.
2. Atomically reserve this listing/current NFT for one offer. Recheck its
   identity, signed revision and availability; serialize competing accepts.
   The seller prepares the NFT transfer to the buyer's fixed destination and
   a pre-signed, fixed-output ecash claim. Persist seller recovery material and
   register the cash-claim job before NFT delivery can commit.
3. Install a buyer-specific NFT HTLC: same `H`, buyer claim authorization,
   seller refund authorization and a shorter NFT deadline. The exact timeout
   and clock-skew margins are protocol-gate outputs. Enforce a strict safety
   gap before the cash deadline, within the approved one-hour acceptance
   cutoff; do not silently reduce that cutoff.
4. NFT issuer validates ownership, conditions and both parties' narrowly bound
   authorizations. Atomically consume the locked NFT nullifier, issue to the
   fixed buyer destination, and save the complete recoverable issuance result,
   delivery receipt and pending collection projection.
5. Expose `r` only after that durable commit. Use the NFT mint's authoritative
   witness/receipt endpoint, backed by a transactional outbox if work crosses
   process boundaries. HTTP disconnects and publishing failures cannot erase
   delivery or cause premature release.
6. Seller or executor appends the committed preimage to the pre-signed ecash
   claim and submits it. On confirmed payment, update balances, mark the sale
   complete and emit its public event. Keep retryable payment failures visible
   as payment pending, with escalation as the refund deadline approaches.
7. Buyer sees the NFT immediately as **Purchased · awaiting wallet sync**.
   On reopening, recover/unblind and verify the credential, save it encrypted,
   then publish the ordinary buyer-signed ownership showing. A mint delivery
   receipt does not receive the existing **Verified owner** badge.

Installing and satisfying the NFT contract may occur in one mint transaction,
or through a durable intermediate lock. Choose during the protocol gate and
test every resulting interruption boundary. Losing offers never release their
preimages. Before delivery, failed acceptance may be released only after the
mint confirms there is no unresolved NFT lock or possible outstanding claim.

## NFT spending conditions

Use a mint-enforced contract registry keyed by the credential's current
nullifier. Preserve existing PS credential/signature wire formats and the
invariant that the JPG hash remains constant through transfers. Return a signed
contract receipt binding all conditions and verify contract state online.

Enforcement belongs inside the transaction that consumes the nullifier.
Unify checks for public transfer, private transfer, burn, portfolio rotation,
migration and all other spend routes. Marketplace API checks alone are
insufficient. Ordinary JPG/link redemption must also obey the lock.

Claim requires the correct preimage and buyer authorization bound to contract,
mint/keyset, branch and complete allowed destination/request. Refund requires
seller authorization after the NFT refund time. Both terminal paths spend
the old nullifier and issue a fresh credential. Never remove an expired lock
and make its original bearer credential spendable again.

Store durable terminal witnesses and exact-request issuance receipts. Preserve
existing checkstate clients while providing explicit lock/outcome information
to new wallets. A locked but unspent NFT must not appear freely transferable.

## Background claims and refunds

Executor jobs contain only locked inputs, fixed blinded output amounts/points,
required signatures, allowed execution times, mint/keyset policy and operation
identity. Full serialized swap previews contain private output material and
belong only in encrypted owner recovery records.

Use output-bound `SIG_ALL`, not input-only signatures. Current NUT-11 binds
input secrets/signatures and output amounts/blinded points; witness preimage
is outside that digest. Consequently a seller can sign the exact cash claim
before preimage release, and a buyer can sign a refund before it is executable.
The mint still enforces the deadline.

Pinned cashu-ts helpers reject signing with a refund-only key before timeout.
A small reviewed adapter may use `SigAll.computeDigests`, `signDigest` and
the correct witness placement for advance authorization. Test it against
real verifier behavior; do not falsify the clock or weaken normal validation.

Jobs need durable leases, bounded retries/backoff, idempotency, receipt storage,
startup recovery, and an independent browser recovery path. Restore lost
responses using saved blinded outputs and tested NUT-09 support. NUT-19 HTTP
caching is optional and can be short-lived; it is not long-term recovery.

Keyset ID is outside the current `SIG_ALL` output digest. A relay may adapt
only to a supported active output keyset with the same curve/unit and identical
amounts/blinded points. Verify actual returned keyset and signatures during
recovery. Any required change to input set, output amounts or blinded points
needs new owner authorization; report **Refund needs wallet attention** when
safe automatic execution is no longer possible.

Expired, declined and losing offers all use the same refund mechanism. Jobs
must determine actual mint outcomes when refund and claim race. Show refund
pending during outages and refunded only after confirmed execution. Refunds
can incur mint fees, so returning less than the originally debited total is
possible and must be explained before funding.

## Ordinary ecash wallet

Build on cashu-ts `5.0.0-rc.11` and Coco `2.0.0`; preserve the project's override
and verify ordinary-wallet compatibility, not just existing NFT-plugin tests.
Coco's shipped send handlers cover default/P2PK and reject HTLC payment
requests. Implement a dedicated HTLC coordinator with supported proof/counter
reservation seams; do not cast an HTLC into the P2PK handler.

Keep money-wallet seed derivation and storage versioned and profile-scoped,
independent of the NFT mint keyset. Preserve existing NFT derivation and
backups. Derive separate keys/domains for encryption, ordinary wallet state
and operation authorizations.

Stock Coco IndexedDB stores proof secrets and keypair secrets in plaintext,
including secret-derived primary keys. Implement an encrypted repository
boundary, with suitable opaque lookup indexes, before claiming encrypted
local persistence. Decrypted spend material may exist in the unlocked wallet's
memory. Profile keys retain the existing local-browser storage model; do not
claim this protects against malicious same-origin JavaScript.

Back up proofs/change, quotes and required quote keys, mint discovery data,
counter reservations, HTLC keys/preimages, output blindings, complete operation
previews, signed terms and receipts. Commit encrypted intent before each remote
spend and reconcile exact outputs before retrying. Deterministic seed restore
does not reconstruct every custom HTLC or random swap secret.

Web Locks cover tabs only. Add a defined multi-device synchronization and
reservation strategy for proofs/counters and backup revisions, so two devices
cannot unknowingly allocate the same outputs or treat reserved proofs as
available. Enable the necessary Coco quote/proof watchers and processors with
explicit start, unlock, visibility, reconnect and disposal behavior.

Balances are per mint and distinguish available, offer-locked, pending claim
and pending refund. Offer prices are net seller amounts; calculate funding,
redemption and refund fees from actual input keysets/proof decompositions.
Use checked integer arithmetic and respect mint limits.

## Mint selection and networking

| Choice | URL |
| --- | --- |
| Default test mint | `https://testnut.cashu.space` |
| Minibits | `https://mint.minibits.cash/Bitcoin` |
| Coinos | `https://mint.coinos.io` |
| Macadamia | `https://mint.macadamia.cash` |

Also accept a custom mint URL. These are discovery shortcuts, not an endorsement
or a permanent capability guarantee. Testnut uses fake value and automatically
paid test invoices: label **test sats** distinctly in balances, offers and
seller confirmation, even though its protocol unit is `sat`.

Check capabilities and browser connectivity when adding a mint and before
funding. Marketplace eligibility requires the HTLC/pubkey and exact SIG_ALL
semantics, authenticity verification, proof-state and recovery support used by
this protocol. An ordinary wallet may support mints ineligible for trading.
Advertised NUT support alone does not prove the deployed SIG_ALL revision;
use a documented compatibility/conformance policy and fail closed on unknown
or incompatible enforcement. The initial observed real/test mint keysets use
ordinary secp256k1 ecash; NFT BLS support is a separate requirement.

Update the existing `connect-src 'self'` CSP deliberately for browser HTTPS/WSS
mint access and retain the other protections. Handle CORS, unavailable sockets
and polling fallback. Preserve valid URL path prefixes such as `/Bitcoin`.
Normalize mint identity consistently and reject credentials in URLs.

Custom URLs also reach the server-side worker. Apply SSRF defenses to every
fetch/redirect and DNS resolution: production HTTPS, no private/loopback/link-
local/metadata destinations or DNS-rebinding bypass, bounded bodies/timeouts
and mint count. Local test mints use an explicit development-only configuration.
This is not a seller mint allowlist; it protects the worker's network boundary.

## Application integration

Preserve the latest frontend, social discovery, activity feeds, encrypted links
and dropdown stacking fixes. Add a marketplace browse/filter/detail flow and
owner list/edit/unlist actions. Offers show amount, full mint identity,
test-value label, relevant deadlines and precise state before acceptance.

Add **Profile** in the top bar with Wallet, My collection and Offers/unread
badge. On collection pages place Explore, Activity and How it works in that
dropdown. Preserve the front page's existing navigation and appearance.
Provide a discoverable Market entry without removing its current links.
Keep product labels in sentence case.

Use authenticated event delivery with durable cursors for offers, notifications
and wallet operations, with batched polling fallback. Current 15-second visible
collection polling and the global API rate limit are not a settlement engine.
Reconnect from stored state and mint outcomes rather than assuming events were
received. Public feeds must whitelist sale fields; private payloads, proofs,
mint/amount details and recovery material must not leak through existing
explore/activity/profile/OG endpoints.

## State and module boundaries

Keep NFT ownership, listing visibility, funded-offer disposition, NFT delivery
and cash settlement as separate durable facts. Avoid one overloaded `status`.
Useful state dimensions are:

- Listing: draft, active, reserved, sold, unlisted, stale.
- Offer: preparing, funded, acceptance reserved, declined, acceptance closed.
- NFT leg: unlocked, locked, delivered, refund pending, refunded.
- Cash leg: locked, claim pending, claimed, refund pending, refunded, needs attention.
- Buyer publication: awaiting wallet sync, verified showing published.

Every transition names its actor, authorization, transaction boundary, retry
key and authoritative evidence. Funded never means paid; deadline reached never
means refunded; delivery never by itself means seller cash received. Reserve
once per current NFT and use compare-and-swap/revision checks across workers.

Add dedicated listing/offer/contract/job/event/recovery records with migration
and restart tests. Existing card states are only owned/ready/sent; `ready` means
exported bearer, not escrow. Adapt reconciliation so locks and refunds are not
misclassified as completed sales. Public activity currently synthesizes rows;
add durable sale events with deduplication and explicit privacy projections.

| Existing area | Implementation responsibility |
| --- | --- |
| `cashu/core/crypto/ps.py`, `cashu/nft/ledger.py`, `api.py` | Purpose-bound authorizations, all-route condition enforcement, issuance and witness receipts. |
| `portfolio.py`, `portfolio_wallet.py` | App wiring, auth/CSP, lock-aware reconciliation, encrypted recovery and offline delivery projection. |
| `portfolio_social.py`, `portfolio_links.py` | Sale activity/privacy; invalidate stale exports/links through credential rotation. |
| New marketplace/settlement modules | Listings, offers, admission checks, atomic acceptance, escrow service boundary, worker/outbox and inbox. |
| `portfolio_web/src/wallet/` | Stable ordinary-wallet service, encrypted Coco storage, HTLC adapter, preauthorization and recovery. |
| `src/main.jsx`, `social.jsx`, `ui.jsx`, `style.css` | Profile navigation, marketplace, wallet, offers, notifications and pending-proof states. |

Keep HTTP/UI handling separate from the swap state machine and crypto adapters.
Keep the issuer's preimage escrow separate from the unprivileged relay job
executor, even when initially deployed in one application.

## Acceptance tests and delivery criteria

The implementation is complete when the following are automated or, for live
third-party compatibility, accompanied by explicit reproducible evidence:

- Buyer funds an offer, closes every browser, seller accepts later, worker
  completes payment, and buyer reopens to recover the usable NFT and publish
  its verified showing. Neither backend nor seller learns buyer wallet keys.
- Buyer closes every browser; an unaccepted, declined or losing offer expires;
  worker refunds to fixed buyer outputs; reopening recovers the actual net
  balance without manual intervention.
- Two simultaneous accepts can deliver one NFT exactly once. Losing offer
  secrets remain unreleased. Price edits and unlisting honor signed revisions.
- Preimage escrow validates hash/manifest and never leaks before delivery,
  including rejected requests, transaction rollback, logs and status APIs.
- Wrong preimage, keys, mint, unit, amount, deadline, destination, signature
  transcript or malformed/forged proofs fail before irreversible delivery.
- Every legacy spend route, burn, direct API call, exported JPG and encrypted
  link obeys NFT contracts. Listing rotation invalidates old exports; both
  terminal NFT branches invalidate the old credential permanently.
- Fault injection at every spend/commit/response boundary demonstrates exact
  retry and recovery across browser/server restart, lost replies, duplicate
  events, lease loss and multiple tabs/devices.
- Claim/refund races, exact deadlines, clock skew, unsupported SIG_ALL, fee and
  keyset changes, CORS failures and mint outages produce honest recoverable
  states, never fabricated success or redirected outputs.
- Local and remote stored spending material is encrypted; public serializers
  expose only intended fields. Executor payloads cannot alter destinations.
  Test custom-URL SSRF, redirect and DNS-rebinding defenses.
- Existing NFT mint/receive/send/cancel, public verification, encrypted links,
  social features and recovery remain functional.
- Browser coverage exercises wallet token/Lightning receive and withdrawal,
  per-mint/test-value balances, list/offer/accept/refund, notification reconnect,
  offline purchase projection and profile navigation on desktop/mobile.

Use fake/local mints for deterministic failure and clock tests. Validate the
external test mint flow separately. Do not spend real funds as an unattended
test. Record capability observations as dated evidence, not permanent facts.

Run relevant NFT/marketplace Python tests, frontend tests/typecheck/build, and
repository lint/type/format hooks. Supply migrations, setup/worker instructions,
protocol transcripts, tested recovery procedures and a concise review of the
new security-sensitive logic. Follow repository human-review requirements for
cryptography and schema changes before production rollout.

## Protocol references

- [NUT-14 HTLCs](https://github.com/cashubtc/nuts/blob/main/14.md)
- [NUT-11 pubkey conditions and SIG_ALL](https://github.com/cashubtc/nuts/blob/main/11.md)
- [NUT-07 proof state and witnesses](https://github.com/cashubtc/nuts/blob/main/07.md)
- [NUT-09 restore](https://github.com/cashubtc/nuts/blob/main/09.md)
- [NUT-02 keysets and input fees](https://github.com/cashubtc/nuts/blob/main/02.md)
- [NUT-12 signature proofs](https://github.com/cashubtc/nuts/blob/main/12.md)
- [NUT-13 deterministic secrets](https://github.com/cashubtc/nuts/blob/main/13.md)
- [NUT-19 request caching](https://github.com/cashubtc/nuts/blob/main/19.md)
- [cashu-ts rc.11](https://github.com/cashubtc/cashu-ts/releases/tag/v5.0.0-rc.11)
- [Coco](https://github.com/cashubtc/coco)

Consult the installed package source and current primary specifications during
the protocol gate. Capability/type names and compatibility observations above
were inspected during planning; they are not substitutes for interoperability
tests of the final implementation.

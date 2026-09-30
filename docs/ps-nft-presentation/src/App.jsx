import React, { useState, useCallback, useEffect } from 'react'
import { WireSizeChart } from './Charts'
import MathTex from './MathTex'

const TITLE = 'PS-NFT Credentials'

// Exact path data from the skill references (sentry-logo.svg / sentry-glyph.svg)
const GLYPH_PATH =
  'M29,2.26a4.67,4.67,0,0,0-8,0L14.42,13.53A32.21,32.21,0,0,1,32.17,40.19H27.55A27.68,27.68,0,0,0,12.09,17.47L6,28a15.92,15.92,0,0,1,9.23,12.17H4.62A.76.76,0,0,1,4,39.06l2.94-5a10.74,10.74,0,0,0-3.36-1.9l-2.91,5a4.54,4.54,0,0,0,1.69,6.24A4.66,4.66,0,0,0,4.62,44H19.15a19.4,19.4,0,0,0-8-17.31l2.31-4A23.87,23.87,0,0,1,23.76,44H36.07a35.88,35.88,0,0,0-16.41-31.8l4.67-8a.77.77,0,0,1,1.05-.27c.53.29,20.29,34.77,20.66,35.17a.76.76,0,0,1-.68,1.13H40.6q.09,1.91,0,3.81h4.78A4.59,4.59,0,0,0,50,39.43a4.49,4.49,0,0,0-.62-2.28Z'
const LOGO_WORDMARK_PATH =
  'M124.32,28.28,109.56,9.22h-3.68V34.77h3.73V15.19l15.18,19.58h3.26V9.22h-3.73ZM87.15,23.54h13.23V20.22H87.14V12.53h14.93V9.21H83.34V34.77h18.92V31.45H87.14ZM71.59,20.3h0C66.44,19.06,65,18.08,65,15.7c0-2.14,1.89-3.59,4.71-3.59a12.06,12.06,0,0,1,7.07,2.55l2-2.83a14.1,14.1,0,0,0-9-3c-5.06,0-8.59,3-8.59,7.27,0,4.6,3,6.19,8.46,7.52C74.51,24.74,76,25.78,76,28.11s-2,3.77-5.09,3.77a12.34,12.34,0,0,1-8.3-3.26l-2.25,2.69a15.94,15.94,0,0,0,10.42,3.85c5.48,0,9-2.95,9-7.51C79.75,23.79,77.47,21.72,71.59,20.3ZM195.7,9.22l-7.69,12-7.64-12h-4.46L186,24.67V34.78h3.84V24.55L200,9.22Zm-64.63,3.46h8.37v22.1h3.84V12.68h8.37V9.22H131.08ZM169.41,24.8c3.86-1.07,6-3.77,6-7.63,0-4.91-3.59-8-9.38-8H154.67V34.76h3.8V25.58h6.45l6.48,9.2h4.44l-7-9.82Zm-10.95-2.5V12.6h7.17c3.74,0,5.88,1.77,5.88,4.84s-2.29,4.86-5.84,4.86Z'

function SentryLogo({ width = 180 }) {
  return (
    <svg viewBox="0 0 200 44" width={width} fill="none" aria-hidden="true">
      <path fill="currentColor" d={LOGO_WORDMARK_PATH} />
      <path fill="currentColor" d={GLYPH_PATH} />
    </svg>
  )
}

function SentryGlyph({ size = 32 }) {
  return (
    <svg viewBox="0 0 72 66" width={size} height={size} aria-hidden="true">
      <path d={GLYPH_PATH} transform="translate(11, 11)" fill="#181225" />
    </svg>
  )
}

/* ─────────────────────────── Slides ─────────────────────────── */

const SlideTitle = () => (
  <div className="title-block d1">
    <div className="title-logo">
      <SentryLogo width={190} />
    </div>
    <h1>PS-NFT: Pointcheval–Sanders credentials for asset-bound NFTs</h1>
    <p className="subtitle">
      Pairing-based anonymous credentials on BLS12-381 — as implemented in
      Nutshell (<span className="mi">cashu/core/crypto/ps.py</span>,{' '}
      <span className="mi">cashu/nft/</span>)
    </p>
    <div className="title-meta">
      September 2026 · experimental branch <code>feature/ps-nft-credentials</code>
    </div>
  </div>
)

const SlideIdea = () => (
  <>
    <h2>The idea in one slide</h2>
    <p className="subtitle d1">
      One credential per asset. Verifiable by <strong>anyone</strong> via a
      pairing — no mint secret needed. Operations feel like ecash.
    </p>
    <div className="cards d2">
      <div className="card">
        <h3>
          <span className="material-symbols-outlined">generating_tokens</span>
          Mint — <code>nft mint</code>
        </h3>
        <p>
          Bind an asset id <MathTex tex={'h'} /> and an owner secret{' '}
          <MathTex tex={'s'} /> into a PS credential. One credential per asset,
          enforced by the mint.
        </p>
      </div>
      <div className="card">
        <h3>
          <span className="material-symbols-outlined">swap_horiz</span>
          Swap — <code>nft send</code> / <code>nft receive</code>
        </h3>
        <p>
          Hand over an offline bearer token; the receiver does a two-round
          blind swap. The mint never learns which asset moved.
        </p>
      </div>
      <div className="card">
        <h3>
          <span className="material-symbols-outlined">local_fire_department</span>
          Burn — <code>nft burn</code>
        </h3>
        <p>
          Tombstone the asset: the nullifier is spent and{' '}
          <MathTex tex={'h'} /> is marked burned. Reveals{' '}
          <MathTex tex={'h'} /> by necessity.
        </p>
      </div>
      <div className="card">
        <h3>
          <span className="material-symbols-outlined">visibility</span>
          Show — <code>nft show</code> / <code>nft inspect</code>
        </h3>
        <p>
          Publish a purpose-bound, unspendable proof of ownership a third party
          can verify offline + one mint query.
        </p>
      </div>
    </div>
  </>
)

const SlideSetup = () => (
  <>
    <h2>Setup and keys</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'e : G_1 \\times G_2 \\to G_T \\qquad e(a\\cdot P,\\ b\\cdot Q) = e(P, Q)^{a\\cdot b}'}
      />
      <MathTex
        display
        tex={'\\text{sk} = (x,\\ y_h,\\ y_s) \\qquad \\text{pk} = (X_2,\\ Y_{h2},\\ Y_{s2}) = (x\\cdot g_2,\\ y_h\\cdot g_2,\\ y_s\\cdot g_2)'}
      />
    </div>
    <div className="cards d2">
      <div className="card">
        <h3>BLS12-381, type-3 pairing</h3>
        <p>
          Groups <MathTex tex={'G_1, G_2'} /> of prime order{' '}
          <MathTex tex={'r'} />, generators{' '}
          <MathTex tex={'g_1, g_2'} />, target group{' '}
          <MathTex tex={'G_T'} /> — and no efficient isomorphism between{' '}
          <MathTex tex={'G_1'} /> and <MathTex tex={'G_2'} />.
        </p>
      </div>
      <div className="card">
        <h3>Credential attributes</h3>
        <p>
          <MathTex tex={'h = \\text{SHA-256}(\\text{asset}) \\bmod r'} /> — the
          asset id — and <MathTex tex={'s'} /> — the owner secret, never
          revealed anywhere.
        </p>
      </div>
    </div>
    <div className="callout purple d3">
      <strong>
        The <MathTex tex={'y'} /> values exist in <MathTex tex={'G_2'} />{' '}
        only, by construction.
      </strong>{' '}
      If <MathTex tex={'y_h'} /> were available in <MathTex tex={'G_1'} />,
      anyone could compute <MathTex tex={'u^{y_h}'} /> in{' '}
      <MathTex tex={'G_1'} /> and rescale a credential to a different asset —
      the exponent-rescaling forgery. The type-3 asymmetry is what makes
      withholding possible while verification still works.
    </div>
  </>
)

const SlideMinting = () => (
  <>
    <h2>Minting</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            <code>nft init</code>, then <code>nft quote &lt;file&gt;</code> →
            BOLT11 invoice via the hosting ecash mint (NUT-04-style) → pay →{' '}
            <code>nft mint --quote &lt;id&gt;</code>. On free mints:{' '}
            <code>nft mint &lt;file&gt;</code>. The file is only needed at
            quote time.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            Wallet sends{' '}
            <MathTex tex={'(h,\\ S = s\\cdot g_1,\\ \\text{PoK of } s)'} />.
            The mint checks the proof, checks <MathTex tex={'h'} /> was never
            minted, consumes the quote atomically, picks{' '}
            <MathTex tex={'k'} /> and sets <MathTex tex={'u = k\\cdot g_1'} />.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <div className="math small">
            <MathTex
              display
              tex={'v = (x + y_h\\cdot h)\\cdot u + (k\\cdot y_s)\\cdot S = (x + y_h\\cdot h + y_s\\cdot s)\\cdot u'}
            />
          </div>
          <p>
            The DH trick —{' '}
            <MathTex
              tex={'S^{k\\cdot y_s} = (s\\cdot g_1)^{k\\cdot y_s} = s\\cdot y_s\\cdot u'}
            />{' '}
            — binds <MathTex tex={'s'} /> without the mint learning it. The
            wallet stores <MathTex tex={'(u,\\ v,\\ h,\\ s)'} />.
          </p>
        </div>
      </div>
    </div>
    <div className="callout d2">
      <strong>
        Why <MathTex tex={'h'} /> is revealed at mint, by design:
      </strong>{' '}
      one credential per asset — the mint must see <MathTex tex={'h'} /> to
      reject duplicates.
    </div>
  </>
)

const SlideAnatomy = () => (
  <>
    <h2>The credential and its presentations</h2>
    <div className="cards three d1">
      <div className="card">
        <h3>Credential — 193 B</h3>
        <p>
          <MathTex tex={'(u,\\ v,\\ h,\\ s)'} /> + keyset id. Never leaves the
          wallet except inside a bearer token.
        </p>
      </div>
      <div className="card">
        <h3>Public presentation — 321 B</h3>
        <p>
          <MathTex tex={"(h,\\ u',\\ v',\\ U_s,\\ N,\\ \\pi)"} /> — reveals
          the asset id <MathTex tex={'h'} />. Used by{' '}
          <code>--public</code> swaps and burns.
        </p>
      </div>
      <div className="card">
        <h3>Private presentation — 401 B</h3>
        <p>
          <MathTex
            tex={"(u',\\ v',\\ U_h,\\ U_s,\\ N,\\ \\pi_h,\\ \\pi_s)"}
          />{' '}
          — <MathTex tex={'h'} /> stays hidden. The default swap.
        </p>
      </div>
    </div>
    <div className="math d2">
      <MathTex
        display
        tex={"\\rho \\leftarrow \\mathbb{Z}_r^{*} \\qquad (u',\\ v') = (\\rho\\cdot u,\\ \\rho\\cdot v)"}
      />
      <span className="math-note">
        rerandomized every showing — a fresh signature object each time
      </span>
    </div>
    <div className="callout purple d3">
      Matching <MathTex tex={"(u',\\ v')"} /> to a recorded issuance{' '}
      <MathTex tex={'(u,\\ v)'} /> means deciding{' '}
      <MathTex tex={"\\log_{u}(u') = \\log_{v}(v')"} /> — DDH in{' '}
      <MathTex tex={'G_1'} />, XDH-hard on BLS12-381 — so the raw MAC can't be
      a static tracking cookie for third parties.
    </div>
  </>
)

const SlideSwapFlow = () => (
  <>
    <h2>Swapping I — the two-round blind swap</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            <code>nft send &lt;h&gt;</code> prints an offline bearer token (
            <span className="mi">psnft1…</span>) containing the credential
            incl. <MathTex tex={'s'} /> — like unredeemed ecash: swap promptly.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            <code>nft receive &lt;token&gt;</code>, round 1:{' '}
            <code>POST /transfer/private/begin</code> with{' '}
            <MathTex tex={'N'} /> → mint returns{' '}
            <MathTex tex={'u_2 = k_2\\cdot g_1'} /> where{' '}
            <MathTex tex={'k_2 = \\text{HMAC}_x(N)'} /> — deterministic, so
            the mint stays stateless.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <p>
            Round 2: <code>POST /transfer/private</code> with the private
            presentation, the blind witness{' '}
            <MathTex tex={'W_h = h\\cdot u_2'} />, and the receiver's{' '}
            <MathTex tex={'S_{\\text{new}}'} /> + PoK. The mint verifies,
            claims <MathTex tex={'N'} /> atomically — double-spend = rejected —
            and blindly re-issues.
          </p>
        </div>
      </div>
    </div>
    <div className="callout d2">
      <code>--public</code> swaps are single-round:{' '}
      <code>POST /transfer</code> with the public presentation — they reveal{' '}
      <MathTex tex={'h'} />.
    </div>
  </>
)

const SlideSwapMath = () => (
  <>
    <h2>Swapping II — the math</h2>
    <div className="cards d1">
      <div className="card">
        <h3>
          Equality of <MathTex tex={'h'} />, proven — never revealed
        </h3>
        <p>
          <MathTex tex={'\\pi_h'} /> is a dlog-eq proof that the SAME{' '}
          <MathTex tex={'h'} /> sits in{' '}
          <MathTex tex={"U_h = h\\cdot u'"} /> (input) and{' '}
          <MathTex tex={'W_h = h\\cdot u_2'} /> (output).
        </p>
      </div>
      <div className="card">
        <h3>Blind re-issuance</h3>
        <p>
          <MathTex
            tex={'v_2 = x\\cdot u_2 + y_h\\cdot W_h + (k_2\\cdot y_s)\\cdot S_{\\text{new}}'}
          />{' '}
          — a fresh credential over the same <MathTex tex={'h'} />, bound to
          the receiver's new secret.
        </p>
      </div>
    </div>
    <div className="callout purple d2">
      <strong>What the mint learns from a private swap — exactly:</strong> THAT
      a credential moved, the spent nullifier <MathTex tex={'N'} />, and an
      unchainable <MathTex tex={'S_{\\text{new}}'} /> — never which asset.
    </div>
  </>
)

const SlideVerification = () => (
  <>
    <h2>Verification equations</h2>
    <div className="cols d1">
      <div className="col">
        <div className="math small">
          <span className="math-label">Public</span>
          <MathTex
            display
            tex={"e(v',\\ g_2) = e(u',\\ X_2 + h\\cdot Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
          />
        </div>
      </div>
      <div className="col">
        <div className="math small">
          <span className="math-label">Private</span>
          <MathTex
            display
            tex={"e(v',\\ g_2) = e(u',\\ X_2) \\cdot e(U_h,\\ Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
          />
        </div>
      </div>
    </div>
    <div className="card d2">
      <h3>Ownership — Chaum–Pedersen dlog-eq</h3>
      <p>
        Same <MathTex tex={'s'} /> in <MathTex tex={'N'} /> (base{' '}
        <MathTex tex={'G_{\\text{NULL}}'} />) and <MathTex tex={'U_s'} />{' '}
        (base <MathTex tex={"u'"} />); in a private swap, same{' '}
        <MathTex tex={'h'} /> in <MathTex tex={'U_h'} /> and{' '}
        <MathTex tex={'W_h'} />.
      </p>
    </div>
    <div className="math small d3">
      <span className="math-label">Why the pairing holds — one line of bilinearity</span>
      <MathTex
        display
        tex={"e(v', g_2) = e(u, g_2)^{\\rho(x + y_h\\cdot h + y_s\\cdot s)} = e(\\rho\\cdot u,\\ (x + y_h\\cdot h)\\cdot g_2) \\cdot e(\\rho\\cdot s\\cdot u,\\ y_s\\cdot g_2)"}
      />
    </div>
    <div className="callout d3">
      Anyone with the 288-byte public parameter set can run this offline — no
      mint secret, no interaction.
    </div>
  </>
)

const SlidePurposeBinding = () => (
  <>
    <h2>Purpose binding</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'c = \\text{SHA-256}(\\text{DST} \\,\\|\\, \\text{binding} \\,\\|\\, B \\,\\|\\, P \\,\\|\\, T) \\bmod r'}
      />
      <span className="math-note">
        every Fiat–Shamir transcript carries a length-framed binding right after the DST
      </span>
    </div>
    <div className="cards three d2">
      <div className="card">
        <h3>Transfer</h3>
        <p>
          Binds the receiver's <MathTex tex={'S_{\\text{new}}'} /> — the proof
          works for that exact re-issuance only.
        </p>
      </div>
      <div className="card">
        <h3>Burn</h3>
        <p>Binds a burn domain constant.</p>
      </div>
      <div className="card">
        <h3>Showing</h3>
        <p>Binds a showing domain + verifier context (e.g. buyer nonce).</p>
      </div>
    </div>
    <div className="math small d3">
      <span className="math-label">Chaum–Pedersen lifecycle, compact</span>
      <MathTex
        display
        tex={'T_i = r\\cdot B_i \\;\\to\\; c \\;\\to\\; z = r + c\\cdot s \\;\\to\\; \\hat{T}_i = z\\cdot B_i - c\\cdot P_i,\\ \\ c \\stackrel{?}{=} \\text{SHA-256}(\\text{DST} \\,\\|\\, \\text{binding} \\,\\|\\, B \\,\\|\\, P \\,\\|\\, \\hat{T})'}
      />
    </div>
    <div className="callout purple d3">
      <strong>This kills replay:</strong> pre-fix, a published presentation
      was replayable into <code>/transfer</code> by anyone — demonstrated live.
      Now a proof speaks for exactly one purpose.
    </div>
  </>
)

const SlideBurn = () => (
  <>
    <h2>Burning</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            <code>nft burn &lt;h&gt;</code> sends a presentation bound to the
            burn domain.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            The mint claims <MathTex tex={'N'} /> and tombstones the asset —
            status <strong>burned</strong>.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <p>
            <code>GET /asset/&lbrace;h&rbrace;</code> →{' '}
            <strong>active | burned | unknown</strong> — a burned asset stays
            distinguishable from a transferred one.
          </p>
        </div>
      </div>
    </div>
    <div className="callout amber d2">
      <strong>
        Burn reveals <MathTex tex={'h'} /> by necessity
      </strong>{' '}
      — the mint must know which asset to tombstone.
    </div>
  </>
)

const SlideShowing = () => (
  <>
    <h2>Showing and third-party verification</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            <code>nft show &lt;h&gt; --context sale-to-bob</code> → prints a{' '}
            <span className="mi">pshow1</span> token:{' '}
            <code>"pshow1" + hex(context ‖ presentation)</code> — mirroring
            the <span className="mi">psnft1</span> bearer tokens — bound to
            the showing domain + context. Mathematically unspendable: the mint
            rejects it for transfer and burn.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            <code>nft inspect &lt;token&gt;</code>, offline: pairing +{' '}
            <MathTex tex={'\\pi'} /> → the mint signed this{' '}
            <MathTex tex={'h'} /> AND the publisher knows{' '}
            <MathTex tex={'s'} /> AND <MathTex tex={'N'} /> belongs to this
            credential.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <p>
            Online: <code>checkstate(N)</code> → UNSPENT = still owned, plus
            asset status. <code>nft verify &lt;h&gt;</code> does the same for
            assets in your own wallet.
          </p>
        </div>
      </div>
    </div>
    <div className="callout purple d2">
      <MathTex tex={'N = s\\cdot G_{\\text{NULL}}'} />, and the mint keeps a
      spent set (NUT-07-style <code>checkstate</code>). Every transfer
      re-issues under a FRESH <MathTex tex={'s'} />, so the current holder's{' '}
      <MathTex tex={'N'} /> is the only unspent one — "is{' '}
      <MathTex tex={'N'} /> spent?" IS the ownership oracle.
    </div>
    <div className="callout amber d3">
      <strong>Point-in-time caveat:</strong> UNSPENT is a snapshot — the owner
      can spend right after. In a sale this is a pre-screen; settle by
      swapping the token before paying.
    </div>
  </>
)

const SlideTrustWire = () => (
  <>
    <h2>Trust model and on the wire</h2>
    <div className="cols d1">
      <div className="col">
        <div className="card">
          <h3>Honest limitations</h3>
          <ul>
            <li>Bearer until swapped — the sender can still spend</li>
            <li>
              Mint liveness needed for <code>checkstate</code>
            </li>
            <li>
              Minting reveals <MathTex tex={'h'} /> by design
            </li>
            <li>
              Showings of one credential are linkable to each other via the
              constant <MathTex tex={'N'} /> — determinism is what catches
              double-spends — but <MathTex tex={'N'} /> can't be matched to
              issuance logs or <MathTex tex={'S'} /> values (DDH in{' '}
              <MathTex tex={'G_1'} />, XDH-hard)
            </li>
          </ul>
        </div>
        <div className="callout purple d2" style={{ marginTop: 14 }}>
          Code map: <strong>cashu/core/crypto/ps.py</strong> (~700 lines,
          pyblst) · <strong>cashu/nft/</strong>
          &lbrace;ledger, api, wallet, cli&rbrace;.py
        </div>
      </div>
      <div className="col">
        <div className="chart-wrap d2">
          <WireSizeChart />
          <p style={{ fontSize: '0.8rem', color: 'var(--muted)', textAlign: 'center', marginTop: 8 }}>
            Serialized sizes — real values, hard-fail length checks in the code
          </p>
        </div>
      </div>
    </div>
  </>
)

const SLIDES = [
  SlideTitle,
  SlideIdea,
  SlideSetup,
  SlideMinting,
  SlideAnatomy,
  SlideSwapFlow,
  SlideSwapMath,
  SlideVerification,
  SlidePurposeBinding,
  SlideBurn,
  SlideShowing,
  SlideTrustWire,
]

/* ─────────────────────────── Chrome ─────────────────────────── */

function Nav({ cur, total, go, setCur }) {
  return (
    <nav>
      <button onClick={() => go(-1)} disabled={cur === 0}>←</button>
      <div className="dots">
        {Array.from({ length: total }, (_, i) => (
          <div key={i} className={`dot${i === cur ? ' on' : ''}`} onClick={() => setCur(i)} />
        ))}
      </div>
      <button onClick={() => go(1)} disabled={cur === total - 1}>→</button>
      <span className="slide-number">{cur + 1} / {total}</span>
    </nav>
  )
}

const WIDE = new Set([3, 4, 5, 7, 8, 10, 11])

export default function App() {
  const [cur, setCur] = useState(0)
  const go = useCallback(
    (d) => setCur((c) => Math.max(0, Math.min(SLIDES.length - 1, c + d))),
    []
  )

  useEffect(() => {
    const h = (e) => {
      if (e.target.tagName === 'INPUT') return
      if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); go(1) }
      if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1) }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [go])

  return (
    <>
      {cur > 0 && (
        <div className="glyph-watermark">
          <SentryGlyph size={50} />
          <span className="watermark-title">{TITLE}</span>
        </div>
      )}
      <div className="progress" style={{ width: `${((cur + 1) / SLIDES.length) * 100}%` }} />
      {SLIDES.map((S, i) => (
        <div key={i} className={`slide ${i === cur ? 'active' : ''}`}>
          <div className={`slide-content${WIDE.has(i) ? ' wide' : ''}${i === cur ? ' anim' : ''}`}>
            <S />
          </div>
        </div>
      ))}
      <Nav cur={cur} total={SLIDES.length} go={go} setCur={setCur} />
    </>
  )
}

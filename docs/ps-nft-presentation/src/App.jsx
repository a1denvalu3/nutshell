import React, { useState, useCallback, useEffect } from 'react'
import { WireSizeChart } from './Charts'
import MathTex from './MathTex'

const TITLE = 'Private NFTs, ecash-style'

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

/* ── Reusable flow diagram: boxes + arrows + caption ── */

function Flow({ steps, caption }) {
  return (
    <>
      <div className="flow">
        {steps.map((s, i) => (
          <React.Fragment key={i}>
            {i > 0 && <div className="flow-arrow">→</div>}
            <div className={`flow-box${s.purple ? ' purple' : ''}`}>
              <div className="flow-title">{s.title}</div>
              {s.sub && <div className="flow-sub">{s.sub}</div>}
            </div>
          </React.Fragment>
        ))}
      </div>
      {caption && <div className="flow-caption">{caption}</div>}
    </>
  )
}

/* ─────────────────────────── Slides ─────────────────────────── */

const SlideTitle = () => (
  <div className="title-block d1">
    <div className="title-logo">
      <SentryLogo width={190} />
    </div>
    <h1>Private NFTs, ecash-style</h1>
    <p className="subtitle">
      Unique digital assets with cash-grade privacy — anyone can verify
      ownership, and even the mint can't see which asset changes hands.
    </p>
    <div className="title-meta">
      September 2026 · experimental branch <code>feature/ps-nft-credentials</code>
    </div>
  </div>
)

const SlideProblem = () => (
  <>
    <div className="headline d1">
      NFTs made ownership public. Cash made payments private. This is both.
    </div>
    <p className="lede d2">
      A regular NFT publishes every ownership transfer to a public ledger,
      forever. Ecash is private — but it's only fungible money. This scheme
      issues unique assets, one per file, with ecash-grade privacy.
    </p>
  </>
)

const SlideQualities = () => (
  <>
    <div className="headline d1">
      Anyone can check. No one can look you up.
    </div>
    <p className="lede d2">
      Anyone can privately verify ownership of an asset — no blockchain
      lookup, no account, no permission.
    </p>
    <p className="lede d2">
      And transfers are private even from the mint: it notarizes every
      transfer, and never learns which asset moved.
    </p>
  </>
)

const SlideCast = () => (
  <>
    <div className="headline d1">
      A notary, an owner, and anyone who wants to check.
    </div>
    <p className="lede d2">
      <strong>The mint</strong> issues and notarizes — but it is not a
      blockchain. It keeps no owner ledger, only a list of serial numbers it
      has seen spent.
    </p>
    <p className="lede d2">
      <strong>The owner</strong> holds a credential plus a secret in their
      wallet. That pair IS the asset.
    </p>
    <p className="lede d2">
      <strong>Anyone</strong> — say, a buyer — can verify before paying.
    </p>
    <div className="callout purple d3">
      A credential is the mint's unforgeable signature over exactly two
      things: the asset's fingerprint, and a secret only the owner knows.
    </div>
  </>
)

const SlideMinting = () => (
  <>
    <div className="headline d1">One file, one credential — ever.</div>
    <div className="d2">
      <Flow
        steps={[
          { title: 'You', sub: 'bring a file; its fingerprint (hash) is the asset id' },
          { title: 'The Mint', sub: 'checks the asset was never issued before', purple: true },
          { title: 'Your wallet', sub: 'receives the credential' },
        ]}
        caption="You pay a normal Lightning invoice if the mint charges — the file is only needed to get a quote."
      />
    </div>
    <p className="lede d3">
      The mint must see the fingerprint to reject duplicates — minting reveals
      the asset, by design. The credential it issues binds that asset to a
      secret your wallet just generated, using a Diffie–Hellman trick: the
      mint never learns the secret, yet the credential provably encodes it.
    </p>
  </>
)

const SlideOwnership = () => (
  <>
    <div className="headline d1">
      Ownership is a secret you hold, not a row in a database.
    </div>
    <p className="lede d2">
      No blockchain, no account, no registry of owners — the credential and
      its secret are all there is. The mint remembers only spent serial
      numbers, and each ownership state has exactly one:{' '}
      <code>serial = secret × public basepoint</code>.
    </p>
    <p className="lede d2">
      Every transfer creates a new secret, hence a new serial — so at any
      moment exactly one serial per asset is unspent: the current owner's.
    </p>
    <div className="callout purple d3">
      "Is this serial spent?" is the whole ownership question.
    </div>
  </>
)

const SlidePullquote = () => (
  <div className="pullquote">
    <div className="headline d1">
      "The mint sees a credential die and a new one be born. It cannot link
      them — and it cannot name the asset."
    </div>
    <p className="lede muted d2">Every default transfer, in one sentence.</p>
  </div>
)

const SlideTransfer = () => (
  <>
    <div className="headline d1">
      Hand it over like cash. Swap it before it's spent twice.
    </div>
    <div className="d2">
      <Flow
        steps={[
          { title: 'Sender', sub: 'copies the credential out as an offline token, like an ecash token' },
          { title: 'Receiver', sub: 'swaps it at the mint for a fresh credential under a new secret', purple: true },
          { title: 'The Mint', sub: 'old serial spent, new credential born' },
        ]}
        caption="The token is a bearer instrument until the receiver swaps — swap promptly, like unredeemed ecash."
      />
    </div>
    <p className="lede d3">
      The receiver's wallet proves the new credential is for the same asset as
      the old one — without naming it. (A public mode exists if you WANT to
      reveal the asset; burning needs it.)
    </p>
  </>
)

const SlideBurn = () => (
  <>
    <div className="headline d1">Burning is final — and public by necessity.</div>
    <div className="d2">
      <Flow
        steps={[
          { title: 'Owner', sub: 'asks the mint to retire the asset forever' },
          { title: 'The Mint', sub: 'spends the serial with no successor', purple: true },
          { title: 'Asset', sub: 'tombstoned — anyone who asks gets "burned"' },
        ]}
        caption='"Burned" stays distinguishable from merely "transferred" for anyone asking about that asset.'
      />
    </div>
    <p className="lede d3">
      The mint must know what it's tombstoning — a burn always reveals the
      asset.
    </p>
  </>
)

const SlideShowing = () => (
  <>
    <div className="headline d1">
      Prove you own it without giving it away.
    </div>
    <div className="d2">
      <Flow
        steps={[
          { title: 'Owner', sub: 'publishes a showing token (pshow1…)' },
          { title: 'Verifier', sub: 'checks the signature and the secret — offline', purple: true },
          { title: 'The Mint', sub: 'one query: is this serial still unspent?' },
        ]}
      />
    </div>
    <div className="steps d3">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>The mint really signed this asset.</p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            The publisher actually holds the secret — not a copy of someone
            else's signature.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <p>They still own it right now.</p>
        </div>
      </div>
    </div>
    <div className="callout purple d3">
      Safe to publish: the showing is purpose-bound — verification only. The
      mint rejects it for transfers and burns; a copied showing is worthless.
      One caveat: "unspent" is a snapshot, so in a sale you settle by swapping
      the token before paying.
    </div>
  </>
)

const SlideWhoLearns = () => (
  <>
    <div className="headline d1">
      The mint notarizes everything — and learns almost nothing.
    </div>
    <table className="compare d2">
      <thead>
        <tr>
          <th></th>
          <th>The mint learns</th>
          <th>The public learns</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Minting</strong></td>
          <td>the asset id + payment</td>
          <td>nothing</td>
        </tr>
        <tr>
          <td><strong>Transfer</strong></td>
          <td>"some credential moved" — not which asset, not who</td>
          <td>nothing</td>
        </tr>
        <tr>
          <td><strong>Burn</strong></td>
          <td>the asset id</td>
          <td>can query the asset's burned status</td>
        </tr>
        <tr>
          <td><strong>Showing</strong></td>
          <td>someone asked about a serial it can't map to anything</td>
          <td>the verifier learns asset + possession + still-owned</td>
        </tr>
      </tbody>
    </table>
  </>
)

const SlideUnderHood = () => (
  <>
    <div className="headline d1">One equation does the checking.</div>
    <p className="lede muted d2">
      Optional depth — everything above stands without this slide.
    </p>
    <div className="math d2">
      <MathTex
        display
        tex={"e(v',\\ g_2) = e(u',\\ X_2 + h\\cdot Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
      />
    </div>
    <p className="lede d3">
      The mint's signature is a point on a pairing-friendly curve (BLS12-381);
      this pairing balances exactly when the mint signed this asset for this
      secret, and anyone can evaluate it with the mint's public parameters.
      The same-asset and same-secret proofs are Chaum–Pedersen sigma proofs —{' '}
      <strong>commit → challenge → respond → verify</strong> — and the mint's
      secret attributes live only in the second curve group, so credentials
      can't be rescaled to other assets.
    </p>
  </>
)

const SlideWrap = () => (
  <>
    <div className="headline d1">Cash-grade privacy for unique assets.</div>
    <div className="cols d2">
      <div className="col">
        <p className="lede">
          Honestly: tokens are bearer instruments until swapped; freshness
          answers come from the mint and are point-in-time — the same trust as
          ecash <code>check_state</code>; the mint sees the asset at minting
          time and learns timing; and showings of one ownership state share
          one serial — linkable to each other, to nothing else.
        </p>
        <div className="callout purple d3" style={{ marginTop: 14 }}>
          <strong>
            Anyone can privately verify ownership; transfers are private even
            from the mint.
          </strong>{' '}
          Code: <strong>cashu/core/crypto/ps.py</strong> +{' '}
          <strong>cashu/nft/</strong>.
        </div>
      </div>
      <div className="col">
        <div className="chart-wrap d3">
          <WireSizeChart />
          <p style={{ fontSize: '0.8rem', color: 'var(--muted)', textAlign: 'center', marginTop: 8 }}>
            On the wire: serialized credential and presentation sizes (bytes)
          </p>
        </div>
      </div>
    </div>
  </>
)

const SLIDES = [
  SlideTitle,
  SlideProblem,
  SlideQualities,
  SlideCast,
  SlideMinting,
  SlideOwnership,
  SlidePullquote,
  SlideTransfer,
  SlideBurn,
  SlideShowing,
  SlideWhoLearns,
  SlideUnderHood,
  SlideWrap,
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

const WIDE = new Set([4, 7, 8, 9, 10, 12])

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

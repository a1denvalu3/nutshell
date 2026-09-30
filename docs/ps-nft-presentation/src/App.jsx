import React, { useState, useCallback, useEffect } from 'react'
import { WireSizeChart } from './Charts'
import MathTex from './MathTex'
import {
  Eye, EyeOff, Envelope, Magnifier, Check, Stamp, Key, Vault,
  Tombstone, Wallet, Plane, Scale, BlindMint, Database, FileDoc,
  Credential, Question, XMark, Dash,
} from './Visuals'

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
    <div className="splitvis d2">
      <div className="split-half">
        <div className="split-title">
          <Eye size={18} /> regular NFTs — a public ledger
        </div>
        <div className="ledger-row">
          <span className="who">0xA3f1… → 0xB7c2…</span>
          <span className="watch"><Eye size={16} /> watching</span>
        </div>
        <div className="ledger-row">
          <span className="who">0xB7c2… → 0xD9e4…</span>
          <span className="watch"><Eye size={16} /> watching</span>
        </div>
        <div className="ledger-row" style={{ marginBottom: 0 }}>
          <span className="who">0xD9e4… → 0xC1a8…</span>
          <span className="watch"><Eye size={16} /> watching</span>
        </div>
      </div>
      <div className="split-half">
        <div className="split-title">
          <Envelope size={18} /> this scheme — sealed envelopes
        </div>
        <div className="ledger-row sealed">
          <span><Envelope size={15} style={{ verticalAlign: '-3px' }} /> sealed transfer</span>
          <span className="watch"><EyeOff size={16} /></span>
        </div>
        <div className="ledger-row sealed">
          <span><Envelope size={15} style={{ verticalAlign: '-3px' }} /> sealed transfer</span>
          <span className="watch"><EyeOff size={16} /></span>
        </div>
        <div className="ledger-row sealed" style={{ marginBottom: 0 }}>
          <span><Envelope size={15} style={{ verticalAlign: '-3px' }} /> sealed transfer</span>
          <span className="watch"><EyeOff size={16} /></span>
        </div>
      </div>
    </div>
  </>
)

const SlideQualities = () => (
  <>
    <div className="headline d1">
      Anyone can check. No one can look you up.
    </div>
    <div className="vrow d2">
      <div className="vbox">
        <span className="token-chip">pshow1…</span>
        <span className="vsub">a published showing token</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox green">
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Magnifier size={26} /><Check size={22} />
        </span>
        <span className="vlabel">ownership verified</span>
        <span className="vsub">offline, no permission</span>
      </div>
      <div className="vbox dark">
        <Database size={28} />
        <span className="vlabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          owner registry <EyeOff size={16} />
        </span>
        <span className="vsub">doesn't exist</span>
      </div>
    </div>
  </>
)

const SlideCast = () => (
  <>
    <div className="headline d1">
      A notary, an owner, and anyone who wants to check.
    </div>
    <div className="triangle-wrap d2">
      <svg className="triangle-lines" viewBox="0 0 100 62" preserveAspectRatio="none" aria-hidden="true">
        <path d="M50 6 L14 56 L86 56 Z" fill="none" stroke="var(--purple-light)" strokeWidth="0.7" strokeDasharray="2.5 1.8" />
      </svg>
      <div className="role-chip" style={{ left: '50%', top: 0 }}>
        <Stamp size={26} />
        <span className="vlabel">the mint</span>
        <span className="vsub">notarizes — no owner ledger</span>
      </div>
      <div className="role-chip" style={{ left: '14%', bottom: 0 }}>
        <Key size={26} />
        <span className="vlabel">the owner</span>
        <span className="vsub">credential + secret</span>
      </div>
      <div className="role-chip" style={{ left: '86%', bottom: 0 }}>
        <Magnifier size={26} />
        <span className="vlabel">anyone</span>
        <span className="vsub">verifies before paying</span>
      </div>
    </div>
    <p className="lede d3">
      A credential is the mint's unforgeable signature over two things: the
      asset's fingerprint, and a secret only the owner knows.
    </p>
  </>
)

const SlideMinting = () => (
  <>
    <div className="headline d1">One file, one credential — ever.</div>
    <div className="vrow d2">
      <div className="vbox">
        <FileDoc size={28} />
        <span className="vlabel">your file</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox">
        <span className="token-chip">a91f…3c</span>
        <span className="vsub">the fingerprint is the asset id</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox purple">
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Credential size={28} /><span className="pop" style={{ display: 'flex' }}><Stamp size={26} /></span>
        </span>
        <span className="vlabel">mint stamps once</span>
        <span className="vsub">never-issued-before check</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox">
        <Vault size={28} />
        <span className="vlabel">your wallet</span>
      </div>
    </div>
    <p className="lede d3">
      Minting reveals the fingerprint by design — it's how duplicates are
      rejected. The credential binds the asset to your freshly generated
      secret via a Diffie–Hellman trick: the mint never learns it.
    </p>
  </>
)

const SlideOwnership = () => (
  <>
    <div className="headline d1">
      Ownership is a secret you hold, not a row in a database.
    </div>
    <div className="vrow d2">
      <div className="vbox">
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Vault size={30} /><Key size={24} />
        </span>
        <span className="vlabel">credential + secret</span>
        <span className="vsub">serial = secret × public basepoint</span>
      </div>
    </div>
    <div className="serial-strip d3">
      <span className="serial-chip spent"><XMark size={13} /> serial 1 · spent</span>
      <span className="serial-chip spent"><XMark size={13} /> serial 2 · spent</span>
      <span className="serial-chip spent"><XMark size={13} /> serial 3 · spent</span>
      <span className="serial-chip unspent"><Check size={13} /> serial 4 · unspent = current owner</span>
    </div>
    <p className="lede d3">
      Every transfer creates a new secret, hence a new serial — exactly one is
      unspent at any moment. "Is this serial spent?" is the whole ownership
      question.
    </p>
  </>
)

const SlidePullquote = () => (
  <div className="pullquote">
    <div className="vrow d1" style={{ marginTop: 0 }}>
      <Wallet size={26} />
      <span className="varrow">→</span>
      <Credential size={30} />
      <span className="varrow">→</span>
      <Wallet size={26} />
      <span style={{ color: 'var(--muted)', display: 'flex', alignItems: 'center', gap: 6, marginLeft: 12 }}>
        <BlindMint size={28} /> the mint, blindfolded
      </span>
    </div>
    <div className="headline d2">
      "The mint sees a credential die and a new one be born. It cannot link
      them — and it cannot name the asset."
    </div>
    <p className="lede muted d3">Every default transfer, in one sentence.</p>
  </div>
)

const SlideTransfer = () => (
  <>
    <div className="headline d1">
      Hand it over like cash. Swap it before it's spent twice.
    </div>
    <div className="vrow d2">
      <div className="vbox">
        <Wallet size={26} />
        <span className="vlabel">sender</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox">
        <Plane size={26} />
        <span className="vlabel">offline token</span>
        <span className="vsub">bearer until swapped — swap promptly</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox">
        <Wallet size={26} />
        <span className="vlabel">receiver</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox purple">
        <span style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ color: 'var(--semantic-red)', display: 'flex', alignItems: 'center', gap: 3 }}>
            <Credential size={22} /><XMark size={15} />
          </span>
          <span title="same asset, never named" style={{ display: 'flex', alignItems: 'center', gap: 3, color: 'var(--purple)' }}>
            <Scale size={18} /><Question size={15} />
          </span>
          <span style={{ color: 'var(--semantic-green)', display: 'flex', alignItems: 'center', gap: 3 }}>
            <Credential size={22} /><Check size={15} />
          </span>
        </span>
        <span className="vlabel">the mint swaps</span>
        <span className="vsub">old spent · new born · asset hidden</span>
      </div>
    </div>
    <p className="lede d3">
      The receiver's wallet proves old and new credential carry the same asset
      — without naming it. (A public mode exists if you WANT to reveal it.)
    </p>
  </>
)

const SlideBurn = () => (
  <>
    <div className="headline d1">Burning is final — and public by necessity.</div>
    <div className="vrow d2">
      <div className="vbox">
        <Credential size={28} />
        <span className="vlabel">owner retires it</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox purple">
        <Tombstone size={28} />
        <span className="vlabel">serial spent, no successor</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox red">
        <span className="vlabel">asset status: "burned"</span>
        <span className="vsub">distinguishable from "transferred"</span>
      </div>
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
    <div className="vrow d2">
      <div className="vbox">
        <span className="token-chip">pshow1…</span>
        <span className="vsub">purpose-bound: verification only, unspendable</span>
      </div>
      <div className="varrow">→</div>
      <div className="vbox purple">
        <Magnifier size={24} />
        <span className="vlabel">verifier</span>
        <span className="vsub">mint query: "spent?" → no</span>
      </div>
    </div>
    <div className="badge-row d3">
      <span className="badge"><Check size={16} /> the mint really signed this asset</span>
      <span className="badge"><Check size={16} /> the publisher holds the secret</span>
      <span className="badge"><Check size={16} /> still owned right now</span>
    </div>
    <p className="lede d3" style={{ marginTop: 12 }}>
      A copied showing is worthless. One caveat: "unspent" is a snapshot — in
      a sale, settle by swapping the token before paying.
    </p>
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
          <th>The mint</th>
          <th>The public</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Minting</strong></td>
          <td><Eye size={16} style={{ verticalAlign: '-3px' }} /> asset id + payment</td>
          <td><Dash size={16} style={{ verticalAlign: '-3px' }} /> nothing</td>
        </tr>
        <tr>
          <td><strong>Transfer</strong></td>
          <td><EyeOff size={16} style={{ verticalAlign: '-3px' }} /> "a credential moved" — not which, not who</td>
          <td><Dash size={16} style={{ verticalAlign: '-3px' }} /> nothing</td>
        </tr>
        <tr>
          <td><strong>Burn</strong></td>
          <td><Eye size={16} style={{ verticalAlign: '-3px' }} /> the asset id</td>
          <td><Eye size={16} style={{ verticalAlign: '-3px' }} /> burned status queryable</td>
        </tr>
        <tr>
          <td><strong>Showing</strong></td>
          <td><EyeOff size={16} style={{ verticalAlign: '-3px' }} /> an unmappable serial query</td>
          <td><Check size={16} style={{ verticalAlign: '-3px' }} /> verifier: asset + possession + still-owned</td>
        </tr>
      </tbody>
    </table>
  </>
)

const SlideUnderHood = () => (
  <>
    <div className="headline d1">One equation does the checking.</div>
    <div className="spotlight d2">
      <div className="math big">
        <MathTex
          display
          tex={"e(v',\\ g_2) = e(u',\\ X_2 + h\\cdot Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
        />
      </div>
    </div>
    <p className="lede d3">
      Optional depth — everything above stands without this slide. It balances
      exactly when the mint signed this asset for this secret; the proofs are
      Chaum–Pedersen sigma protocols (commit → challenge → respond → verify).
    </p>
    <div className="chart-wrap d3">
      <WireSizeChart />
      <p style={{ fontSize: '0.8rem', color: 'var(--muted)', textAlign: 'center', marginTop: 4 }}>
        On the wire: serialized credential and presentation sizes (bytes)
      </p>
    </div>
  </>
)

const SlideWrap = () => (
  <>
    <div className="headline d1">Cash-grade privacy for unique assets.</div>
    <div className="emblem-grid d2">
      <div className="emblem">
        <span className="icon-wrap">
          <Magnifier size={24} />
        </span>
        <span className="big">Anyone can verify ownership — privately.</span>
      </div>
      <div className="emblem">
        <span className="icon-wrap">
          <EyeOff size={24} />
        </span>
        <span className="big">Transfers are private even from the mint.</span>
      </div>
    </div>
    <p className="footnote d3">
      Honestly: tokens are bearer until swapped · freshness answers come from
      the mint, point-in-time (same trust as ecash check_state) · the mint
      sees the asset at minting and learns timing · showings of one ownership
      state share one serial — linkable to each other, to nothing else.
      Code: cashu/core/crypto/ps.py + cashu/nft/.
    </p>
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

const WIDE = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])

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

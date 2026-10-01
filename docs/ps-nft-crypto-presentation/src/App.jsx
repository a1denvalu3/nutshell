import React, { useState, useCallback, useEffect } from 'react'

const TITLE = 'PS-NFT — what the proofs say'

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

const Sym = ({ children }) => <code>{children}</code>

const Statement = ({ claim, to, tone }) => (
  <div className={`statement${tone ? ' ' + tone : ''}`}>
    <div className="claim">{claim}</div>
    {to && <div className="proven-to">proven to: {to}</div>}
  </div>
)

/* ─────────────────────────── Slides ─────────────────────────── */

const Slide0 = () => (
  <div className="title-block d1">
    <div className="title-logo">
      <SentryLogo width={190} />
    </div>
    <h1>PS-NFT — what the proofs say</h1>
    <p className="subtitle">The cryptography as a chain of statements</p>
    <div className="title-meta">
      September 2026 · experimental branch <code>feature/ps-nft-credentials</code>
    </div>
  </div>
)

const Slide1 = () => (
  <>
    <div className="headline d1">The one big idea</div>
    <div className="d2">
      <Statement
        claim={
          <>
            A credential is the mint's unforgeable signature over two things:
            an asset fingerprint and a secret only the owner knows.
          </>
        }
      />
    </div>
    <p className="lede d3">
      Two enabling facts: <strong>pairings</strong> let ANYONE check the
      mint's signature offline, without the mint's secret key — and{' '}
      <strong>zero-knowledge proofs</strong> let the owner prove they hold the
      secret without revealing it.
    </p>
  </>
)

const Slide2 = () => (
  <>
    <div className="headline d1">Minting</div>
    <div className="d2">
      <Statement
        claim={<>“I know the secret <Sym>s</Sym> behind the commitment <Sym>S</Sym> I'm handing you.”</>}
        to="the mint"
      />
      <div className="mint-note">
        The mint checks its <em>own</em> ledger: it remembers every asset it
        has ever signed and refuses repeats. No proof needed — the mint sees
        the asset at issuance, so it knows. The credential it hands back is
        the attestation: the mint accepted this asset as new.
      </div>
    </div>
    <p className="lede d3">
      So the credential comes out bound to a secret the mint never saw. What
      the mint learns: the asset id and the payment. What it never learns:{' '}
      <Sym>s</Sym>.
    </p>
  </>
)

const Slide3 = () => (
  <>
    <div className="headline d1">Owning & showing</div>
    <p className="lede d2">
      A showing proves three statements to ANY verifier:
    </p>
    <div className="d3">
      <Statement claim={<>“The mint signed this asset.”</>} to="anyone, offline" />
      <Statement
        claim={<>“The publisher knows the secret bound into the credential.”</>}
        to="anyone, offline — possession, not a copy"
      />
      <Statement
        claim={<>“This credential's serial has never been spent.”</>}
        to="the mint, online — its one-word answer to the only question that needs it"
        tone="green"
      />
    </div>
  </>
)

const Slide4 = () => (
  <>
    <div className="headline d1">Serials</div>
    <p className="lede d2">
      Every ownership state has exactly one serial number{' '}
      <Sym>N</Sym>, derived from the secret. Spending reveals it. Transfers
      create a fresh secret, hence a fresh serial.
    </p>
    <div className="d3">
      <Statement
        claim={
          <>
            At any moment, exactly one serial per asset is unspent: the
            current owner's.
          </>
        }
      />
    </div>
    <div className="callout purple d3">
      <strong>“Is this serial spent?” IS the ownership question.</strong>
    </div>
  </>
)

const Slide5 = () => (
  <>
    <div className="headline d1">Transferring</div>
    <div className="d2">
      <Statement
        claim={
          <>
            “The asset inside the old credential is the same asset inside the
            new credential.”
          </>
        }
        to="the mint — proven without naming it"
      />
    </div>
    <p className="lede d3">
      The mint sees a credential die and a new one born. It cannot name the
      asset, cannot link the two — and cannot even test guesses: every
      candidate asset has a consistent story.
    </p>
  </>
)

const Slide6 = () => (
  <>
    <div className="headline d1">Purpose binding</div>
    <p className="lede d2">
      Every proof declares what it's FOR, inside the proof itself:
    </p>
    <div className="cards three d3">
      <div className="card">
        <h3>Showing</h3>
        <p>“verify-only”</p>
      </div>
      <div className="card">
        <h3>Transfer</h3>
        <p>“only for this exact recipient commitment”</p>
      </div>
      <div className="card">
        <h3>Burn</h3>
        <p>“burn”</p>
      </div>
    </div>
    <div className="callout purple d3">
      A copied proof is worthless outside its declared purpose.
    </div>
  </>
)

const Slide7 = () => (
  <>
    <div className="headline d1">Burning</div>
    <div className="d2">
      <Statement
        claim={<>“Retire this asset forever.”</>}
        to="the mint"
        tone="amber"
      />
    </div>
    <p className="lede d3">
      The mint tombstones the asset — “burned” stays distinguishable from
      merely “transferred”. Burn names the asset, unavoidably: the mint must
      know what it's tombstoning.
    </p>
  </>
)

const Slide8 = () => (
  <>
    <div className="headline d1">The whole system in one slide</div>
    <table className="compare d2">
      <thead>
        <tr>
          <th>Message</th>
          <th>The statement it proves</th>
          <th>Verified by</th>
          <th>Leaks</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Minting</strong></td>
          <td>“I know the secret behind this commitment” + “never issued before”</td>
          <td>the mint, online</td>
          <td>asset id, payment</td>
        </tr>
        <tr>
          <td><strong>Showing</strong></td>
          <td>“signed · possessed · unspent”</td>
          <td>anyone, offline (+ one mint query)</td>
          <td>nothing</td>
        </tr>
        <tr>
          <td><strong>Transfer</strong></td>
          <td>“same asset, old and new”</td>
          <td>the mint, online</td>
          <td>timing only</td>
        </tr>
        <tr>
          <td><strong>Burn</strong></td>
          <td>“retire this asset forever”</td>
          <td>the mint, online</td>
          <td>asset id</td>
        </tr>
      </tbody>
    </table>
    <div className="callout purple d3">
      <strong>
        Ownership you can prove to anyone. Transfers the mint can't see into.
      </strong>
    </div>
  </>
)

const SLIDES = [
  Slide0, Slide1, Slide2, Slide3, Slide4, Slide5, Slide6, Slide7, Slide8,
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

const WIDE = new Set([3, 6, 8])

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

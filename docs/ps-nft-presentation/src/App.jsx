import React, { useState, useCallback, useEffect } from 'react'
import { WireSizeChart } from './Charts'

const TITLE = 'Pointcheval–Sanders NFT Credentials'

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

const Slide0 = () => (
  <div className="title-block d1">
    <div className="title-logo">
      <SentryLogo width={190} />
    </div>
    <h1>Pointcheval–Sanders NFT Credentials</h1>
    <p className="subtitle">
      Pairing-based anonymous credentials for asset-bound NFTs on BLS12-381 — as
      implemented in Nutshell (<span className="mi">cashu/core/crypto/ps.py</span>)
    </p>
    <div className="title-meta">
      September 2026 · experimental branch <code>feature/ps-nft-credentials</code>
    </div>
  </div>
)

const Slide1 = () => (
  <>
    <h2>From KVAC to pairings</h2>
    <div className="cols d1">
      <div className="col">
        <div className="card">
          <h3>
            <span className="material-symbols-outlined">lock</span>
            Nutshell today — KVAC on secp256k1
          </h3>
          <ul>
            <li>
              <span className="mi">
                MAC = u<sup>(x + y<sub>h</sub>·h + y<sub>s</sub>·s)</sup>
              </span>{' '}
              computed as a Pedersen-like aggregate
            </li>
            <li>
              Verification needs the mint's secret key — only the mint can check
              a credential
            </li>
            <li>Range proofs + sigma protocols for amounts</li>
          </ul>
        </div>
      </div>
      <div className="col">
        <div className="card">
          <h3>
            <span className="material-symbols-outlined">public</span>
            This scheme — PS on BLS12-381
          </h3>
          <ul>
            <li>Same aggregate MAC shape</li>
            <li>
              A bilinear pairing{' '}
              <span className="mi">
                e : G<sub>1</sub> × G<sub>2</sub> → G<sub>T</sub>
              </span>
            </li>
            <li>
              <strong>Anyone</strong> verifies a presentation against the mint's
              public G<sub>2</sub> parameters — offline, without the secret key
            </li>
          </ul>
        </div>
      </div>
    </div>
    <div className="callout purple d2">
      <strong>That single difference — public verifiability — is what pairings buy.</strong>
    </div>
  </>
)

const Slide2 = () => (
  <>
    <h2>Setting and notation</h2>
    <div className="cards d1">
      <div className="card">
        <h3>BLS12-381</h3>
        <p>A pairing-friendly elliptic curve.</p>
      </div>
      <div className="card">
        <h3>
          Groups G<sub>1</sub>, G<sub>2</sub>, G<sub>T</sub>
        </h3>
        <p>
          G<sub>1</sub>, G<sub>2</sub> of prime order{' '}
          <span className="mi">r</span> with generators{' '}
          <span className="mi">
            g<sub>1</sub>, g<sub>2</sub>
          </span>
          ; G<sub>T</sub> is the target group.
        </p>
      </div>
      <div className="card">
        <h3>Bilinear map</h3>
        <p>
          <span className="mi">
            e(a·P, b·Q) = e(P, Q)<sup>a·b</sup>
          </span>
        </p>
      </div>
      <div className="card">
        <h3>Type-3 pairing</h3>
        <p>
          No efficient isomorphism between G<sub>1</sub> and G<sub>2</sub>. This
          asymmetry is load-bearing — see the next slide.
        </p>
      </div>
    </div>
    <div className="callout d2">
      <strong>Two credential attributes:</strong>{' '}
      <span className="mi">h = SHA-256(asset) mod r</span> — hash of the
      JPEG/asset, public at issuance — and <span className="mi">s</span> — the
      owner secret, never revealed to the mint.
    </div>
  </>
)

const Slide3 = () => (
  <>
    <h2>Mint key and public parameters</h2>
    <div className="math d1">
      <span className="eq-step">
        sk = (x, y<sub>h</sub>, y<sub>s</sub>) ← random in Z<sub>r</sub>
      </span>
      <span className="eq-step">
        pk = (X<sub>2</sub>, Y<sub>h2</sub>, Y<sub>s2</sub>) = (x·g<sub>2</sub>
        , y<sub>h</sub>·g<sub>2</sub>, y<sub>s</sub>·g<sub>2</sub>)
      </span>
    </div>
    <div className="callout purple d2">
      <p>
        <strong>
          The y values exist in G<sub>2</sub> only, by construction.
        </strong>
      </p>
      <p>
        If y<sub>h</sub> were available in G<sub>1</sub>, anyone could rescale a
        credential from asset h<sub>1</sub> to h<sub>2</sub> — they'd need{' '}
        <span className="mi">
          u<sup>(y<sub>h</sub>)</sup>
        </span>{' '}
        in G<sub>1</sub>, which is exactly what the mint withholds. This is the
        "exponent rescaling" forgery.
      </p>
      <p>
        The G<sub>1</sub>/G<sub>2</sub> asymmetry of a type-3 pairing is what
        makes withholding possible while still allowing verification.
      </p>
    </div>
  </>
)

const Slide4 = () => (
  <>
    <h2>Issuance: binding an owner without learning the secret</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            User picks <span className="mi">s</span>, sends{' '}
            <span className="mi">
              S = s·g<sub>1</sub>
            </span>{' '}
            plus a Schnorr proof of knowledge of <span className="mi">s</span>{' '}
            (Chaum–Pedersen, Fiat–Shamir).
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            Mint checks the proof, checks <span className="mi">h</span> was
            never issued before, samples{' '}
            <span className="mi">
              k ← Z<sub>r</sub>
            </span>{' '}
            and sets{' '}
            <span className="mi">
              u = k·g<sub>1</sub>
            </span>
            .
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <div className="math small">
            v = (x + y<sub>h</sub>·h)·u + (k·y<sub>s</sub>)·S
          </div>
          <p>
            A Diffie–Hellman trick:{' '}
            <span className="mi">
              S<sup>(k·y<sub>s</sub>)</sup> = (s·g<sub>1</sub>)
              <sup>(k·y<sub>s</sub>)</sup> = s·y<sub>s</sub>·u
            </span>
            , so{' '}
            <span className="mi">
              v = (x + y<sub>h</sub>·h + y<sub>s</sub>·s)·u
            </span>{' '}
            — without the mint ever seeing <span className="mi">s</span>.
          </p>
        </div>
      </div>
    </div>
    <div className="callout d2">
      <strong>
        Credential = (u, v, h, s).
      </strong>{' '}
      The mint only ever emits ONE aggregate exponent — it never hands out
      separate per-term oracles like{' '}
      <span className="mi">
        u<sup>x</sup>
      </span>{' '}
      or{' '}
      <span className="mi">
        u<sup>(y<sub>h</sub>·h)</sup>
      </span>
      ; the sum is what keeps the individual scalars safe.
    </div>
  </>
)

const Slide5 = () => (
  <>
    <h2>Presentation: randomized, publicly verifiable</h2>
    <div className="math d1">
      <span className="eq-step">
        ρ ← Z<sub>r</sub>*&nbsp;&nbsp;&nbsp;(u′, v′) = (ρ·u, ρ·v)
      </span>
      <span className="eq-step" style={{ fontSize: '0.85rem', fontStyle: 'normal', color: 'var(--muted)' }}>
        rerandomizable — unlinkable across showings
      </span>
    </div>
    <div className="cards d2">
      <div className="card">
        <h3>Revealed values</h3>
        <ul>
          <li>
            <span className="mi">h, u′, v′</span>
          </li>
          <li>
            <span className="mi">
              U<sub>s</sub> = s·u′
            </span>
          </li>
          <li>
            <span className="mi">
              S = s·g<sub>1</sub>
            </span>
          </li>
          <li>
            <span className="mi">
              N = s·G<sub>NULL</sub>
            </span>{' '}
            — nullifier; G<sub>NULL</sub> is a nothing-up-my-sleeve
            hash-to-curve point with unknown discrete log
          </li>
        </ul>
      </div>
      <div className="card">
        <h3>Proof π</h3>
        <p>
          One Chaum–Pedersen proof that the SAME <span className="mi">s</span>{' '}
          is the discrete log of <span className="mi">S</span> (base{' '}
          <span className="mi">
            g<sub>1</sub>
          </span>
          ), <span className="mi">N</span> (base{' '}
          <span className="mi">
            G<sub>NULL</sub>
          </span>
          ) and{' '}
          <span className="mi">
            U<sub>s</sub>
          </span>{' '}
          (base <span className="mi">u′</span>).
        </p>
        <p>
          All bases are G<sub>1</sub> points, so no G<sub>T</sub> exponentiation
          is needed.
        </p>
      </div>
    </div>
  </>
)

const Slide6 = () => (
  <>
    <h2>The verification equation</h2>
    <div className="math big d1">
      e(v′, g<sub>2</sub>) = e(u′, X<sub>2</sub> + h·Y<sub>h2</sub>) · e(U
      <sub>s</sub>, Y<sub>s2</sub>)
    </div>
    <div className="math small d2">
      <span className="math-label">Why it holds — bilinearity</span>
      <span className="eq-step">
        v′ = ρ(x + y<sub>h</sub>·h + y<sub>s</sub>·s)·u
      </span>
      <span className="eq-step">
        e(v′, g<sub>2</sub>) = e(u, g<sub>2</sub>)
        <sup>
          ρ(x + y<sub>h</sub>·h + y<sub>s</sub>·s)
        </sup>{' '}
        = e(ρ·u, (x + y<sub>h</sub>·h)·g<sub>2</sub>) · e(ρ·s·u, y<sub>s</sub>·g
        <sub>2</sub>)
      </span>
    </div>
    <div className="callout purple d3">
      <p>
        Anyone with the 288-byte public parameter set can run this — 3 Miller
        loops + 1 final exponentiation, fully offline.
      </p>
      <p>
        <strong>Ownership</strong> = the dlog-eq proof on{' '}
        <span className="mi">s</span>; <strong>authenticity</strong> = the
        pairing.
      </p>
    </div>
  </>
)

const Slide7 = () => (
  <>
    <h2>Transfers and double-spend safety</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            Sender hands over the credential + <span className="mi">s</span>{' '}
            offline as a bearer token (<span className="mi">psnft1…</span>).
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>Receiver presents it to the mint.</p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <p>
            Mint verifies the presentation, checks nullifier{' '}
            <span className="mi">
              N = s·G<sub>NULL</sub>
            </span>{' '}
            is FRESH (never seen), records it, then re-issues a credential over
            the same <span className="mi">h</span> bound to the receiver's new
            secret.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">4</div>
        <div className="step-body">
          <p>
            Spent nullifier = rejected — same as double-spent ecash.
          </p>
        </div>
      </div>
    </div>
    <div className="callout amber d2">
      <strong>Trust note:</strong> until the receiver swaps, the sender can
      still spend — swap promptly, like unredeemed ecash.
    </div>
  </>
)

const Slide8 = () => (
  <>
    <h2>Private presentations: hiding h</h2>
    <p className="subtitle d1">
      Instead of revealing <span className="mi">h</span>, the owner reveals{' '}
      <span className="mi">
        U<sub>h</sub> = h·u′
      </span>{' '}
      with a Chaum–Pedersen proof. The pairing becomes:
    </p>
    <div className="math d1">
      e(v′, g<sub>2</sub>) = e(u′, X<sub>2</sub>) · e(U<sub>h</sub>, Y
      <sub>h2</sub>) · e(U<sub>s</sub>, Y<sub>s2</sub>)
    </div>
    <div className="card d2">
      <h3>Blind re-issuance</h3>
      <ul>
        <li>
          Mint derives a fresh base deterministically from the nullifier:{' '}
          <span className="mi">
            u<sub>2</sub> = k<sub>2</sub>·g<sub>1</sub>
          </span>{' '}
          with{' '}
          <span className="mi">
            k<sub>2</sub> = HMAC<sub>x</sub>(nullifier)
          </span>{' '}
          — the two-round protocol is stateless
        </li>
        <li>
          Owner shows{' '}
          <span className="mi">
            W<sub>h</sub> = h·u<sub>2</sub>
          </span>{' '}
          with a dlog-eq proof that the same <span className="mi">h</span> sits
          in{' '}
          <span className="mi">
            U<sub>h</sub>
          </span>{' '}
          and{' '}
          <span className="mi">
            W<sub>h</sub>
          </span>
        </li>
        <li>
          Mint computes{' '}
          <span className="mi">
            v<sub>2</sub> = x·u<sub>2</sub> + y<sub>h</sub>·W<sub>h</sub> + (k
            <sub>2</sub>·y<sub>s</sub>)·S<sub>new</sub>
          </span>{' '}
          without ever learning <span className="mi">h</span>
        </li>
      </ul>
    </div>
    <div className="callout amber d3">
      <strong>Scope:</strong> this is honest-but-curious privacy for the asset
      id — <span className="mi">h</span> never leaves the wallet, but the mint
      sees THAT a transfer happened and can correlate old/new owner commitments.
      Not full KVAC anonymity.
    </div>
  </>
)

const Slide9 = () => (
  <>
    <h2>On the wire</h2>
    <div className="chart-wrap d1">
      <WireSizeChart />
      <p style={{ fontSize: '0.8rem', color: 'var(--muted)', textAlign: 'center', marginTop: 8 }}>
        Serialized sizes — real values, enforced by hard-fail length checks in the code
      </p>
    </div>
    <table className="compare d2">
      <thead>
        <tr>
          <th>Component</th>
          <th>Size</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>keyset id</td>
          <td>33 B</td>
          <td>"03" version byte + 32-byte SHA-256, derived like v3 ecash keysets</td>
        </tr>
        <tr>
          <td>
            compressed G<sub>1</sub> point
          </td>
          <td>48 B</td>
          <td>—</td>
        </tr>
        <tr>
          <td>scalar</td>
          <td>32 B</td>
          <td>—</td>
        </tr>
        <tr>
          <td>dlog-eq proof</td>
          <td>64 B</td>
          <td>—</td>
        </tr>
        <tr>
          <td>mint public params</td>
          <td>288 B</td>
          <td>
            3 compressed G<sub>2</sub> points
          </td>
        </tr>
      </tbody>
    </table>
    <div className="callout purple d3">
      Everything above lives in <strong>cashu/core/crypto/ps.py</strong> (~700
      lines, pyblst); ledger/wallet/CLI in <strong>cashu/nft/</strong>.
    </div>
  </>
)

const SLIDES = [Slide0, Slide1, Slide2, Slide3, Slide4, Slide5, Slide6, Slide7, Slide8, Slide9]

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

const WIDE = new Set([1, 2, 4, 7, 9])

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

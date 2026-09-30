import React, { useState, useCallback, useEffect } from 'react'
import { WireSizeChart } from './Charts'
import MathTex from './MathTex'

const TITLE = 'PS-NFT — the cryptography'

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
    <h1>PS-NFT — the cryptography</h1>
    <p className="subtitle">
      Pairing-based credentials for private, unique digital assets
    </p>
    <div className="title-meta">
      September 2026 · experimental branch <code>feature/ps-nft-credentials</code>
    </div>
  </div>
)

const Slide1 = () => (
  <>
    <h2>The toolkit</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'e : G_1 \\times G_2 \\to G_T \\qquad e(a\\cdot P,\\ b\\cdot Q) = e(P, Q)^{a\\cdot b}'}
      />
    </div>
    <div className="cards d2">
      <div className="card">
        <h3>BLS12-381</h3>
        <p>
          <MathTex tex={'G_1, G_2'} /> of prime order <MathTex tex={'r'} />,
          generators <MathTex tex={'g_1, g_2'} />; target group{' '}
          <MathTex tex={'G_T'} />.
        </p>
      </div>
      <div className="card">
        <h3>Type-3 pairing</h3>
        <p>
          No efficient isomorphism between <MathTex tex={'G_1'} /> and{' '}
          <MathTex tex={'G_2'} /> — the asymmetry is load-bearing.
        </p>
      </div>
    </div>
    <div className="cards d3" style={{ marginTop: 14 }}>
      <div className="card">
        <h3>XDH</h3>
        <p>
          DDH is hard in <MathTex tex={'G_1'} />.
        </p>
      </div>
      <div className="card">
        <h3>CDH</h3>
        <p>
          CDH is hard in <MathTex tex={'G_1'} />.
        </p>
      </div>
      <div className="card">
        <h3>DL + PS</h3>
        <p>
          Discrete log is hard everywhere; PS signatures are unforgeable.
        </p>
      </div>
    </div>
  </>
)

const Slide2 = () => (
  <>
    <h2>Pointcheval–Sanders signatures</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'\\text{sk} = (x,\\ y_1, \\dots, y_n)'}
      />
      <MathTex
        display
        tex={'u = k\\cdot g_1 \\qquad v = (x + \\textstyle\\sum_i y_i\\cdot m_i)\\cdot u'}
      />
      <MathTex
        display
        tex={"\\rho \\leftarrow \\mathbb{Z}_r^{*} \\qquad (u',\\ v') = (\\rho\\cdot u,\\ \\rho\\cdot v)"}
      />
    </div>
    <div className="callout purple d2">
      <strong>Unforgeability intuition:</strong> the signer only ever emits
      the aggregate exponent — never per-term oracles like{' '}
      <MathTex tex={'u^{x}'} /> or <MathTex tex={'u^{y_i\\cdot m_i}'} />. The
      sum is what keeps the individual scalars safe, and{' '}
      <MathTex tex={'\\rho'} />-rerandomization makes each presentation a
      fresh signature object.
    </div>
  </>
)

const Slide3 = () => (
  <>
    <h2>Our credential</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'v = (x + y_h\\cdot h + y_s\\cdot s)\\cdot u'}
      />
    </div>
    <p className="lede d2">
      Two attributes: <MathTex tex={'h = \\text{SHA-256}(\\text{asset}) \\bmod r'} />{' '}
      — the asset fingerprint — and <MathTex tex={'s'} /> — the owner secret,
      never revealed.
    </p>
    <div className="cards d3">
      <div className="card">
        <h3>
          In <MathTex tex={'G_2'} />: verification
        </h3>
        <p>
          <MathTex tex={'(X_2,\\ Y_{h2},\\ Y_{s2}) = (x\\cdot g_2,\\ y_h\\cdot g_2,\\ y_s\\cdot g_2)'} />
          . Withholding <MathTex tex={'u^{y_h}'} /> from{' '}
          <MathTex tex={'G_1'} /> blocks the exponent-rescaling forgery.
        </p>
      </div>
      <div className="card">
        <h3>
          In <MathTex tex={'G_1'} />: unblinding
        </h3>
        <p>
          <MathTex tex={'Y_{h1} = y_h\\cdot g_1'} /> lets the owner strip a
          blinding correction term. Turning it into{' '}
          <MathTex tex={'u^{y_h}'} /> is CDH in <MathTex tex={'G_1'} />.
        </p>
      </div>
    </div>
    <div className="callout d3">
      The v3-style keyset id commits to all four public points.
    </div>
  </>
)

const Slide4 = () => (
  <>
    <h2>Issuance: binding a secret the mint never sees</h2>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            User sends <MathTex tex={'S = s\\cdot g_1'} /> plus a Schnorr proof
            of knowledge of <MathTex tex={'s'} />.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            Mint samples <MathTex tex={'k'} />, sets{' '}
            <MathTex tex={'u = k\\cdot g_1'} />, and checks{' '}
            <MathTex tex={'h'} /> was never minted — one credential per asset.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <div className="math small">
            <MathTex
              display
              tex={'(k\\cdot y_s)\\cdot S = s\\cdot y_s\\cdot u'}
            />
            <MathTex
              display
              tex={'v = (x + y_h\\cdot h)\\cdot u + (k\\cdot y_s)\\cdot S = (x + y_h\\cdot h + y_s\\cdot s)\\cdot u'}
            />
          </div>
          <p>
            The Diffie–Hellman trick: <MathTex tex={'s'} /> enters the
            credential without the mint ever learning it.
          </p>
        </div>
      </div>
    </div>
  </>
)

const Slide5 = () => (
  <>
    <h2>Public presentation</h2>
    <p className="lede d1">
      Reveal{' '}
      <MathTex tex={"(h,\\ u',\\ v',\\ U_s = s\\cdot u',\\ N = s\\cdot G_{\\text{NULL}},\\ \\pi)"} />
      .
    </p>
    <div className="math big d2">
      <MathTex
        display
        tex={"e(v',\\ g_2) = e(u',\\ X_2 + h\\cdot Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
      />
    </div>
    <div className="math small d3">
      <span className="math-label">Why it holds — bilinearity</span>
      <MathTex
        display
        tex={"v' = \\rho\\,(x + y_h\\cdot h + y_s\\cdot s)\\cdot u"}
      />
      <MathTex
        display
        tex={"e(v', g_2) = e(u, g_2)^{\\rho\\,(x + y_h\\cdot h + y_s\\cdot s)} = e(\\rho\\cdot u,\\ (x + y_h\\cdot h)\\cdot g_2) \\cdot e(\\rho\\cdot s\\cdot u,\\ y_s\\cdot g_2)"}
      />
    </div>
  </>
)

const Slide6 = () => (
  <>
    <h2>The ownership proof</h2>
    <p className="subtitle d1">
      Chaum–Pedersen dlog-eq — witness <MathTex tex={'s'} />, bases{' '}
      <MathTex tex={"B = (G_{\\text{NULL}},\\ u')"} />, points{' '}
      <MathTex tex={'P = (N,\\ U_s)'} />.
    </p>
    <div className="math small d1">
      <MathTex
        display
        tex={'T_i = r\\cdot B_i \\;\\to\\; c = \\text{SHA-256}(\\text{DST} \\,\\|\\, \\text{binding} \\,\\|\\, B \\,\\|\\, P \\,\\|\\, T) \\bmod r \\;\\to\\; z = r + c\\cdot s'}
      />
      <MathTex
        display
        tex={'\\hat{T}_i = z\\cdot B_i - c\\cdot P_i \\qquad \\text{accept iff } c = \\text{SHA-256}(\\text{DST} \\,\\|\\, \\text{binding} \\,\\|\\, B \\,\\|\\, P \\,\\|\\, \\hat{T})'}
      />
      <MathTex
        display
        tex={'z\\cdot B_i = (r + c\\cdot s)\\cdot B_i = r\\cdot B_i + c\\cdot(s\\cdot B_i) = T_i + c\\cdot P_i'}
      />
    </div>
    <div className="cards three d2">
      <div className="card">
        <h3>Zero-knowledge</h3>
        <p>
          Simulator picks <MathTex tex={'(c,\\ z)'} /> first and sets{' '}
          <MathTex tex={'T_i = z\\cdot B_i - c\\cdot P_i'} />.
        </p>
      </div>
      <div className="card">
        <h3>Proof of knowledge</h3>
        <p>
          Extractor from two transcripts:{' '}
          <MathTex tex={'s = (z_1 - z_2)\\,/\\,(c_1 - c_2)'} />.
        </p>
      </div>
      <div className="card">
        <h3>One proof, all bases</h3>
        <p>
          A single 64-byte <MathTex tex={'(c,\\ z)'} /> covers both bases at
          once.
        </p>
      </div>
    </div>
  </>
)

const Slide7 = () => (
  <>
    <h2>Nullifiers</h2>
    <div className="math d1">
      <MathTex display tex={'N = s\\cdot G_{\\text{NULL}}'} />
    </div>
    <div className="cards d2">
      <div className="card">
        <h3>NUMS base</h3>
        <p>
          <MathTex tex={'G_{\\text{NULL}}'} /> is a hash-to-curve
          nothing-up-my-sleeve point — unknown discrete log.
        </p>
      </div>
      <div className="card">
        <h3>Deterministic by design</h3>
        <p>
          Determinism is exactly what makes double-spending detectable.
        </p>
      </div>
      <div className="card">
        <h3>One live serial</h3>
        <p>
          Every transfer re-issues under a fresh <MathTex tex={'s'} /> — the
          current holder's <MathTex tex={'N'} /> is the only unspent one.
        </p>
      </div>
      <div className="card">
        <h3>DDH separation</h3>
        <p>
          <MathTex tex={'N'} /> is unlinkable to <MathTex tex={'S'} /> or{' '}
          <MathTex tex={"u'"} /> — deciding they share a secret is DDH in{' '}
          <MathTex tex={'G_1'} /> (XDH).
        </p>
      </div>
    </div>
  </>
)

const Slide8 = () => (
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
          Binds the receiver's <MathTex tex={'S_{\\text{new}}'} /> — valid for
          that exact re-issuance only.
        </p>
      </div>
      <div className="card">
        <h3>Burn</h3>
        <p>Binds a burn domain.</p>
      </div>
      <div className="card">
        <h3>Showing</h3>
        <p>
          Binds a showing domain + verifier context — verify-only,
          unspendable.
        </p>
      </div>
    </div>
    <div className="callout purple d3">
      <strong>One proof = one purpose.</strong> A copied presentation is
      worthless outside its purpose.
    </div>
  </>
)

const Slide9 = () => (
  <>
    <h2>Hidden-asset presentations</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'\\kappa_h = h\\cdot Y_{h2} + o\\cdot g_2 \\qquad \\text{(Pedersen commitment in } G_2\\text{, fresh } o\\text{)}'}
      />
      <MathTex
        display
        tex={"v'' = \\rho\\cdot v + o\\cdot u'"}
      />
      <MathTex
        display
        tex={"e(v'',\\ g_2) = e(u',\\ X_2) \\cdot e(u',\\ \\kappa_h) \\cdot e(U_s,\\ Y_{s2})"}
      />
    </div>
    <div className="math small d2">
      <span className="math-label">Closure</span>
      <MathTex
        display
        tex={"e(v'', g_2) = e(u, g_2)^{\\rho\\,(x + y_h\\cdot h + y_s\\cdot s + o)}"}
      />
    </div>
    <div className="callout purple d3">
      <strong>Hiding, information-theoretically:</strong> for every candidate
      asset <MathTex tex={"h'"} /> there EXISTS a blinding{' '}
      <MathTex tex={"o'"} /> with{' '}
      <MathTex tex={"\\kappa_h = h'\\cdot Y_{h2} + o'\\cdot g_2"} /> — no
      distinguishing test exists.
    </div>
  </>
)

const Slide10 = () => (
  <>
    <h2>Blind re-issuance</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'B = h\\cdot u_2 + t\\cdot g_1 \\qquad u_2 = k_2\\cdot g_1,\\ \\ k_2 = \\text{HMAC}_x(N)'}
      />
    </div>
    <div className="cards d2">
      <div className="card">
        <h3>One multi-witness sigma proof</h3>
        <p>
          Witnesses <MathTex tex={'(h,\\ o,\\ t)'} /> over{' '}
          <MathTex tex={'\\kappa_h = h\\cdot Y_{h2} + o\\cdot g_2'} /> and{' '}
          <MathTex tex={'B = h\\cdot u_2 + t\\cdot g_1'} /> prove the SAME{' '}
          <MathTex tex={'h'} /> opens both — cross-group, valid because{' '}
          <MathTex tex={'G_1'} /> and <MathTex tex={'G_2'} /> share the scalar
          field <MathTex tex={'r'} />.
        </p>
      </div>
      <div className="card">
        <h3>Stateless mint</h3>
        <p>
          <MathTex tex={'k_2 = \\text{HMAC}_x(N)'} /> is deterministic per
          nullifier — the two-round protocol keeps no mint state.
        </p>
      </div>
    </div>
    <div className="math small d3">
      <MathTex
        display
        tex={'v_{2\\text{raw}} = x\\cdot u_2 + y_h\\cdot B + (k_2\\cdot y_s)\\cdot S_{\\text{new}}'}
      />
      <MathTex
        display
        tex={'y_h\\cdot B = y_h\\cdot h\\cdot u_2 + t\\cdot y_h\\cdot g_1 \\qquad v_2 = v_{2\\text{raw}} - t\\cdot Y_{h1}'}
      />
    </div>
    <div className="callout purple d3">
      The mint learns nothing about <MathTex tex={'h'} /> — not even in
      principle.
    </div>
  </>
)

const Slide11 = () => (
  <>
    <h2>What holds what up</h2>
    <table className="compare d1">
      <thead>
        <tr>
          <th>If this breaks…</th>
          <th>…this falls</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>XDH (DDH in <MathTex tex={'G_1'} />)</td>
          <td>presentations become linkable to issuance</td>
        </tr>
        <tr>
          <td>CDH in <MathTex tex={'G_1'} /></td>
          <td>
            <MathTex tex={'Y_{h1}'} /> becomes forgery leverage
          </td>
        </tr>
        <tr>
          <td>PS assumption</td>
          <td>credential forgery</td>
        </tr>
        <tr>
          <td>ROM / Fiat–Shamir</td>
          <td>proof malleability</td>
        </tr>
      </tbody>
    </table>
    <div className="callout amber d2">
      <strong>Honest footer:</strong> the primitives are standard
      (PS16/Coconut-style); the composition is ours and not yet formally
      proven.
    </div>
  </>
)

const Slide12 = () => (
  <>
    <h2>On the wire</h2>
    <div className="chart-wrap d1">
      <WireSizeChart />
      <p style={{ fontSize: '0.8rem', color: 'var(--muted)', textAlign: 'center', marginTop: 8 }}>
        Serialized sizes — real values, hard-fail length checks in the code
      </p>
    </div>
    <div className="callout purple d2">
      Code map: <strong>cashu/core/crypto/ps.py</strong> (pyblst) ·{' '}
      <strong>cashu/nft/</strong>
    </div>
  </>
)

const SLIDES = [
  Slide0, Slide1, Slide2, Slide3, Slide4, Slide5, Slide6,
  Slide7, Slide8, Slide9, Slide10, Slide11, Slide12,
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

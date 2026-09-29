import React, { useState, useCallback, useEffect } from 'react'
import { WireSizeChart } from './Charts'
import MathTex from './MathTex'

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
              <MathTex tex={'\\text{MAC} = u^{x + y_h\\cdot h + y_s\\cdot s}'} />{' '}
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
              <MathTex tex={'e : G_1 \\times G_2 \\to G_T'} />
            </li>
            <li>
              <strong>Anyone</strong> verifies a presentation against the mint's
              public <MathTex tex={'G_2'} /> parameters — offline, without the
              secret key
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
          Groups <MathTex tex={'G_1,\\ G_2,\\ G_T'} />
        </h3>
        <p>
          <MathTex tex={'G_1, G_2'} /> of prime order <MathTex tex={'r'} /> with
          generators <MathTex tex={'g_1, g_2'} />; <MathTex tex={'G_T'} /> is
          the target group.
        </p>
      </div>
      <div className="card">
        <h3>Bilinear map</h3>
        <p>
          <MathTex tex={'e(a\\cdot P,\\ b\\cdot Q) = e(P, Q)^{a\\cdot b}'} />
        </p>
      </div>
      <div className="card">
        <h3>Type-3 pairing</h3>
        <p>
          No efficient isomorphism between <MathTex tex={'G_1'} /> and{' '}
          <MathTex tex={'G_2'} />. This asymmetry is load-bearing — see the
          next slide.
        </p>
      </div>
    </div>
    <div className="callout d2">
      <strong>Two credential attributes:</strong>{' '}
      <MathTex tex={'h = \\text{SHA-256}(\\text{asset}) \\bmod r'} /> — hash of
      the JPEG/asset, public at issuance — and <MathTex tex={'s'} /> — the
      owner secret, never revealed to the mint.
    </div>
  </>
)

const Slide3 = () => (
  <>
    <h2>Mint key and public parameters</h2>
    <div className="math d1">
      <MathTex
        display
        tex={'\\text{sk} = (x,\\ y_h,\\ y_s) \\xleftarrow{\\text{random}} \\mathbb{Z}_r'}
      />
      <MathTex
        display
        tex={'\\text{pk} = (X_2,\\ Y_{h2},\\ Y_{s2}) = (x\\cdot g_2,\\ y_h\\cdot g_2,\\ y_s\\cdot g_2)'}
      />
    </div>
    <div className="callout purple d2">
      <p>
        <strong>
          The <MathTex tex={'y'} /> values exist in <MathTex tex={'G_2'} />{' '}
          only, by construction.
        </strong>
      </p>
      <p>
        If <MathTex tex={'y_h'} /> were available in <MathTex tex={'G_1'} />,
        anyone could rescale a credential from asset <MathTex tex={'h_1'} /> to{' '}
        <MathTex tex={'h_2'} /> — they'd need <MathTex tex={'u^{y_h}'} /> in{' '}
        <MathTex tex={'G_1'} />, which is exactly what the mint withholds. This
        is the "exponent rescaling" forgery.
      </p>
      <p>
        The <MathTex tex={'G_1'}/>/<MathTex tex={'G_2'} /> asymmetry of a
        type-3 pairing is what makes withholding possible while still allowing
        verification.
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
            User picks <MathTex tex={'s'} />, sends{' '}
            <MathTex tex={'S = s\\cdot g_1'} /> plus a Schnorr proof of
            knowledge of <MathTex tex={'s'} /> (Chaum–Pedersen, Fiat–Shamir).
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            Mint checks the proof, checks <MathTex tex={'h'} /> was never
            issued before, samples <MathTex tex={'k \\leftarrow \\mathbb{Z}_r'} />{' '}
            and sets <MathTex tex={'u = k\\cdot g_1'} />.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <div className="math small">
            <MathTex
              display
              tex={'v = (x + y_h\\cdot h)\\cdot u + (k\\cdot y_s)\\cdot S'}
            />
          </div>
          <p>
            A Diffie–Hellman trick:{' '}
            <MathTex
              tex={'S^{k\\cdot y_s} = (s\\cdot g_1)^{k\\cdot y_s} = s\\cdot y_s\\cdot u'}
            />
            , so{' '}
            <MathTex tex={'v = (x + y_h\\cdot h + y_s\\cdot s)\\cdot u'} /> —
            without the mint ever seeing <MathTex tex={'s'} />.
          </p>
        </div>
      </div>
    </div>
    <div className="callout d2">
      <strong>
        Credential <MathTex tex={'= (u,\\ v,\\ h,\\ s)'} />.
      </strong>{' '}
      The mint only ever emits ONE aggregate exponent — it never hands out
      separate per-term oracles like <MathTex tex={'u^{x}'} /> or{' '}
      <MathTex tex={'u^{y_h\\cdot h}'} />; the sum is what keeps the individual
      scalars safe.
    </div>
  </>
)

const Slide5 = () => (
  <>
    <h2>Presentation: randomized, publicly verifiable</h2>
    <div className="math d1">
      <MathTex
        display
        tex={"\\rho \\leftarrow \\mathbb{Z}_r^{*} \\qquad (u',\\ v') = (\\rho\\cdot u,\\ \\rho\\cdot v)"}
      />
      <span className="math-note">rerandomizable — unlinkable across showings</span>
    </div>
    <div className="cards d2">
      <div className="card">
        <h3>Revealed values</h3>
        <ul>
          <li>
            <MathTex tex={"h,\\ u',\\ v'"} />
          </li>
          <li>
            <MathTex tex={"U_s = s\\cdot u'"} />
          </li>
          <li>
            <MathTex tex={'S = s\\cdot g_1'} />
          </li>
          <li>
            <MathTex tex={'N = s\\cdot G_{\\text{NULL}}'} /> — nullifier;{' '}
            <MathTex tex={'G_{\\text{NULL}}'} /> is a nothing-up-my-sleeve
            hash-to-curve point with unknown discrete log
          </li>
        </ul>
      </div>
      <div className="card">
        <h3>
          Proof <MathTex tex={'\\pi'} />
        </h3>
        <p>
          One Chaum–Pedersen proof that the SAME <MathTex tex={'s'} /> is the
          discrete log of <MathTex tex={'S'} /> (base{' '}
          <MathTex tex={'g_1'} />), <MathTex tex={'N'} /> (base{' '}
          <MathTex tex={'G_{\\text{NULL}}'} />) and <MathTex tex={'U_s'} />{' '}
          (base <MathTex tex={"u'"} />).
        </p>
        <p>
          All bases are <MathTex tex={'G_1'} /> points, so no{' '}
          <MathTex tex={'G_T'} /> exponentiation is needed.
        </p>
      </div>
    </div>
  </>
)

const Slide6 = () => (
  <>
    <h2>The verification equation</h2>
    <div className="math big d1">
      <MathTex
        display
        tex={"e(v',\\ g_2) = e(u',\\ X_2 + h\\cdot Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
      />
    </div>
    <div className="math small d2">
      <span className="math-label">Why it holds — bilinearity</span>
      <MathTex
        display
        tex={"v' = \\rho(x + y_h\\cdot h + y_s\\cdot s)\\cdot u"}
      />
      <MathTex
        display
        tex={"e(v', g_2) = e(u, g_2)^{\\rho(x + y_h\\cdot h + y_s\\cdot s)} = e(\\rho\\cdot u,\\ (x + y_h\\cdot h)\\cdot g_2) \\cdot e(\\rho\\cdot s\\cdot u,\\ y_s\\cdot g_2)"}
      />
    </div>
    <div className="callout purple d3">
      <p>
        Anyone with the 288-byte public parameter set can run this — 3 Miller
        loops + 1 final exponentiation, fully offline.
      </p>
      <p>
        <strong>Ownership</strong> = the dlog-eq proof on{' '}
        <MathTex tex={'s'} />; <strong>authenticity</strong> = the pairing.
      </p>
    </div>
  </>
)

const SlideProofs = () => (
  <>
    <h2>Two proofs, two jobs</h2>
    <div className="cols d1">
      <div className="col">
        <div className="card">
          <h3>
            <span className="material-symbols-outlined">verified</span>
            Authenticity — the pairing check
          </h3>
          <ul>
            <li>
              NOT a sigma protocol — no prover interaction at all
            </li>
            <li>
              The presentation itself{' '}
              <MathTex tex={"(h,\\ u',\\ v',\\ U_s)"} /> is the proof: the
              verifier simply evaluates{' '}
              <MathTex
                tex={"e(v', g_2) = e(u', X_2 + h\\cdot Y_{h2}) \\cdot e(U_s, Y_{s2})"}
              />{' '}
              with the mint's public parameters
            </li>
            <li>
              Answers: "was this credential really issued by the mint, over this{' '}
              <MathTex tex={'h'} />?"
            </li>
            <li>
              Unforgeable under the PS assumption — without{' '}
              <MathTex tex={'(x,\\ y_h,\\ y_s)'} /> you cannot produce{' '}
              <MathTex tex={"(u',\\ v')"} /> that satisfies the equation
            </li>
          </ul>
        </div>
      </div>
      <div className="col">
        <div className="card">
          <h3>
            <span className="material-symbols-outlined">key</span>
            Ownership — the dlog-eq proof
          </h3>
          <ul>
            <li>
              An interactive sigma protocol made non-interactive with
              Fiat–Shamir
            </li>
            <li>
              Answers: "does the presenter actually know the secret{' '}
              <MathTex tex={'s'} /> bound into this credential?"
            </li>
            <li>
              Proves knowledge of a single <MathTex tex={'s'} /> that is
              simultaneously the discrete log of <MathTex tex={'S'} /> (base{' '}
              <MathTex tex={'g_1'} />), <MathTex tex={'N'} /> (base{' '}
              <MathTex tex={'G_{\\text{NULL}}'} />) and{' '}
              <MathTex tex={'U_s'} /> (base <MathTex tex={"u'"} />) — without
              revealing <MathTex tex={'s'} />
            </li>
          </ul>
        </div>
      </div>
    </div>
    <div className="callout purple d2">
      In a PRIVATE presentation there is a second dlog-eq proof of the same
      shape with witness <MathTex tex={'h'} /> instead of{' '}
      <MathTex tex={'s'} /> (bases <MathTex tex={"u'"} /> and{' '}
      <MathTex tex={'u_2'} />, points <MathTex tex={'U_h'} /> and{' '}
      <MathTex tex={'W_h'} />). One construction, two witnesses.
    </div>
  </>
)

const SlideChaumPedersen = () => (
  <>
    <h2>Inside the Chaum–Pedersen proof</h2>
    <p className="subtitle d1">
      Witness <MathTex tex={'s'} />; bases{' '}
      <MathTex tex={"B = (g_1,\\ G_{\\text{NULL}},\\ u')"} />, points{' '}
      <MathTex tex={'P = (S,\\ N,\\ U_s)'} />.
    </p>
    <div className="steps d1">
      <div className="step">
        <div className="step-num">1</div>
        <div className="step-body">
          <p>
            <strong>Commit</strong> — prover samples{' '}
            <MathTex tex={'r \\xleftarrow{\\text{\\$}} \\mathbb{Z}_r'} /> and sends
            commitments <MathTex tex={'T_i = r\\cdot B_i'} />, i.e.{' '}
            <MathTex
              tex={"T_1 = r\\cdot g_1,\\ \\ T_2 = r\\cdot G_{\\text{NULL}},\\ \\ T_3 = r\\cdot u'"}
            />
            .
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">2</div>
        <div className="step-body">
          <p>
            <strong>Challenge</strong> — Fiat–Shamir:{' '}
            <MathTex
              tex={'c = \\text{SHA-256}(\\text{DST} \\,\\|\\, B_1,B_2,B_3 \\,\\|\\, P_1,P_2,P_3 \\,\\|\\, T_1,T_2,T_3) \\bmod r'}
            />
            . The transcript binds the proof to THIS statement — it can't be
            replayed for a different credential. The DST is{' '}
            <code>b"Cashu_PS_Present_v1"</code> and each point is
            length-framed.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">3</div>
        <div className="step-body">
          <p>
            <strong>Respond</strong> —{' '}
            <MathTex tex={'z = r + c\\cdot s \\bmod r'} />. The proof on the
            wire is just <MathTex tex={'(c,\\ z)'} />: 64 bytes.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">4</div>
        <div className="step-body">
          <p>
            <strong>Verify</strong> — recompute{' '}
            <MathTex tex={'\\hat{T}_i = z\\cdot B_i - c\\cdot P_i'} /> for
            each <MathTex tex={'i'} /> and accept iff:
          </p>
        </div>
      </div>
    </div>
    <div className="math small d2">
      <MathTex
        display
        tex={'c = \\text{SHA-256}(\\text{DST} \\,\\|\\, B \\,\\|\\, P \\,\\|\\, \\hat{T})'}
      />
    </div>
    <div className="math small d2">
      <span className="math-label">Why it works</span>
      <MathTex
        display
        tex={'z\\cdot B_i = (r + c\\cdot s)\\cdot B_i = r\\cdot B_i + c\\cdot(s\\cdot B_i) = T_i + c\\cdot P_i'}
      />
    </div>
    <div className="cards three d3">
      <div className="card">
        <h3>Zero-knowledge</h3>
        <p>
          <MathTex tex={'z'} /> hides <MathTex tex={'s'} /> perfectly because{' '}
          <MathTex tex={'r'} /> is uniform; a simulator can fake transcripts by
          picking <MathTex tex={'(c,\\ z)'} /> first and setting{' '}
          <MathTex tex={'T_i = z\\cdot B_i - c\\cdot P_i'} />.
        </p>
      </div>
      <div className="card">
        <h3>Proof of knowledge</h3>
        <p>
          From two accepting transcripts with the same commitments but different
          challenges, an extractor recovers{' '}
          <MathTex tex={'s = (z_1 - z_2)\\,/(c_1 - c_2)'} />.
        </p>
      </div>
      <div className="card">
        <h3>One proof, n bases</h3>
        <p>
          A single <MathTex tex={'(c,\\ z)'} /> covers all three bases at once,
          so ownership, nullifier and credential-binding cost 64 bytes total.
        </p>
      </div>
    </div>
    <div className="callout d3">
      Implemented in <strong>prove_dlog_eq</strong> /{' '}
      <strong>verify_dlog_eq</strong> in{' '}
      <span className="mi">cashu/core/crypto/ps.py</span>.
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
            Sender hands over the credential + <MathTex tex={'s'} /> offline as
            a bearer token (<span className="mi">psnft1…</span>).
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
            <MathTex tex={'N = s\\cdot G_{\\text{NULL}}'} /> is FRESH (never
            seen), records it, then re-issues a credential over the same{' '}
            <MathTex tex={'h'} /> bound to the receiver's new secret.
          </p>
        </div>
      </div>
      <div className="step">
        <div className="step-num">4</div>
        <div className="step-body">
          <p>Spent nullifier = rejected — same as double-spent ecash.</p>
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
      Instead of revealing <MathTex tex={'h'} />, the owner reveals{' '}
      <MathTex tex={"U_h = h\\cdot u'"} /> with a Chaum–Pedersen proof. The
      pairing becomes:
    </p>
    <div className="math d1">
      <MathTex
        display
        tex={"e(v',\\ g_2) = e(u',\\ X_2) \\cdot e(U_h,\\ Y_{h2}) \\cdot e(U_s,\\ Y_{s2})"}
      />
    </div>
    <div className="card d2">
      <h3>Blind re-issuance</h3>
      <ul>
        <li>
          Mint derives a fresh base deterministically from the nullifier:{' '}
          <MathTex tex={'u_2 = k_2\\cdot g_1'} /> with{' '}
          <MathTex tex={'k_2 = \\text{HMAC}_x(\\text{nullifier})'} /> — the
          two-round protocol is stateless
        </li>
        <li>
          Owner shows <MathTex tex={'W_h = h\\cdot u_2'} /> with a dlog-eq
          proof that the same <MathTex tex={'h'} /> sits in{' '}
          <MathTex tex={'U_h'} /> and <MathTex tex={'W_h'} />
        </li>
        <li>
          Mint computes{' '}
          <MathTex
            tex={'v_2 = x\\cdot u_2 + y_h\\cdot W_h + (k_2\\cdot y_s)\\cdot S_{\\text{new}}'}
          />{' '}
          without ever learning <MathTex tex={'h'} />
        </li>
      </ul>
    </div>
    <div className="callout amber d3">
      <strong>Scope:</strong> this is honest-but-curious privacy for the asset
      id — <MathTex tex={'h'} /> never leaves the wallet, but the mint sees
      THAT a transfer happened and can correlate old/new owner commitments. Not
      full KVAC anonymity.
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
            compressed <MathTex tex={'G_1'} /> point
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
            3 compressed <MathTex tex={'G_2'} /> points
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

const SLIDES = [Slide0, Slide1, Slide2, Slide3, Slide4, Slide5, Slide6, SlideProofs, SlideChaumPedersen, Slide7, Slide8, Slide9]

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

const WIDE = new Set([1, 2, 4, 7, 8, 9, 11])

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

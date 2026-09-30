import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Dialog } from '@base-ui/react/dialog';
import { motion, useReducedMotion, useSpring, useTransform } from 'motion/react';
import { Toaster, toast } from 'sonner';
import { ArrowUpRight, ArrowDownToLine, ArrowLeft, Plus, Fingerprint, ShieldCheck, ShieldX,
  KeyRound, Copy, Check, X, Sparkles, ImagePlus, ScanLine, RotateCcw, Eye, Link, LoaderCircle,
  Layers3, MoveHorizontal, Download, CircleHelp, WalletCards } from 'lucide-react';
import '@fontsource/unbounded/600.css';
import '@fontsource/unbounded/800.css';
import '@fontsource/manrope/400.css';
import '@fontsource/manrope/600.css';
import '@fontsource/manrope/700.css';
import './style.css';
import { newPrivateKey, profileKey, signClaim, validateKeyset } from './crypto.mjs';
import { checked, download, getJSON, signedRequest } from './api.mjs';

const KEYRING = 'cashu-nft-keys-v1', ACTIVE = 'cashu-nft-active-v1', MINT_PIN = 'cashu-nft-mint-v1';
const short = (s) => s ? `${s.slice(0, 8)}…${s.slice(-6)}` : '';
const date = (n) => new Date(n * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
function storedKeys() {
  try { const keys = JSON.parse(localStorage.getItem(KEYRING) || '{}'); return keys && typeof keys === 'object' && !Array.isArray(keys) ? keys : {}; }
  catch { return {}; }
}
function initialIdentity() {
  try {
    const keys = storedKeys(), active = localStorage.getItem(ACTIVE);
    const secret = keys[active];
    return secret && profileKey(secret) === active ? { secret, pubkey: active } : null;
  } catch { return null; }
}
function routeKey() { return window.location.pathname.match(/^\/p\/([0-9a-f]{64})\/?$/)?.[1] || null; }

function Modal({ open, close, title, description, children, wide = false }) {
  return <Dialog.Root open={open} onOpenChange={(value) => { if (!value) close(); }}>
    <Dialog.Portal><Dialog.Backdrop className="modal-backdrop" />
      <Dialog.Popup className={`modal ${wide ? 'modal-wide' : ''}`}>
        <Dialog.Close className="icon-button modal-close" aria-label="Close"><X size={20} /></Dialog.Close>
        <Dialog.Title className="modal-title">{title}</Dialog.Title>
        <Dialog.Description className="modal-description">{description}</Dialog.Description>
        {children}
      </Dialog.Popup>
    </Dialog.Portal>
  </Dialog.Root>;
}

function PreviewArt({ variant = 0 }) {
  return <svg viewBox="0 0 500 540" role="img" aria-label="Illustrative holographic collectible, preview only">
    <defs>
      <radialGradient id={`art-bg-${variant}`}><stop stopColor={variant ? '#fd80f6' : '#b7c8ff'} /><stop offset="1" stopColor={variant ? '#351584' : '#251a50'} /></radialGradient>
      <linearGradient id={`art-body-${variant}`} x2=".8" y2="1"><stop stopColor="#e9ff8c" /><stop offset=".6" stopColor="#88edbf" /><stop offset="1" stopColor="#8786ff" /></linearGradient>
      <pattern id={`art-grid-${variant}`} width="35" height="35" patternUnits="userSpaceOnUse"><path d="M35 0H0V35" fill="none" stroke="#fff" opacity=".12" /></pattern>
    </defs>
    <rect width="500" height="540" fill={`url(#art-bg-${variant})`} />
    <rect width="500" height="540" fill={`url(#art-grid-${variant})`} />
    <circle cx="250" cy="243" r="190" fill="none" stroke="#c7ff86" strokeWidth="2" opacity=".55" />
    <circle cx="250" cy="243" r="170" fill="none" stroke="#fafff0" strokeDasharray="2 15" strokeWidth="4" opacity=".5" />
    <ellipse cx="250" cy="448" rx="125" ry="23" fill="#10082c" opacity=".6" />
    <path d="M130 316Q112 258 166 229Q161 150 215 160Q260 132 302 164Q356 142 348 233Q401 272 367 333L335 414Q252 442 171 411Z" fill={`url(#art-body-${variant})`} stroke="#172246" strokeWidth="9" />
    <ellipse cx="199" cy="207" rx="42" ry="51" fill="#f0ffe1" stroke="#172246" strokeWidth="8" />
    <ellipse cx="305" cy="207" rx="42" ry="51" fill="#f0ffe1" stroke="#172246" strokeWidth="8" />
    <rect x="167" y="190" width="67" height="39" rx="12" fill="#151327" />
    <rect x="272" y="190" width="67" height="39" rx="12" fill="#151327" />
    <path d="M177 199L193 219M283 199L299 219" stroke="#ecff80" strokeWidth="7" />
    <path d="M211 310Q254 345 298 307" fill="none" stroke="#172246" strokeWidth="9" strokeLinecap="round" />
    <circle cx="170" cy="287" r="17" fill="#ff78d7" opacity=".7" /><circle cx="336" cy="287" r="17" fill="#ff78d7" opacity=".7" />
    <path d="M239 352L255 338L271 354L254 379Z" fill="#d1a7ff" stroke="#172246" strokeWidth="4" />
    <g fill="#edff8c"><path d="M76 83L81 102L101 107L81 112L76 131L71 112L52 107L71 102Z"/><path d="M423 376L427 390L442 394L427 398L423 413L419 398L405 394L419 390Z"/></g>
  </svg>;
}

function Tilt({ children, interactive = false, className = '', flipped = false }) {
  const reduced = useReducedMotion();
  const rx = useSpring(0, { mass: 1, stiffness: 100, damping: 10 });
  const ry = useSpring(0, { mass: 1, stiffness: 100, damping: 10 });
  const turn = useSpring(0, { mass: 1, stiffness: 100, damping: 10 });
  const drag = useRef(null);
  useEffect(() => { reduced ? turn.jump(flipped ? 180 : 0) : turn.set(flipped ? 180 : 0); }, [flipped, reduced, turn]);
  const transform = useTransform([rx, ry, turn], ([x, y, t]) => `rotateX(${x}deg) rotateY(${y + t}deg)`);
  const move = (event) => {
    if (reduced) return;
    if (drag.current) {
      ry.set(Math.max(-60, Math.min(60, (event.clientX - drag.current.x) * .35)));
      rx.set(Math.max(-25, Math.min(25, (drag.current.y - event.clientY) * .12)));
    } else if (event.pointerType === 'mouse' && matchMedia('(hover: hover) and (pointer: fine)').matches) {
      const rect = event.currentTarget.getBoundingClientRect();
      ry.set(((event.clientX - rect.left) / rect.width - .5) * 24);
      rx.set(((event.clientY - rect.top) / rect.height - .5) * -20);
    }
  };
  const reset = () => { drag.current = null; rx.set(0); ry.set(0); };
  return <div className={`perspective ${className}`}>
    <motion.div className="tilt" style={{ transform: reduced ? `rotateY(${flipped ? 180 : 0}deg)` : transform }}
      onPointerMove={move} onPointerLeave={() => { if (!drag.current) reset(); }}
      onPointerDown={interactive && !reduced ? (e) => {
        if (!e.isPrimary || drag.current) return;
        drag.current = { x: e.clientX, y: e.clientY };
        e.currentTarget.setPointerCapture(e.pointerId);
      } : undefined}
      onPointerUp={reset} onPointerCancel={reset}>
      {children}
    </motion.div>
  </div>;
}

function CollectorCard({ card, verification, onSelect, preview = false, variant = 0, celebrate = false }) {
  const sent = card?.status === 'sent';
  return <article className={`collector ${sent ? 'collector-sent' : ''} ${celebrate ? 'new-card' : ''}`}>
    <Tilt className={preview ? 'preview-card' : ''}>
      <div className="card-shell">
        <div className="card-top"><span><Sparkles size={13} /> Cashu NFT</span><span>{preview ? 'Card preview' : short(card.h)}</span></div>
        <div className="card-image">{preview ? <PreviewArt variant={variant} /> : <img src={`/api/images/${card.h}.jpg`} alt={card.title} loading="lazy" />}
          <div className="foil-film" /><div className="card-image-vignette" />
          {sent && <span className="sent-stamp">Sent</span>}
        </div>
        <div className="card-bottom"><div><small>{preview ? 'The original file is the collectible' : date(card.created)}</small><h3>{preview ? (variant ? 'Rare energy' : 'Certified jpg enjoyer') : card.title}</h3></div>
          <Fingerprint size={31} strokeWidth={1.2} />
        </div>
        <div className="card-verification">{preview ? <><span className="status-dot" /> Illustrative preview</> : <ProofBadge result={verification} ready={card.status === 'ready'} />}</div>
      </div>
    </Tilt>
    {!preview && <button className="card-open" onClick={() => onSelect(card.id)} aria-label={`Inspect ${card.title}`}><span>Inspect card</span><ArrowUpRight size={17} /></button>}
  </article>;
}

function ProofBadge({ result, ready = false }) {
  if (!result) return <span className="badge muted"><LoaderCircle size={13} className="spinner" /> Checking ownership</span>;
  if (result.pending) return <span className="badge muted"><KeyRound size={13} /> Awaiting profile signature</span>;
  if (!result.valid) return <span className="badge bad"><ShieldX size={13} /> Verification failed</span>;
  if (result.state === 'SPENT') return <span className="badge muted"><ArrowUpRight size={13} /> Transferred</span>;
  if (result.state !== 'UNSPENT') return <span className="badge muted"><CircleHelp size={13} /> Verification unavailable</span>;
  return <span className="badge good"><ShieldCheck size={13} /> {ready ? 'Transfer ready' : 'Verified owner'}</span>;
}

function useVerification(profile, config, refresh) {
  const [results, setResults] = useState({});
  const worker = useRef(null), run = useRef(0);
  useEffect(() => {
    worker.current = new Worker(new URL('./verify.worker.js', import.meta.url), { type: 'module' });
    const current = worker.current;
    return () => { current.terminate(); worker.current = null; };
  }, []);
  useEffect(() => {
    if (!profile || !config || !worker.current) { setResults({}); return; }
    const id = ++run.current, proofs = {}, controller = new AbortController();
    worker.current.onmessage = async ({ data }) => {
      if (data.id !== id || run.current !== id || controller.signal.aborted) return;
      if (!data.done) { proofs[data.cardId] = data.result; return; }
      const valid = Object.entries(proofs).filter(([, r]) => r.valid);
      try {
        for (let i = 0; i < valid.length; i += 1000) {
          const chunk = valid.slice(i, i + 1000);
          const response = await checked(await fetch('/v1/nft/checkstate', { method: 'POST', cache: 'no-store', signal: controller.signal,
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nullifiers: chunk.map(([, r]) => r.nullifier) }) }));
          const payload = await response.json();
          const byNullifier = new Map(payload.states.map((s) => [s.nullifier, s.state]));
          for (const [, result] of chunk) result.state = byNullifier.get(result.nullifier) || 'unknown';
        }
      } catch { for (const [, result] of valid) result.state = 'unknown'; }
      if (run.current === id && !controller.signal.aborted) setResults({ ...proofs });
    };
    // Remove previous proof badges immediately if the credential/context changed.
    setResults({});
    worker.current.postMessage({ id, cards: profile.cards, profile: profile.pubkey, config });
    return () => { controller.abort(); };
  }, [profile, config, refresh]);
  return results;
}

function App() {
  const [identity, setIdentity] = useState(initialIdentity);
  const [pubkey, setPubkey] = useState(routeKey);
  const [config, setConfig] = useState(null), [fatal, setFatal] = useState('');
  const [profile, setProfile] = useState(null), [loading, setLoading] = useState(false), [profileError, setProfileError] = useState('');
  const [dialog, setDialog] = useState(null), [selected, setSelected] = useState(null), [flipped, setFlipped] = useState(false);
  const [busy, setBusy] = useState(''), [refresh, setRefresh] = useState(0), [visitor, setVisitor] = useState(false);
  const [generated, setGenerated] = useState(''), [inputKey, setInputKey] = useState(''), [name, setName] = useState(''), [backedUp, setBackedUp] = useState(false);
  const [openInput, setOpenInput] = useState(''), [file, setFile] = useState(null), [title, setTitle] = useState('');
  const [previewUrl, setPreviewUrl] = useState(''), [celebration, setCelebration] = useState(null);
  const recovery = useRef(false), reloadRef = useRef(null);
  const owner = Boolean(identity && identity.pubkey === pubkey && !visitor);
  const verification = useVerification(profile, config, refresh);
  const card = profile?.cards.find((c) => c.id === selected);
  const active = profile?.cards.filter((c) => c.status !== 'sent') || [];
  const sent = profile?.cards.filter((c) => c.status === 'sent') || [];

  const navigate = useCallback((key) => {
    window.history.pushState({}, '', key ? `/p/${key}` : '/');
    setPubkey(key); setProfile(null); setSelected(null); setVisitor(false);
    window.scrollTo({ top: 0, behavior: 'instant' });
  }, []);
  useEffect(() => { const pop = () => { setPubkey(routeKey()); setProfile(null); setSelected(null); }; window.addEventListener('popstate', pop); return () => window.removeEventListener('popstate', pop); }, []);
  useEffect(() => {
    getJSON('/api/config').then((data) => {
      validateKeyset(data);
      const pinned = localStorage.getItem(MINT_PIN);
      const buildPin = import.meta.env.VITE_MINT_KEYSET_ID;
      if ((pinned && pinned !== data.keyset_id) || (buildPin && buildPin !== data.keyset_id)) throw new Error('The mint identity has changed. Restore the original mint before using this app.');
      localStorage.setItem(MINT_PIN, data.keyset_id);
      setConfig(data);
    }).catch((e) => setFatal(e.message));
  }, []);
  const reload = useCallback(async (key = pubkey) => {
    if (!key) return;
    const data = await getJSON(`/api/profiles/${key}`);
    if (routeKey() === key) { setProfile(data); setProfileError(''); }
    return data;
  }, [pubkey]);
  reloadRef.current = reload;
  useEffect(() => {
    if (!pubkey) return;
    let disposed = false;
    setLoading(true); setProfileError('');
    getJSON(`/api/profiles/${pubkey}`).then((data) => { if (!disposed) setProfile(data); })
      .catch((e) => { if (!disposed) setProfileError(e.message); }).finally(() => { if (!disposed) setLoading(false); });
    const timer = setInterval(() => { if (document.visibilityState === 'visible') reloadRef.current(pubkey).catch(() => { setProfileError('Connection lost. Ownership status will refresh when the mint returns.'); setRefresh((r) => r + 1); }); }, 15000);
    return () => { disposed = true; clearInterval(timer); };
  }, [pubkey]);
  useEffect(() => {
    if (!file) { setPreviewUrl(''); return; }
    const url = URL.createObjectURL(file); setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  const finalize = useCallback(async (asset, secret) => {
    const body = JSON.stringify({ showing: asset.showing, signature: signClaim(secret, asset.showing) });
    return (await signedRequest(secret, `/api/profiles/${profileKey(secret)}/cards/${asset.id}/claim`, body, 'application/json')).json();
  }, []);
  useEffect(() => {
    const missing = owner && profile?.cards.filter((c) => c.status !== 'sent' && !c.signature);
    if (!missing?.length || recovery.current || busy) return;
    recovery.current = true;
    (async () => {
      try { for (const asset of missing) await finalize(asset, identity.secret); await reload(); }
      catch (e) { toast.error(`Ownership signing needs another try: ${e.message}`); }
      finally { recovery.current = false; }
    })();
  }, [profile, owner, identity, busy, finalize, reload]);

  const closeDialog = () => { if (busy) return; setDialog(null); setGenerated(''); setInputKey(''); setBackedUp(false); setFile(null); setTitle(''); };
  const openCreate = () => { setName(''); setGenerated(newPrivateKey()); setBackedUp(false); setDialog('create'); };
  const saveIdentity = (secret) => {
    const p = profileKey(secret), keys = storedKeys(); keys[p] = secret;
    localStorage.setItem(KEYRING, JSON.stringify(keys)); localStorage.setItem(ACTIVE, p);
    const next = { secret, pubkey: p }; setIdentity(next); return next;
  };
  const onboard = async (event) => {
    event.preventDefault(); setBusy('Opening your portfolio');
    try {
      const secret = dialog === 'create' ? generated : inputKey.trim().toLowerCase();
      const p = profileKey(secret);
      const response = await signedRequest(secret, `/api/profiles/${p}`, JSON.stringify({ name: name.trim() || 'Collector' }), 'application/json');
      const data = await response.json(); saveIdentity(secret);
      setDialog(null); setGenerated(''); setInputKey(''); setBackedUp(false);
      navigate(p); setProfile(data); toast.success('Your portfolio is unlocked.');
    } catch (e) { toast.error(e.message); } finally { setBusy(''); }
  };
  const chooseFile = (next) => {
    if (!next) return;
    if (!/\.jpe?g$/i.test(next.name)) { toast.error('Choose an original JPG file.'); return; }
    const allowance = dialog === 'receive' ? 65536 : 0;
    if (config && next.size > config.max_jpg_bytes + allowance) { toast.error(`Choose a JPG smaller than ${Math.round(config.max_jpg_bytes / 1024 / 1024)} MB.`); return; }
    setFile(next); setTitle(next.name.replace(/\.jpe?g$/i, '').slice(0, 80));
  };
  const upload = async (event) => {
    event.preventDefault(); if (!file || !owner) return;
    const mode = dialog; setBusy(mode === 'mint' ? 'Minting your JPG' : 'Receiving your JPG');
    let asset;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      asset = await (await signedRequest(identity.secret, `/api/profiles/${pubkey}/${mode}?title=${encodeURIComponent(title.trim() || 'Untitled JPG')}`, bytes, 'image/jpeg')).json();
      await finalize(asset, identity.secret);
      await reload(); setDialog(null); setFile(null); setSelected(asset.id); setFlipped(false); setCelebration(asset.id);
      toast.success(mode === 'mint' ? 'Your JPG is now a collectible.' : 'Collected. The original transfer is now spent.');
      setTimeout(() => setCelebration(null), 2500);
    } catch (e) {
      if (asset) { toast.error(`Card saved. Reopen your portfolio to finish its ownership signature: ${e.message}`); await reload().catch(() => {}); }
      else toast.error(e.message);
    } finally { setBusy(''); }
  };
  const exportCard = async () => {
    setBusy('Preparing the transfer JPG');
    try {
      const response = await signedRequest(identity.secret, `/api/profiles/${pubkey}/cards/${card.id}/export`);
      download(await response.blob(), `cashu-transfer-${card.h.slice(0, 12)}.jpg`);
      await reload(); toast.success('Transfer JPG downloaded. Send it as an original file.');
    } catch (e) { toast.error(e.message); } finally { setBusy(''); }
  };
  const cancelTransfer = async () => {
    setBusy('Canceling the transfer');
    try {
      const updated = await (await signedRequest(identity.secret, `/api/profiles/${pubkey}/cards/${card.id}/cancel`)).json();
      await finalize(updated, identity.secret); await reload(); toast.success('Canceled. Every previous transfer JPG is now invalid.');
    } catch (e) { toast.error(e.message); await reload().catch(() => {}); } finally { setBusy(''); }
  };
  const copy = async (text, message) => { try { await navigator.clipboard.writeText(text); toast.success(message); } catch { toast.error('Clipboard unavailable. Select and copy the text instead.'); } };
  const openProfile = (event) => {
    event.preventDefault();
    const match = openInput.trim().match(/(?:^|\/p\/)([0-9a-f]{64})(?:\/?$)/);
    if (!match) { toast.error('Enter a public key or a portfolio URL.'); return; }
    setDialog(null); navigate(match[1]);
  };

  return <>
    <div className="atmosphere" aria-hidden="true"><div className="aurora aurora-lime" /><div className="aurora aurora-violet" /><div className="starfield" /><div className="floor-grid" /></div>
    <header className="site-header"><a className="wordmark" href="/" onClick={(e) => { e.preventDefault(); navigate(null); }}><span className="brand-icon"><Layers3 size={25} /></span>Cashu <span>NFT</span></a>
      <nav aria-label="Main navigation"><button className="text-button" onClick={() => setDialog('how')}>How it works</button>
        {identity ? <button className="button button-glass" onClick={() => navigate(identity.pubkey)}><Fingerprint size={17} /><span>My portfolio</span><ArrowUpRight size={16} /></button> : <button className="button button-glass" onClick={() => { setName(''); setDialog('import'); }}><KeyRound size={17} /> Import key</button>}
      </nav>
    </header>
    {fatal ? <main className="error-page"><ShieldX size={42} /><h1>The mint is unavailable</h1><p>{fatal}</p><button className="button" onClick={() => window.location.reload()}>Try again</button></main> : !pubkey ? <main>
      <section className="hero">
        <div className="hero-copy"><div className="eyebrow"><span className="status-dot" /> Collect the file. Own the flex.</div>
          <h1>Your jpg.<br /><span className="chrome-type">Your flex.</span><span className="hero-sparkle" aria-hidden="true">✳</span></h1>
          <p className="hero-description">A gallery for your internet treasures.<br />Mint a JPG. Prove it’s yours. Pass it on.</p>
          <div className="hero-actions"><button className="button button-lime" onClick={openCreate} disabled={!config}><Plus size={18} /> Create portfolio <ArrowUpRight size={18} /></button><button className="button button-glass" onClick={() => setDialog('open')}><Eye size={18} /> Open profile</button></div>
          <div className="hero-footnote"><Fingerprint size={17} /><span>Your key. Your public collection. No wallet extension.</span></div>
        </div>
        <div className="hero-showcase"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="floating-label label-one"><ShieldCheck size={17} /> Proof, with your flex</div>
          <div className="hero-card-back"><CollectorCard preview variant={1} /></div><div className="hero-card-main"><CollectorCard preview /></div>
          <div className="floating-label label-two"><ImagePlus size={17} /> A JPG you can actually send</div><span className="showcase-star star-one">✦</span><span className="showcase-star star-two">✧</span>
        </div>
      </section>
      <section className="ritual-strip" aria-label="How collecting works"><div><span className="ritual-icon"><ImagePlus /></span><p><strong>Drop a JPG</strong><span>It becomes your collectible.</span></p></div><div><span className="ritual-icon"><ShieldCheck /></span><p><strong>Show your ownership</strong><span>Visitors verify the proof.</span></p></div><div><span className="ritual-icon"><ArrowUpRight /></span><p><strong>Pass the file on</strong><span>The next collector receives it.</span></p></div></section>
      <section className="manifesto"><span className="eyebrow">Less onboarding. More collecting.</span><h2>A collectible that<br /><em>travels as a picture.</em></h2><p>Your public page is your display case. Your private key unlocks it. When you send a transfer JPG, its ownership token travels inside the original file.</p><button className="text-link" onClick={() => setDialog('how')}>Meet your next obsession <ArrowUpRight size={18} /></button></section>
    </main> : <main className="portfolio-page">
      <button className="back-link" onClick={() => navigate(null)}><ArrowLeft size={16} /> Back to Cashu NFT</button>
      <section className="profile-banner"><div className="profile-avatar" style={{ '--avatar-hue': parseInt(pubkey.slice(0, 4), 16) % 360 }}><Fingerprint size={52} strokeWidth={1.2} /></div>
        <div className="profile-heading"><div className="eyebrow">{owner ? 'Your collector vault' : 'Public collector vault'}</div><h1>{profile?.name || 'Collector'}<span className="name-star" aria-hidden="true">✳</span></h1><button className="pubkey-button" title={pubkey} onClick={() => copy(pubkey, 'Public key copied.')}><span>{short(pubkey)}</span><Copy size={13} /></button></div>
        <div className="profile-actions"><button className="button button-glass" onClick={() => copy(window.location.href, 'Portfolio link copied.')}><Link size={17} /> Share profile</button>
          {identity?.pubkey === pubkey && <button className="text-button" onClick={() => setVisitor((v) => !v)}><Eye size={15} /> {visitor ? 'Owner view' : 'View as visitor'}</button>}
          {owner && <button className="text-button" onClick={() => setDialog('backup')}><KeyRound size={15} /> Back up key</button>}
          {!owner && <button className="text-button" onClick={() => { setName(''); setDialog('import'); }}><KeyRound size={15} /> Unlock a portfolio</button>}
        </div>
      </section>
      {profileError && <div className="notice" role="status">{profileError}{!profile && identity?.pubkey === pubkey && <button className="text-link" onClick={() => { setInputKey(identity.secret); setDialog('import'); }}>Create this portfolio</button>}</div>}
      <section className="collection-section"><div className="section-heading"><div><div className="eyebrow">The display case</div><h2>Collection <span className="count">{active.length}</span></h2></div>
        {owner && <div className="collection-actions"><button className="button button-glass" disabled={!!busy || !config} onClick={() => { setFile(null); setTitle(''); setDialog('receive'); }}><ArrowDownToLine size={17} /> Receive JPG</button><button className="button button-lime" disabled={!!busy || !config} onClick={() => { setFile(null); setTitle(''); setDialog('mint'); }}><Plus size={18} /> Mint a JPG</button></div>}
      </div>
      <div className="collection-meta"><span><span className="status-dot" /> Ownership checked in your browser</span><button className="text-button" onClick={() => { setRefresh((r) => r + 1); reload().catch((e) => toast.error(e.message)); }}><RotateCcw size={13} /> Verify now</button></div>
      {loading && !profile ? <div className="empty-state"><LoaderCircle className="spinner" /><p>Opening the display case…</p></div> : <div className="card-grid">
        {active.map((asset) => <CollectorCard key={asset.id} card={asset} verification={verification[asset.id]} celebrate={asset.id === celebration} onSelect={(id) => { setSelected(id); setFlipped(false); }} />)}
        {owner && <button className="add-card" onClick={() => { setFile(null); setTitle(''); setDialog('mint'); }} disabled={!!busy || !config}><span className="add-card-orbit"><Plus size={37} strokeWidth={1} /></span><strong>{active.length ? 'One more for the vault' : 'Your first flex starts here'}</strong><span>Upload a JPG. Mint it. Make it yours.</span><span className="add-card-link">Mint a JPG <ArrowUpRight size={16} /></span></button>}
        {!active.length && !owner && <div className="empty-state"><WalletCards size={40} /><h3>The display case is waiting</h3><p>This collector hasn’t added any JPGs yet.</p></div>}
      </div>}</section>
      <section className="sent-section"><div className="section-heading"><div><div className="eyebrow">Passed on, still part of the story</div><h2>Sent <span className="count">{sent.length}</span></h2></div><ArrowUpRight className="sent-section-arrow" size={30} /></div>
        {sent.length ? <div className="card-grid">{sent.map((asset) => <CollectorCard key={asset.id} card={asset} verification={verification[asset.id]} onSelect={(id) => { setSelected(id); setFlipped(false); }} />)}</div> : <p className="sent-empty">Cards appear here after their transfer JPG is redeemed.</p>}
      </section>
    </main>}
    <footer className="site-footer"><span className="footer-brand"><Layers3 size={17} /> Cashu NFT</span><span>JPGs with a little more soul.</span><button className="text-button" onClick={() => setDialog('how')}>How ownership works <ArrowUpRight size={14} /></button></footer>

    <Modal open={dialog === 'create' || dialog === 'import'} close={closeDialog} title={dialog === 'create' ? 'Your collection starts with a key' : 'Unlock your portfolio'} description={dialog === 'create' ? 'Save your private key before you start. It unlocks your portfolio on any browser.' : 'Enter your private key. Your public profile and collection will reopen.'}>
      <form onSubmit={onboard}>
        {dialog === 'create' ? <><label className="field-label" htmlFor="collection-name">Collection name</label><input id="collection-name" maxLength={40} placeholder="A very serious JPG collection" value={name} onChange={(e) => setName(e.target.value)} />
          <div className="key-box"><div><KeyRound size={15} /> Your private key <span>Keep this private</span></div><textarea readOnly aria-label="Generated private key" value={generated} spellCheck={false} /><button type="button" className="text-link" onClick={() => download(new Blob([generated + '\n'], { type: 'text/plain' }), 'cashu-nft-private-key.txt')}><Download size={15} /> Download key backup</button></div>
          <label className="checkbox-label"><input type="checkbox" checked={backedUp} onChange={(e) => setBackedUp(e.target.checked)} /><span>I saved my key. Losing it means losing access to this profile.</span></label>
        </> : <><label className="field-label" htmlFor="private-key">Private key</label><input id="private-key" type="password" autoComplete="off" placeholder="64-character private key" spellCheck={false} value={inputKey} onChange={(e) => setInputKey(e.target.value)} required /><p className="field-help">Your key stays in this browser. It is never sent to the mint.</p></>}
        <button className="button button-lime full-width" disabled={!!busy || (dialog === 'create' && !backedUp)}>{busy ? <LoaderCircle className="spinner" size={17} /> : <Fingerprint size={18} />}{busy || (dialog === 'create' ? 'Create my portfolio' : 'Unlock portfolio')}<ArrowUpRight size={18} /></button>
        <p className="fine-print">The mint stores your NFTs and bearer credentials. Your key authorizes owner actions. This browser remembers your key.</p>
      </form>
    </Modal>
    <Modal open={dialog === 'open'} close={closeDialog} title="Open a collector’s portfolio" description="Paste their public key or the link to their Cashu NFT profile."><form onSubmit={openProfile}><label className="field-label" htmlFor="profile-link">Public key or profile link</label><input id="profile-link" value={openInput} onChange={(e) => setOpenInput(e.target.value)} placeholder="Public key or /p/…" required /><button className="button button-lime full-width"><Eye size={18} /> Open profile <ArrowUpRight size={17} /></button></form></Modal>
    <Modal open={dialog === 'mint' || dialog === 'receive'} close={closeDialog} title={dialog === 'mint' ? 'Make a JPG yours' : 'Collect a transfer JPG'} description={dialog === 'mint' ? 'Pick an original JPG. We’ll mint it and add it to your display case.' : 'Upload the original transfer file. We’ll match its picture to its token before redeeming it.'}>
      <form onSubmit={upload}><label className={`upload-zone ${file ? 'has-file' : ''}`} onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); chooseFile(e.dataTransfer.files[0]); }}>
        <input type="file" accept="image/jpeg,.jpg,.jpeg" onChange={(e) => chooseFile(e.target.files[0])} disabled={!!busy} aria-label={dialog === 'mint' ? 'Choose JPG to mint' : 'Choose transfer JPG to receive'} />
        {file ? <><img src={previewUrl} alt="JPG upload preview" /><span><Check size={16} /> {file.name}</span></> : <><ImagePlus size={35} strokeWidth={1.3} /><strong>Drop your JPG here</strong><span>or click to choose a file · up to {Math.round((config?.max_jpg_bytes || 10485760) / 1048576)} MB</span></>}
      </label><label className="field-label" htmlFor="card-title">Card title</label><input id="card-title" maxLength={80} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Give your collectible a name" disabled={!!busy} />
        {dialog === 'receive' && <p className="field-help">Use a file attachment. Screenshots, edited images and metadata-stripped copies cannot transfer ownership.</p>}
        <button className="button button-lime full-width" disabled={!file || !!busy}>{busy ? <LoaderCircle size={18} className="spinner" /> : <Sparkles size={18} />}{busy || (dialog === 'mint' ? 'Mint and add to collection' : 'Receive and add to collection')}</button>
      </form>
    </Modal>
    <Modal open={dialog === 'backup'} close={closeDialog} title="Keep your collection key safe" description="Anyone with this key can act as your profile. Save a private backup outside browser storage."><div className="key-box"><textarea readOnly aria-label="Your private key" value={identity?.secret || ''} spellCheck={false} /><button className="button button-lime full-width" onClick={() => download(new Blob([identity.secret + '\n'], { type: 'text/plain' }), 'cashu-nft-private-key.txt')}><Download size={17} /> Download key backup</button></div></Modal>
    <Modal open={dialog === 'how'} close={closeDialog} title="A JPG. A proof. A new collector." description="Your display case is public. Your private key controls your profile."><div className="how-steps"><div><ImagePlus /><h3>Mint your JPG</h3><p>The app prepares a clean JPG, mints it for free, and stores the file and its bearer credential at the mint.</p></div><div><ShieldCheck /><h3>Show it’s yours</h3><p>Your browser signs an ownership showing. Visitors check the proof and your profile signature locally, then ask the mint whether it is still unspent.</p></div><div><ArrowUpRight /><h3>Send the original file</h3><p>A transfer download embeds its bearer token in EXIF. Anyone with that original file can receive it. The first successful redemption wins.</p></div><div><RotateCcw /><h3>Changed your mind?</h3><p>Cancel a transfer before it is redeemed. The credential rotates, invalidating every previous transfer file.</p></div></div><p className="fine-print">The mint is a custodian. Public image downloads and ownership proofs never contain bearer tokens. Mint identity is remembered on your first visit.</p></Modal>

    <Modal open={!!card} close={() => { if (!busy) setSelected(null); }} title={card?.title || 'Collectible'} description={card?.status === 'sent' ? 'Part of this collector’s history. Current ownership has moved on.' : 'A collectible JPG with a verifiable ownership showing.'} wide>
      {card && <div className="card-detail"><div className="detail-art"><Tilt interactive flipped={flipped}><div className={`card-shell detail-face ${card.status === 'sent' ? 'detail-sent' : ''}`}><div className="card-top"><span><Sparkles size={13} /> Cashu NFT</span><span>{short(card.h)}</span></div><div className="card-image"><img src={`/api/images/${card.h}.jpg`} alt={card.title} /><div className="foil-film" /></div><div className="card-bottom"><h3>{card.title}</h3><Fingerprint size={30} /></div><div className="card-verification"><ProofBadge result={verification[card.id]} ready={card.status === 'ready'} /></div></div>
        <div className="card-back-face"><Fingerprint size={66} strokeWidth={.8} /><h3>Proof of your flex</h3><p>One JPG. One credential.<br />A verifiable collector.</p><div className="back-key">{short(card.h)}</div><ShieldCheck size={31} /></div></Tilt>
        <button className="text-button rotate-button" onClick={() => setFlipped((v) => !v)}><RotateCcw size={15} /> Flip card <span><MoveHorizontal size={14} /> Drag to rotate</span></button>
      </div><div className="detail-info"><div className="eyebrow">The ownership receipt</div><div className="proof-heading"><ProofBadge result={verification[card.id]} ready={card.status === 'ready'} /></div><dl><div><dt>Collector</dt><dd>{short(card.pubkey)}</dd></div><div><dt>Asset</dt><dd>{short(card.h)}</dd></div><div><dt>Added</dt><dd>{date(card.created)}</dd></div>{card.sent && <div><dt>Transferred</dt><dd>{date(card.sent)}</dd></div>}</dl>
        <div className="verification-checks"><p><span>{verification[card.id]?.valid ? <Check /> : <ScanLine />}</span>NFT showing and profile signature</p><p><span>{verification[card.id]?.state === 'UNSPENT' ? <Check /> : <CircleHelp />}</span>Live mint ownership status</p><small>Proofs are checked in your browser. Current ownership depends on the mint’s live response.</small></div>
        {owner && card.status !== 'sent' && <><button className="button button-lime full-width" onClick={exportCard} disabled={!!busy || !card.signature}><Download size={17} />{busy || 'Download transfer JPG'}</button><p className="field-help">Anyone with this file can receive the NFT. Send the original as a file attachment.</p>{card.status === 'ready' && <button className="button button-glass full-width" disabled={!!busy} onClick={cancelTransfer}><RotateCcw size={17} /> Cancel transfer</button>}</>}
        <button className="text-link" onClick={() => download(new Blob([JSON.stringify({ ...card, mint: { keyset_id: config.keyset_id, public_key: config.public_key } }, null, 2)], { type: 'application/json' }), `cashu-ownership-${card.h.slice(0, 12)}.json`)}><ShieldCheck size={16} /> Download public proof</button>
        <a className="text-link" href={`/api/images/${card.h}.jpg`} download={`cashu-${card.h.slice(0, 12)}.jpg`}><ImagePlus size={16} /> Save image without transfer token</a>
      </div></div>}
    </Modal>
    <Toaster theme="dark" position="bottom-right" richColors closeButton />
  </>;
}

createRoot(document.getElementById('root')).render(<App />);

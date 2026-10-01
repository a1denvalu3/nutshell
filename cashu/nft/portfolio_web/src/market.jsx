// Marketplace and ordinary-wallet screens. Protocol, journal and Coco logic
// live in src/market/ and src/money/; this file is UI only.
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { toast } from 'sonner';
import { ArrowDownToLine, ArrowLeft, ArrowUpFromLine, Clock, Coins, Plus, Search, Store, Tag, Wallet, Zap } from 'lucide-react';
import { getJSON } from './api.mjs';
import { Button, CheckRow, CopyChip, HoldButton, Identicon, Modal, Notice, Spinner, Tilt, panel, short, useTint } from './ui.jsx';
import { Segmented, ago, imageUrl } from './social.jsx';

const loadMoney = () => import('./money/wallet.ts');
export const sats = (n) => `${Number(n || 0).toLocaleString()} sat${Number(n) === 1 ? '' : 's'}`;
const when = (t) => new Date(t * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const LIFETIMES = [[6 * 3600, '6 hours'], [24 * 3600, '24 hours'], [3 * 86400, '3 days'], [7 * 86400, '7 days']];
const host = (url) => { try { return new URL(url).host + new URL(url).pathname.replace(/\/$/, ''); } catch { return url; } };

const EVENT_TEXT = {
  offer_received: (p) => `New offer: ${sats(p.price)}.`,
  offer_funded: () => 'Your offer is funded. It’s safe to close this tab.',
  offer_declined: () => 'Your offer was declined. Your funds return after its deadline.',
  offer_lost: () => 'Another offer won this NFT. Your funds return after the deadline.',
  purchased: (p) => `You bought ${p.title || 'an NFT'}. Syncing it to your wallet.`,
  sold: (p) => `Sold for ${sats(p.price)}. Payment is on its way.`,
  paid: (p) => `Payment received: ${sats(p.price)}.`,
  refunded: () => 'Refund received.',
  payment_attention: () => 'A payment needs attention. Open Offers for details.',
  payment_lost_race: () => 'A payment lost a race with its other branch. Open Offers for details.',
};

/* ---------- state: ordinary wallet + inbox ---------- */

// Which Offers tab an inbox event belongs to.
const EVENT_TAB = { offer_received: 'received', sold: 'received', paid: 'received', offer_funded: 'made', offer_declined: 'made', offer_lost: 'made', purchased: 'made', refunded: 'made', payment_lost_race: null, payment_attention: null };
const eventTab = (e) => EVENT_TAB[e.kind] ?? (e.payload?.kind === 'claim' ? 'received' : 'made');

export function useMarket(identity, nftWallet, open) {
  const [money, setMoney] = useState(null), [state, setState] = useState('closed'), [error, setError] = useState('');
  const [balances, setBalances] = useState([]), [unread, setUnread] = useState(0), [version, setVersion] = useState(0);
  const [config, setConfig] = useState(null);
  const moneyRef = useRef(null), nftRef = useRef(nftWallet), openRef = useRef(open);
  nftRef.current = nftWallet; openRef.current = open;
  const bump = () => setVersion((v) => v + 1);

  useEffect(() => { getJSON('/api/market/config').then(setConfig).catch(() => {}); }, []);
  const refresh = useCallback(async () => {
    const wallet = moneyRef.current;
    if (!wallet) return;
    setBalances(await wallet.balances());
  }, []);
  const reconcile = useCallback(async () => {
    const wallet = moneyRef.current;
    if (!wallet || wallet.readOnly) return;
    const { changed, attention } = await wallet.reconcile(nftRef.current || undefined);
    if (attention.length) setError(attention[0]);
    if (changed) bump();
    await refresh();
  }, [refresh]);

  useEffect(() => {
    if (!identity || !config) return;
    let disposed = false, wallet = null;
    setState('opening'); setError('');
    loadMoney().then(({ MoneyWallet }) => MoneyWallet.open(identity.secret, { devMints: config.dev_mints }))
      .then(async (opened) => {
        if (disposed) { await opened.dispose(); return; }
        wallet = opened; moneyRef.current = opened; setMoney(opened);
        setState(opened.readOnly ? 'elsewhere' : 'ready');
        await refresh();
        await reconcile().catch((e) => setError(e.message));
      })
      .catch((e) => { if (!disposed) { setState('error'); setError(e.message); } });
    return () => { disposed = true; moneyRef.current = null; setMoney(null); if (wallet) wallet.dispose().catch(() => {}); };
  }, [identity, config, refresh, reconcile]);

  // Purchases recover once the NFT wallet is open too.
  useEffect(() => { if (nftWallet && moneyRef.current) reconcile().catch(() => {}); }, [nftWallet, reconcile]);

  // Private inbox: authenticated long-poll from a stored cursor; on return,
  // missed events replay and reconciliation reads authoritative state.
  useEffect(() => {
    if (!money) return;
    let stop = false;
    const key = `cashu-market-cursor:${identity.pubkey}`;
    let cursor = Number(localStorage.getItem(key) || 0), first = !localStorage.getItem(key);
    (async () => {
      while (!stop) {
        try {
          const wait = document.visibilityState === 'visible' ? 25 : 0;
          const data = await money.api.inbox(cursor, first ? 0 : wait);
          if (stop) return;
          // Store the cursor before publishing the unread count, so "mark read"
          // always covers every event the badge counted.
          if (data.events.length) { cursor = data.cursor; localStorage.setItem(key, String(cursor)); }
          setUnread(data.unread);
          for (const e of data.events) {
            if (first || e.read) continue;
            toast(EVENT_TEXT[e.kind]?.(e.payload) || 'Marketplace update.', { action: { label: 'View', onClick: () => openRef.current?.(`/offers?tab=${eventTab(e)}`) } });
          }
          if (data.events.length) { bump(); await reconcile().catch(() => {}); }
          first = false;
          if (!wait) await new Promise((r) => setTimeout(r, 15000));
        } catch { await new Promise((r) => setTimeout(r, 10000)); }
      }
    })();
    return () => { stop = true; };
  }, [money, identity, reconcile]);

  const markRead = useCallback(async () => {
    if (!money) return;
    const key = `cashu-market-cursor:${identity.pubkey}`;
    await money.api.markRead(Number(localStorage.getItem(key) || 0)).catch(() => {});
    setUnread(0);
  }, [money, identity]);
  const takeOver = async () => {
    if (!money) return;
    await money.takeOver(); setState(money.readOnly ? 'elsewhere' : 'ready'); await reconcile();
  };
  return { money, state, error, balances, unread, version, config, refresh, reconcile, markRead, takeOver, bump };
}

function TestBadge({ on }) { return on ? <span className="badge badge-warn">Test sats</span> : null; }
function Price({ value, big }) { return <span className={`price ${big ? 'price-lg' : ''}`}><Tag size={big ? 18 : 13} />{sats(value)}</span>; }

/* ---------- browse ---------- */

function ListingCard({ item, index, onOpen }) {
  const [tint, onLoad] = useTint(item.h);
  return <motion.div className="card-slot" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(index, 10) * .035, type: 'spring', stiffness: 260, damping: 26 }}>
    <Tilt>
      <button className="nft-card" style={tint ? { '--tint': tint } : undefined} onClick={() => onOpen(item)} aria-label={`Open ${item.title}`}>
        <div className="nft-media"><img src={imageUrl(item.h)} alt="" loading="lazy" decoding="async" onLoad={onLoad} />{item.state === 'reserved' && <span className="media-tag">Sale in progress</span>}</div>
        <div className="nft-body">
          <span className="nft-title">{item.title || 'Untitled'}</span>
          <span className="nft-meta"><span className="owner-chip"><Identicon pubkey={item.seller} size={18} /><span className="ellipsis">{item.seller_name || 'Collector'}</span></span><Price value={item.price} /></span>
        </div>
      </button>
    </Tilt>
  </motion.div>;
}

export function MarketPage({ navigate }) {
  const [items, setItems] = useState(null), [more, setMore] = useState(false), [sort, setSort] = useState('new'), [query, setQuery] = useState('');
  const [q, setQ] = useState('');
  useEffect(() => { const t = setTimeout(() => setQ(query.trim()), 250); return () => clearTimeout(t); }, [query]);
  const load = useCallback(async (offset = 0) => {
    const data = await getJSON(`/api/market/listings?sort=${sort}&q=${encodeURIComponent(q)}&limit=24&offset=${offset}`);
    setItems((prev) => offset ? [...(prev || []), ...data.items] : data.items); setMore(data.more);
  }, [sort, q]);
  useEffect(() => { setItems(null); load(0).catch((e) => { toast.error(e.message); setItems([]); }); }, [load]);
  return <main className="page explore">
    <header className="page-head">
      <div><span className="pill"><Store size={14} />Market</span><h1>NFTs for sale</h1></div>
      <p className="muted page-lede">Offers are paid upfront in ecash and held in a time lock. If the seller doesn’t accept, the money comes back automatically.</p>
    </header>
    <div className="toolbar">
      <label className="search"><Search size={17} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by title" aria-label="Search listings" /></label>
      <div className="sorts">{[['new', 'Newest'], ['price_asc', 'Price: low to high'], ['price_desc', 'Price: high to low']].map(([k, l]) =>
        <button key={k} className={`sort ${sort === k ? 'is-active' : ''}`} onClick={() => setSort(k)}>{l}</button>)}</div>
    </div>
    {!items ? <div className="grid">{Array.from({ length: 8 }, (_, i) => <div key={i} className="nft-card skeleton" />)}</div>
      : !items.length ? <div className="empty"><strong>Nothing listed yet</strong><span className="muted">{q ? 'Try a different search.' : 'Open one of your NFTs and choose List for sale.'}</span></div>
        : <div className="grid">{items.map((item, i) => <ListingCard key={item.id} item={item} index={i} onOpen={(l) => navigate(`/market/${l.id}`)} />)}</div>}
    {more && <div className="load-more"><Button variant="secondary" onClick={() => load(items.length)}>Load more</Button></div>}
  </main>;
}

/* ---------- listing detail + funded offer ---------- */

export function ListingPage({ id, navigate, identity, market, onStart, startOffer }) {
  const [listing, setListing] = useState(null), [error, setError] = useState('');
  const [step, setStep] = useState('info'), [mint, setMint] = useState(''), [price, setPrice] = useState(''), [lifetime, setLifetime] = useState(24 * 3600);
  const [quote, setQuote] = useState(null), [quoteError, setQuoteError] = useState(''), [busy, setBusy] = useState(''), [done, setDone] = useState(null);
  useEffect(() => { getJSON(`/api/market/listings/${id}`).then((l) => { setListing(l); setPrice(String(l.price)); }).catch((e) => setError(e.message)); }, [id]);
  const funded = market.balances.filter((b) => b.available > 0);
  useEffect(() => { if (!mint && funded.length) setMint(funded[0].mint); }, [funded.length]); // eslint-disable-line react-hooks/exhaustive-deps
  const amount = Number(price);
  // Returning from the wallet (?offer=1): open the offer form once it can be used.
  const autoOpened = useRef(false);
  useEffect(() => {
    if (!startOffer || autoOpened.current || !listing || !identity || market.state !== 'ready') return;
    if (identity.pubkey === listing.seller || listing.state !== 'active') return;
    autoOpened.current = true; setStep('offer');
  }, [startOffer, listing, identity, market.state]);
  useEffect(() => {
    if (step !== 'offer' || !mint || !market.money || !Number.isSafeInteger(amount) || amount < (listing?.price || 1)) { setQuote(null); return; }
    let live = true; setQuote(null); setQuoteError('');
    market.money.market.quote(mint, amount).then((q) => { if (live) setQuote(q); }).catch((e) => { if (live) setQuoteError(e.message); });
    return () => { live = false; };
  }, [step, mint, amount, market.money, listing?.price]);
  if (error) return <main className="page"><Notice tone="bad">{error}</Notice></main>;
  if (!listing) return <main className="page"><div className="feed-loading"><Spinner /> Loading listing…</div></main>;
  const mine = identity?.pubkey === listing.seller, open = listing.state === 'active';
  const balance = market.balances.find((b) => b.mint === mint);
  const deadline = Math.floor(Date.now() / 1000) + lifetime, acceptBy = deadline - (market.config?.accept_window || 3600);
  const enough = quote && balance && balance.available >= quote.amount;
  const fund = async () => {
    setBusy('Funding offer');
    try {
      const record = await market.money.market.makeOffer(listing, mint, { price: amount, lifetime });
      await market.refresh(); market.bump();
      if (record.stage !== 'registered') throw new Error(record.error || 'The offer was funded but not accepted by the marketplace. It refunds after its deadline.');
      setDone(record); setStep('done');
    } catch (e) { toast.error(e.message); await market.refresh().catch(() => {}); } finally { setBusy(''); }
  };
  return <main className="page listing">
    <button className="back" onClick={() => navigate('/market')}><ArrowLeft size={14} /> Market</button>
    <div className="detail">
      <div className="detail-art"><Tilt interactive max={8}><div className="nft-card detail-face"><div className="nft-media"><img src={imageUrl(listing.h)} alt={listing.title || ''} /></div>
        <div className="nft-body"><span className="nft-title">{listing.title}</span><span className="nft-meta"><span className="mono">{short(listing.h, 6, 4)}</span><Price value={listing.price} /></span></div></div></Tilt></div>
      <div className="detail-side"><AnimatePresence mode="wait" initial={false}>
        {step === 'info' && <motion.div key="info" className="detail-panel" {...panel}>
          <div className="detail-head"><span className={`badge ${open ? 'badge-good' : 'badge-warn'}`}>{open ? 'For sale' : listing.state === 'reserved' ? 'Sale in progress' : 'Not for sale'}</span><h2>{listing.title}</h2></div>
          <Price value={listing.price} big />
          <dl className="props">
            <div><dt>Seller</dt><dd><button className="who" onClick={() => navigate(`/p/${listing.seller}`)}><Identicon pubkey={listing.seller} size={22} /><span>{listing.seller_name || short(listing.seller)}</span></button></dd></div>
            <div><dt>Listed</dt><dd>{ago(listing.updated)}</dd></div>
          </dl>
          <ul className="send-facts">
            <li><span className="mono">01</span>You pay now. The ecash is locked to this sale and can only go to the seller if they deliver this NFT to you.</li>
            <li><span className="mono">02</span>You can close the tab once the offer is funded. If it isn’t accepted, the money returns to you after the deadline.</li>
          </ul>
          {mine ? <Notice>This is your listing. Manage it from the NFT in your collection.</Notice>
            : !identity ? <Button variant="primary" size="lg" className="full" onClick={onStart}>Start a collection to make an offer</Button>
              : <Button variant="primary" size="lg" className="full" icon={<Coins size={16} />} disabled={!open || market.state !== 'ready'} onClick={() => setStep('offer')}>Make an offer</Button>}
          {identity && !mine && market.state === 'elsewhere' && <p className="hint">Your wallet is open on another device. Open Wallet to use it here.</p>}
        </motion.div>}
        {step === 'offer' && <motion.div key="offer" className="detail-panel" {...panel}>
          <button className="back" onClick={() => setStep('info')} disabled={!!busy}><ArrowLeft size={14} /> Back</button>
          <h2>Make an offer</h2>
          {!funded.length ? <Notice action={<Button size="sm" variant="secondary" onClick={() => navigate(`/wallet?then=/market/${id}`)}>Add ecash</Button>}>Add ecash to your wallet first. We’ll bring you back here.</Notice> : <>
            <label className="field"><span>Pay from</span><select value={mint} onChange={(e) => setMint(e.target.value)} disabled={!!busy}>
              {funded.map((b) => <option key={b.mint} value={b.mint}>{host(b.mint)} · {sats(b.available)}{b.testValue ? ' · test sats' : ''}</option>)}</select></label>
            <div className="row-2">
              <label className="field"><span>Your offer (seller receives)</span><input inputMode="numeric" value={price} onChange={(e) => setPrice(e.target.value.replace(/\D/g, ''))} disabled={!!busy} /></label>
              <label className="field"><span>Offer expires in</span><select value={lifetime} onChange={(e) => setLifetime(Number(e.target.value))} disabled={!!busy}>{LIFETIMES.map(([s, l]) => <option key={s} value={s}>{l}</option>)}</select></label>
            </div>
            {amount < listing.price && <p className="field-error">Offers must be at least the asking price of {sats(listing.price)}.</p>}
            {quoteError && <Notice tone="bad">{quoteError}</Notice>}
            {quote ? <dl className="fee-table">
              <div><dt>Seller receives</dt><dd>{sats(amount)}</dd></div>
              <div><dt>Mint fee for the seller’s claim</dt><dd>{sats(quote.fee)}</dd></div>
              <div className="total"><dt>Locked from your wallet</dt><dd>{sats(quote.amount)}{balance?.testValue && <TestBadge on />}</dd></div>
              <div><dt>Back to you if not accepted</dt><dd>{sats(quote.amount - quote.fee)}</dd></div>
              <div><dt>Seller can accept until</dt><dd>{when(acceptBy)}</dd></div>
              <div><dt>Refund available from</dt><dd>{when(deadline)}</dd></div>
            </dl> : !quoteError && amount >= listing.price && <div className="feed-loading"><Spinner /> Checking the mint…</div>}
            <p className="hint">Paid from <span className="mono">{mint}</span>. The seller decides whether to trust this mint. Funding may also cost a small mint fee for your own swap.</p>
            {quote && !enough && <p className="field-error">Not enough balance at this mint.</p>}
            {busy ? <Button variant="primary" size="lg" className="full" disabled icon={<Spinner />}>{busy}</Button>
              : <HoldButton disabled={!quote || !enough} onComplete={fund} icon={<Coins size={16} />}>Hold to fund offer</HoldButton>}
          </>}
        </motion.div>}
        {step === 'done' && <motion.div key="done" className="detail-panel" {...panel}>
          <span className="success-mark"><Clock size={24} /></span>
          <h2>Offer funded</h2>
          <p className="muted">It’s safe to close this tab. If the seller accepts, the NFT lands in your collection and syncs the next time you open it. If not, {sats(done.manifest.payment.amount - done.manifest.payment.refund_fee)} return to your wallet after {when(done.manifest.cash_deadline)}.</p>
          <Button variant="secondary" className="full" onClick={() => navigate('/offers?tab=made')}>See my offers</Button>
        </motion.div>}
      </AnimatePresence></div>
    </div>
  </main>;
}

/* ---------- seller controls on a card ---------- */

export function ListingControls({ card, market, nftWallet, busy, onChanged, navigate, onListing }) {
  const [listing, setListing] = useState(undefined), [price, setPrice] = useState(''), [mode, setMode] = useState(''), [working, setWorking] = useState('');
  const load = useCallback(() => getJSON(`/api/market/cards/${card.id}/listing`).then((r) => { setListing(r.listing); onListing?.(r.listing); }).catch(() => setListing(null)), [card.id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [load, market.version]);
  if (listing === undefined) return null;
  const run = async (label, fn, success) => {
    setWorking(label);
    try { await fn(); toast.success(success); setMode(''); await load(); await onChanged?.(); } catch (e) { toast.error(e.message); } finally { setWorking(''); }
  };
  const ready = market.money && market.state === 'ready' && nftWallet;
  const value = Number(price);
  if (listing) return <div className="pending-box listing-box">
    <div className="row-between"><strong>{listing.state === 'reserved' ? 'Sale in progress' : 'Listed for sale'}</strong><Price value={listing.price} /></div>
    {mode === 'edit' ? <div className="stack">
      <label className="field"><span>New asking price (sats)</span><input inputMode="numeric" value={price} onChange={(e) => setPrice(e.target.value.replace(/\D/g, ''))} autoFocus /></label>
      <p className="hint">Existing offers keep their terms. The new price applies to new offers.</p>
      <div className="row"><Button variant="primary" disabled={!ready || !value || !!working} icon={working ? <Spinner /> : null} onClick={() => run('Updating', () => market.money.market.revise(listing, value), 'Price updated.')}>Save price</Button>
        <Button variant="ghost" onClick={() => setMode('')}>Cancel</Button></div>
    </div> : <>
      <p>Buyers see the asking price. Sending is off while it’s listed; unlist first to send it.</p>
      {listing.state === 'active' && <div className="row">
        <Button variant="secondary" disabled={!ready || !!working || !!busy} onClick={() => { setPrice(String(listing.price)); setMode('edit'); }}>Edit price</Button>
        <Button variant="secondary" disabled={!ready || !!working || !!busy} icon={working ? <Spinner /> : null}
          onClick={() => run('Unlisting', () => market.money.api.unlist(listing.id), 'Unlisted. Pending offers were declined and refund at their deadlines.')}>Unlist</Button>
        <button className="link" onClick={() => navigate('/offers?tab=received')}>See offers</button>
      </div>}
    </>}
  </div>;
  if (card.status !== 'owned' || card.custody !== 'browser') return null;
  return mode === 'list' ? <div className="pending-box listing-box stack">
    <strong>List for sale</strong>
    <label className="field"><span>Asking price (sats you receive)</span><input inputMode="numeric" value={price} onChange={(e) => setPrice(e.target.value.replace(/\D/g, ''))} placeholder="e.g. 2100" autoFocus /></label>
    <p className="hint">Listing refreshes this NFT’s credential, so any transfer link or JPG you made before stops working. Buyers pay into a time lock; you get paid when you accept.</p>
    {working ? <Button variant="primary" className="full" disabled icon={<Spinner />}>{working}</Button>
      : <HoldButton disabled={!ready || !value} onComplete={() => run('Listing', () => market.money.market.list(nftWallet, card, value), 'Listed. It’s on the market now.')} icon={<Tag size={16} />}>Hold to list</HoldButton>}
    <Button variant="ghost" onClick={() => setMode('')}>Cancel</Button>
  </div> : <Button variant="secondary" size="lg" className="full" icon={<Tag size={16} />} disabled={!ready || !!busy} onClick={() => setMode('list')}>List for sale</Button>;
}

/* ---------- offers ---------- */

const LEG = {
  disposition: { funded: ['Waiting for seller', 'warn'], accepted: ['Accepted', 'good'], declined: ['Declined', ''], superseded: ['Another offer won', ''], closed: ['Closed', ''] },
  nft_leg: { unlocked: ['NFT with seller', ''], delivered: ['NFT delivered', 'good'] },
  cash_leg: { locked: ['Payment locked', 'warn'], claim_pending: ['Payment pending', 'warn'], claimed: ['Seller paid', 'good'], refund_pending: ['Refund pending', 'warn'], refunded: ['Refunded', 'good'], needs_attention: ['Needs attention', 'bad'] },
  publication: { awaiting_sync: ['Purchased · awaiting wallet sync', 'warn'], published: ['In collection', 'good'] },
};
function Legs({ offer }) {
  return <div className="legs">{['disposition', 'nft_leg', 'cash_leg', 'publication'].map((k) => {
    const v = LEG[k][offer[k]]; return v ? <span key={k} className={`badge ${v[1] ? 'badge-' + v[1] : ''}`}>{v[0]}</span> : null;
  })}</div>;
}

export function OffersPage({ navigate, market, nftWallet, cards, initialTab }) {
  const [tab, setTabState] = useState(initialTab), [offers, setOffers] = useState(null), [review, setReview] = useState(null);
  useEffect(() => { if (initialTab) setTabState(initialTab); }, [initialTab]);
  // Without an explicit tab, open the side with the most recent activity.
  useEffect(() => { if (!tab && offers) setTabState(offers[0]?.role === 'buyer' ? 'made' : 'received'); }, [tab, offers]);
  const setTab = (t) => { setTabState(t); window.history.replaceState({}, '', `/offers?tab=${t}`); };
  const load = useCallback(async () => { if (market.money) setOffers(await market.money.api.offers()); }, [market.money]);
  useEffect(() => { load().catch((e) => toast.error(e.message)); }, [load, market.version]);
  const { markRead, unread } = market;
  useEffect(() => { if (unread) markRead(); }, [markRead, unread]);
  if (market.state === 'opening' || market.state === 'closed') return <main className="page"><div className="feed-loading"><Spinner /> Opening your wallet…</div></main>;
  if (!market.money) return <main className="page"><Notice tone="bad">{market.error || 'Your wallet is unavailable.'}</Notice></main>;
  const shown = (offers || []).filter((o) => o.role === (tab === 'received' ? 'seller' : 'buyer'));
  return <main className="page offers">
    <header className="page-head"><div><span className="pill">Offers</span><h1>{!tab ? 'Offers' : tab === 'received' ? 'Offers on your NFTs' : 'Offers you made'}</h1></div>
      <Segmented id="offers" value={tab} onChange={setTab} options={[['received', 'Received'], ['made', 'Made']]} /></header>
    {market.state === 'elsewhere' && <Notice action={<Button size="sm" variant="secondary" onClick={market.takeOver}>Use it here</Button>}>Your wallet is open on another device.</Notice>}
    {!offers || !tab ? <div className="feed-loading"><Spinner /> Loading offers…</div>
      : !shown.length ? <div className="empty"><strong>{tab === 'received' ? 'No offers yet' : 'You haven’t made any offers'}</strong><span className="muted">{tab === 'received' ? 'List an NFT and offers show up here.' : 'Browse the market to find something you like.'}</span>
        <Button variant="secondary" onClick={() => navigate('/market')}>Go to market</Button></div>
        : <ul className="offer-list">{shown.map((o, i) => <motion.li key={o.id} className="offer-row" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i, 10) * .03 }}>
          <img className="offer-thumb" src={imageUrl(o.h)} alt="" loading="lazy" />
          <div className="offer-main">
            <div className="row-between"><strong className="ellipsis">{o.title || 'NFT'}</strong><Price value={o.price} /></div>
            <span className="muted small">{o.role === 'seller' ? `From ${o.buyer_name || short(o.buyer)}` : `To ${o.seller_name || short(o.seller)}`} · <span className="mono">{host(o.mint)}</span> <TestBadge on={o.test_value} /></span>
            <Legs offer={o} />
            {['locked', 'refund_pending', 'needs_attention'].includes(o.cash_leg) && <span className="muted small">{o.disposition === 'funded' ? `Accept by ${when(o.accept_deadline)} · ` : ''}Refund opens {when(o.cash_deadline)}</span>}
          </div>
          {o.role === 'seller' && o.disposition === 'funded' && <Button variant="primary" size="sm" onClick={() => setReview(o)}>Review</Button>}
        </motion.li>)}</ul>}
    <ReviewDialog offer={review} close={() => setReview(null)} market={market} nftWallet={nftWallet} cards={cards} onDone={() => { setReview(null); load(); market.bump(); }} />
  </main>;
}

function ReviewDialog({ offer, close, market, nftWallet, cards, onDone }) {
  const [check, setCheck] = useState(null), [busy, setBusy] = useState('');
  useEffect(() => {
    if (!offer) return; setCheck(null);
    market.money.api.offer(offer.id).then((full) => market.money.market.review(full).then((r) => setCheck({ ...r, full })))
      .catch((e) => setCheck({ ok: false, reasons: [e.message] }));
  }, [offer, market.money]);
  if (!offer) return null;
  const card = cards?.find((c) => c.id === offer.card_id);
  const accept = async () => {
    setBusy('Delivering NFT');
    try { await market.money.market.accept(nftWallet, check.full, card); toast.success('Sold. The NFT was delivered and your payment is being claimed.'); onDone(); }
    catch (e) { toast.error(e.message); } finally { setBusy(''); }
  };
  const decline = async () => {
    setBusy('Declining');
    try { await market.money.api.decline(offer.id); toast.success('Declined. The buyer’s funds return at the deadline.'); onDone(); } catch (e) { toast.error(e.message); } finally { setBusy(''); }
  };
  return <Modal open={!!offer} close={() => { if (!busy) close(); }} title={`Offer for ${offer.title || 'your NFT'}`} description="Check the payment before you deliver. Delivery is final.">
    <div className="stack">
      <dl className="fee-table">
        <div className="total"><dt>You receive</dt><dd>{sats(offer.price)} <TestBadge on={offer.test_value} /></dd></div>
        <div><dt>Paid with ecash from</dt><dd className="mono wrap">{offer.mint}</dd></div>
        <div><dt>Accept before</dt><dd>{when(offer.accept_deadline)}</dd></div>
        <div><dt>Buyer can reclaim from</dt><dd>{when(offer.cash_deadline)}</dd></div>
      </dl>
      {offer.test_value && <Notice>This offer is paid in test sats. They have no value.</Notice>}
      <ul className="checks">
        <CheckRow state={!check ? 'pending' : check.ok ? 'ok' : 'fail'} detail={check?.reasons?.join(' · ')}>Payment is genuine, locked to you and still unspent</CheckRow>
        <CheckRow state={card ? 'ok' : 'fail'} detail={card ? '' : 'Open your collection so your wallet can sign the delivery'}>NFT is in this browser’s wallet</CheckRow>
      </ul>
      <p className="hint">Only accept payments from mints you trust. Adding a mint to a buyer’s wallet doesn’t make it trustworthy.</p>
      {busy ? <Button variant="primary" size="lg" className="full" disabled icon={<Spinner />}>{busy}</Button>
        : <HoldButton disabled={!check?.ok || !card || !nftWallet} onComplete={accept} icon={<Zap size={16} />}>Hold to accept and deliver</HoldButton>}
      <Button variant="ghost" onClick={decline} disabled={!!busy}>Decline offer</Button>
    </div>
  </Modal>;
}

/* ---------- purchase projection in the collection ---------- */

export function PendingPurchases({ market }) {
  const [items, setItems] = useState([]);
  useEffect(() => { if (market.money) market.money.api.purchases().then((p) => setItems(p.filter((x) => x.publication !== 'published'))).catch(() => {}); }, [market.money, market.version]);
  return items.map((p) => <div key={p.id} className="card-slot"><div className="nft-card is-pending">
    <div className="nft-media"><img src={imageUrl(p.h)} alt="" /><span className="media-tag">Purchased · awaiting wallet sync</span></div>
    <div className="nft-body"><span className="nft-title">{p.title || 'NFT'}</span><span className="nft-meta"><span className="muted small">Delivered {ago(p.delivered)}</span><Spinner size={13} /></span></div>
  </div></div>);
}

/* ---------- wallet ---------- */

/** Onboarding banner on the wallet when the user came to make an offer. */
function Guide({ goal, balances, onContinue }) {
  const funded = balances.filter((b) => b.available > 0);
  const ready = goal && funded.some((b) => b.available > goal.price);
  return <motion.section className="guide" initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
    {goal && <img src={imageUrl(goal.h)} alt="" />}
    <div className="guide-text">
      <strong>{ready ? 'You’re ready to make your offer' : `Add ecash to make an offer${goal ? ` on ${goal.title || 'this NFT'}` : ''}`}</strong>
      <span>{ready ? `Your balance covers the asking price of ${sats(goal.price)}.`
        : goal ? <>It asks {sats(goal.price)} plus a small mint fee. {balances.length ? 'Top up' : 'Add a mint below, then top up'} or receive a token. We’ll bring you back to the NFT.</>
          : 'Loading the NFT…'}</span>
      {!balances.length && <span className="small">Just trying it out? Testnut gives free test sats with no value.</span>}
    </div>
    <Button variant={ready ? 'primary' : 'secondary'} icon={<ArrowLeft size={15} />} onClick={onContinue}>{ready ? 'Continue to offer' : 'Back to the NFT'}</Button>
  </motion.section>;
}

export function WalletPage({ market, navigate, then }) {
  const [dialog, setDialog] = useState(null), [mintUrl, setMintUrl] = useState(''), [busy, setBusy] = useState('');
  const [amount, setAmount] = useState(''), [token, setToken] = useState(''), [invoice, setInvoice] = useState(''), [result, setResult] = useState(null);
  const money = market.money, polling = useRef(0);
  // Onboarding for an offer: the listing the user came from (?then=/market/<id>).
  const [goal, setGoal] = useState(null);
  useEffect(() => {
    setGoal(null);
    if (then) getJSON(`/api/${then.slice(1).replace('market/', 'market/listings/')}`).then(setGoal).catch(() => setGoal(null));
  }, [then]);
  const backToGoal = (message) => { if (!then) return false; if (message) toast.success(message); navigate(`${then}?offer=1`); return true; };
  if (market.state === 'opening' || market.state === 'closed') return <main className="page"><div className="feed-loading"><Spinner /> Opening your wallet…</div></main>;
  if (!money) return <main className="page"><Notice tone="bad">{market.error || 'Your wallet is unavailable.'}</Notice></main>;
  const close = () => { polling.current++; if (!busy) { setDialog(null); setAmount(''); setToken(''); setInvoice(''); setResult(null); } };
  const act = async (label, fn) => { setBusy(label); try { return await fn(); } catch (e) { toast.error(e.message); return null; } finally { setBusy(''); await market.refresh().catch(() => {}); } };
  const addMint = (url) => act('Checking mint', async () => { const c = await money.addMint(url); toast.success(`Added ${c.name || host(c.url)}.`); setMintUrl(''); });
  const topUp = async () => {
    const r = await act('Creating invoice', () => money.topUp(dialog.mint, Number(amount)));
    if (!r) return;
    setResult(r);
    // Coco claims the quote in the background; this only follows it while the dialog is open.
    const run = ++polling.current;
    while (run === polling.current) {
      const s = await money.topUpState(r.operationId).catch(() => 'pending');
      if (s === 'finalized') {
        await market.refresh(); polling.current++; setDialog(null); setResult(null); setAmount('');
        if (!backToGoal(`Received ${sats(amount)}. Now make your offer.`)) toast.success(`Received ${sats(amount)}.`);
        return;
      }
      if (s === 'failed') { toast.error('The top-up failed.'); return; }
      await new Promise((res) => setTimeout(res, 2000));
    }
  };
  const send = () => act('Creating token', async () => setResult({ token: await money.send(dialog.mint, Number(amount)) }));
  const receive = () => act('Receiving', async () => {
    const r = await money.receive(token); close();
    if (!backToGoal(`Received ${sats(r.amount)}. Now make your offer.`)) toast.success(`Received ${sats(r.amount)}.`);
  });
  const withdrawQuote = () => act('Getting a quote', async () => setResult(await money.withdrawQuote(dialog.mint, invoice)));
  const withdraw = () => act('Paying invoice', async () => { await money.withdraw(result.operation.id); toast.success('Invoice paid.'); close(); });
  const shortcuts = (market.config?.mint_shortcuts || []).filter((s) => !market.balances.some((b) => b.mint === s.url));
  return <main className="page wallet-page">
    <header className="page-head"><div><span className="pill"><Wallet size={14} />Wallet</span><h1>Your ecash</h1></div>
      <Button variant="secondary" icon={<ArrowDownToLine size={15} />} onClick={() => setDialog({ kind: 'receive' })} disabled={money.readOnly}>Receive token</Button></header>
    {market.state === 'elsewhere' && <Notice action={<Button size="sm" variant="secondary" onClick={market.takeOver}>Use it here</Button>}>This wallet is open on another device. Using it here makes the other device read-only.</Notice>}
    {market.error && <Notice tone="bad">{market.error}</Notice>}
    {then && <Guide goal={goal} balances={market.balances} onContinue={() => backToGoal()} />}
    <p className="muted page-lede">Balances are per mint. Each mint holds its own ecash; nothing is exchanged between mints. Encrypted backups use your collection key.</p>
    <div className="balance-grid">
      {market.balances.map((b) => <motion.section key={b.mint} className="balance-card" layout>
        <div className="row-between"><span className="mono ellipsis" title={b.mint}>{host(b.mint)}</span><TestBadge on={b.testValue} /></div>
        <strong className="balance-big">{sats(b.available)}</strong>
        <dl className="balance-legs">
          {b.offerLocked > 0 && <div><dt>In offers</dt><dd>{sats(b.offerLocked)}</dd></div>}
          {b.pendingRefund > 0 && <div><dt>Refund pending</dt><dd>{sats(b.pendingRefund)}</dd></div>}
          {b.pendingClaim > 0 && <div><dt>Payment pending</dt><dd>{sats(b.pendingClaim)}</dd></div>}
          {b.reserved > 0 && <div><dt>Reserved</dt><dd>{sats(b.reserved)}</dd></div>}
        </dl>
        <div className="row">
          <Button size="sm" variant="primary" icon={<Zap size={14} />} disabled={money.readOnly} onClick={() => setDialog({ kind: 'topup', mint: b.mint })}>Top up</Button>
          <Button size="sm" variant="secondary" icon={<ArrowUpFromLine size={14} />} disabled={money.readOnly || !b.available} onClick={() => setDialog({ kind: 'send', mint: b.mint })}>Send</Button>
          <Button size="sm" variant="ghost" disabled={money.readOnly || !b.available} onClick={() => setDialog({ kind: 'withdraw', mint: b.mint })}>Withdraw</Button>
        </div>
      </motion.section>)}
      <section className="balance-card add-mint">
        <strong>Add a mint</strong>
        <div className="mint-shortcuts">{shortcuts.map((s) => <button key={s.url} className="chip" disabled={!!busy || money.readOnly} onClick={() => addMint(s.url)}>{s.name}</button>)}</div>
        <form className="row" onSubmit={(e) => { e.preventDefault(); addMint(mintUrl); }}>
          <input className="input" value={mintUrl} onChange={(e) => setMintUrl(e.target.value)} placeholder="https://mint.example" aria-label="Mint URL" />
          <Button type="submit" size="sm" variant="secondary" icon={busy === 'Checking mint' ? <Spinner /> : <Plus size={14} />} disabled={!mintUrl || !!busy || money.readOnly}>Add</Button>
        </form>
        <p className="hint">Shortcuts aren’t endorsements. Testnut pays its own invoices with test sats that have no value.</p>
      </section>
    </div>

    <Modal open={!!dialog} close={close} title={{ topup: 'Top up with Lightning', send: 'Send ecash', withdraw: 'Withdraw to Lightning', receive: 'Receive a token' }[dialog?.kind]} description={dialog?.mint ? host(dialog.mint) : 'Paste a Cashu token.'}>
      {dialog?.kind === 'receive' && <form className="stack" onSubmit={(e) => { e.preventDefault(); receive(); }}>
        <label className="field"><span>Token</span><textarea rows={4} value={token} onChange={(e) => setToken(e.target.value)} placeholder="cashuB…" spellCheck={false} /></label>
        <Button type="submit" variant="primary" className="full" disabled={!token || !!busy} icon={busy ? <Spinner /> : null}>{busy || 'Receive'}</Button>
      </form>}
      {(dialog?.kind === 'topup' || dialog?.kind === 'send') && (!result ? <form className="stack" onSubmit={(e) => { e.preventDefault(); dialog.kind === 'topup' ? topUp() : send(); }}>
        <label className="field"><span>Amount (sats)</span><input inputMode="numeric" value={amount} onChange={(e) => setAmount(e.target.value.replace(/\D/g, ''))} autoFocus /></label>
        <Button type="submit" variant="primary" className="full" disabled={!Number(amount) || !!busy} icon={busy ? <Spinner /> : null}>{busy || (dialog.kind === 'topup' ? 'Create invoice' : 'Create token')}</Button>
      </form> : result.invoice ? <div className="stack">
        <div className="link-box"><code className="mono">{result.invoice}</code><CopyChip value={result.invoice} display="Copy invoice" message="Invoice copied" /></div>
        <p className="muted"><Spinner size={13} /> Waiting for payment. You can close this; the wallet claims it when you’re back.</p>
      </div> : <div className="stack">
        <div className="link-box"><code className="mono">{result.token}</code><CopyChip value={result.token} display="Copy token" message="Token copied" /></div>
        <p className="muted">Treat this token like cash: whoever receives it first gets it.</p>
      </div>)}
      {dialog?.kind === 'withdraw' && (!result ? <form className="stack" onSubmit={(e) => { e.preventDefault(); withdrawQuote(); }}>
        <label className="field"><span>Lightning invoice</span><textarea rows={3} value={invoice} onChange={(e) => setInvoice(e.target.value)} placeholder="lnbc…" spellCheck={false} /></label>
        <Button type="submit" variant="primary" className="full" disabled={!invoice || !!busy} icon={busy ? <Spinner /> : null}>{busy || 'Get a quote'}</Button>
      </form> : <div className="stack">
        <dl className="fee-table"><div><dt>Invoice amount</dt><dd>{sats(Number(String(result.quote.amount)))}</dd></div><div><dt>Fee reserve</dt><dd>{sats(Number(String(result.quote.fee_reserve ?? result.quote.feeReserve ?? 0)))}</dd></div></dl>
        {busy ? <Button variant="primary" className="full" disabled icon={<Spinner />}>{busy}</Button> : <HoldButton onComplete={withdraw} icon={<Zap size={16} />}>Hold to pay invoice</HoldButton>}
      </div>)}
    </Modal>
  </main>;
}

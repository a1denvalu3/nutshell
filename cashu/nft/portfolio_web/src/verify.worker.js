import { verifyCard } from './crypto.mjs';
const cache = new Map();
self.onmessage = ({ data }) => {
  const { id, cards, profile, config } = data;
  for (const card of cards) {
    const key = [profile, config.public_key, card.h, card.showing, card.signature].join('|');
    let result = cache.get(key);
    if (!result) {
      result = verifyCard(card, profile, config);
      if (cache.size > 1000) cache.clear();
      cache.set(key, result);
    }
    self.postMessage({ id, cardId: card.id, result });
  }
  self.postMessage({ id, done: true });
};

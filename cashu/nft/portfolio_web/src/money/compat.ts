// Coco 2.0.0 was built against cashu-ts 4.x; this app pins cashu-ts
// 5.0.0-rc.11 (shared with the NFT wallet). Two seams differ, observed
// 2026-10-01 and recorded in MARKETPLACE_PLAN.md:
//
// 1. Coco calls `wallet.createLockedMintQuote(amount, pubkey)` for NUT-20
//    locked quotes; rc.11 folds it into `createMintQuoteBolt11(amount, pubkey)`.
// 2. rc.11 hands custom request functions a pre-serialized `requestBody`
//    string (so auth headers can bind the exact bytes) while Coco's request
//    function serializes again, sending a JSON string literal. The body is
//    parsed back with the same big-int-safe codec before it reaches Coco.
// 3. Nutshell reports quote `updated_at` in whole seconds. A quote paid in the
//    second it was created (FakeWallet mints such as testnut) comes back with
//    the same `updated_at` but new amounts, which Coco ignores as conflicting
//    accounting, so the top-up never completes. Dropping `updated_at` from
//    polled bolt11 mint quotes makes Coco use its monotonic paid/issued rule.
//
// Both shims are no-ops once the upstream signatures match again.
import { JSONInt, Mint, Wallet } from '@cashu/cashu-ts';

type RequestFn = (options: { requestBody?: unknown; endpoint?: string }) => Promise<unknown>;

const MINT_QUOTE = /\/v1\/mint\/quote\/bolt11(\/|$)/;

const PATCHED = Symbol('cashu-money-compat');
const DECODING = Symbol('cashu-money-compat-request');

function decodedBody(fn: RequestFn): RequestFn {
  return async (options) => {
    const response = await fn(
      typeof options.requestBody === 'string'
        ? { ...options, requestBody: JSONInt.parse(options.requestBody) }
        : options,
    );
    if (MINT_QUOTE.test(options.endpoint ?? '') && response && typeof response === 'object') {
      const { updated_at: _coarse, ...rest } = response as Record<string, unknown>;
      return rest;
    }
    return response;
  };
}

export function installCocoCompat(): void {
  const wallet = Wallet.prototype as unknown as Record<string, unknown>;
  if (typeof wallet.createLockedMintQuote !== 'function') {
    wallet.createLockedMintQuote = function (this: Wallet, amount: number, pubkey: string, description?: string) {
      return this.createMintQuoteBolt11(amount, pubkey, description);
    };
  }
  const mint = Mint.prototype as unknown as Record<string | symbol, unknown> & {
    requestWithAuth: (this: Record<string | symbol, unknown>, ...args: unknown[]) => Promise<unknown>;
  };
  if (mint[PATCHED]) return;
  const original = mint.requestWithAuth;
  mint.requestWithAuth = function (method, path, init, options) {
    if (!Object.prototype.hasOwnProperty.call(this, DECODING)) {
      this._request = decodedBody(this._request as RequestFn);
      this[DECODING] = true;
    }
    const custom = (options as { customRequest?: RequestFn } | undefined)?.customRequest;
    const next = custom ? { ...(options as object), customRequest: decodedBody(custom) } : options;
    return original.call(this, method, path, init, next);
  };
  mint[PATCHED] = true;
}

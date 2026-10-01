import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Social previews need absolute URLs. Set PUBLIC_URL (e.g. https://jpg.example)
// at build time; without it the tags fall back to same-origin paths.
const publicUrl = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const publicUrlTags = { name: 'public-url', transformIndexHtml: (html) => html.replaceAll('%PUBLIC_URL%', publicUrl) };

export default defineConfig({
  plugins: [react(), publicUrlTags],
  server: { proxy: { '/api': process.env.NFT_PORTFOLIO_API || 'http://127.0.0.1:8401', '/v1': process.env.NFT_PORTFOLIO_API || 'http://127.0.0.1:8401' } },
  build: { target: 'es2022', assetsInlineLimit: 0 },
  worker: { format: 'es' },
});

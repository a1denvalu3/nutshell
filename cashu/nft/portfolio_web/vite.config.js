import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': process.env.NFT_PORTFOLIO_API || 'http://127.0.0.1:8401', '/v1': process.env.NFT_PORTFOLIO_API || 'http://127.0.0.1:8401' } },
  build: { target: 'es2022', assetsInlineLimit: 0 },
  worker: { format: 'es' },
});

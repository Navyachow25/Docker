// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './', // ✅ Critical for production build in Docker/Nginx
  build: {
    outDir: 'dist'
  }
});

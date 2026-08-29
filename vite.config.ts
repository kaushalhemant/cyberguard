import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    base: './',
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:3000',
          changeOrigin: true,
        },
      },
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Ignore db.json to prevent infinite page reloads when backend logs database writes
      watch: {
        ignored: ['**/db.json', '**/db.json.tmp']
      },
    },
    build: {
      chunkSizeWarningLimit: 2000,
      rollupOptions: {
        external: ['canvg'],
        output: {
          manualChunks: {
            vendor: ['react', 'react-dom'],
            jspdf: ['jspdf'],
            icons: ['lucide-react']
          }
        }
      }
    }
  };
});

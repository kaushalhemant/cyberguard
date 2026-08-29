import path from 'path';
import fs from 'fs';
import express, { Request, Response } from 'express';
import handler from './api/[...path]';
import {
  lookupEmailBreaches,
  searchCves,
  analyzeUrl,
  analyzeHash,
  analyzeOsint,
  calculateShannonEntropy
} from './src/server/threatEngine';

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));

// Route all /api/* requests to the unified catch-all handler
app.all('/api/*', async (req: Request, res: Response) => {
  await handler(req, res);
});
app.all('/api', async (req: Request, res: Response) => {
  await handler(req, res);
});

// Startup-time sanity check for deterministic engine and environment readiness
function performStartupSanityCheck() {
  console.log('[CyberGuard] Performing deterministic engine sanity checks...');
  try {
    if (!lookupEmailBreaches || !searchCves || !analyzeUrl || !analyzeHash || !analyzeOsint || !calculateShannonEntropy) {
      throw new Error('Core deterministic threat engine exports are missing or incomplete.');
    }
    // Verify entropy calculation
    const testEnt = calculateShannonEntropy(Buffer.from('CYBERGUARD_DETERMINISTIC_TEST'));
    if (typeof testEnt !== 'number' || isNaN(testEnt)) {
      throw new Error('Shannon entropy engine self-test failed.');
    }
    console.log('[CyberGuard] Deterministic Threat Engine Self-Test: PASSED');
  } catch (err: any) {
    console.error('[CyberGuard CRITICAL ERROR] Startup engine self-test failed:', err.message);
    process.exit(1);
  }
}

async function startServer() {
  performStartupSanityCheck();

  // In development, mount Vite dev middleware for live React 19 HMR
  if (process.env.NODE_ENV !== 'production') {
    try {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa'
      });
      app.use(vite.middlewares);
    } catch (e) {
      console.warn('[CyberGuard] Vite dev middleware skipped, falling back to static dist:', e);
    }
  }

  // Serve compiled production SPA assets if available
  const distPath = path.resolve(process.cwd(), 'dist');
  if (fs.existsSync(distPath)) {
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      if (!req.url.startsWith('/api')) {
        const indexPath = path.join(distPath, 'index.html');
        if (fs.existsSync(indexPath)) {
          return res.sendFile(indexPath);
        }
      }
      res.status(404).json({ error: 'Not Found' });
    });
  }

  if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[CyberGuard] Core Threat Engine & UI running on http://0.0.0.0:${PORT}`);
      console.log(`[CyberGuard] Deterministic Rule-Based Architecture: 100% AUDITABLE`);
    });
  }
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}

export default app;

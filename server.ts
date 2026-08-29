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

// Serve frontend assets & SPA
const distPath = path.resolve(process.cwd(), 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
}

// Serve SPA index.html for all non-API routes
app.get('*', (req: Request, res: Response) => {
  if (!req.url.startsWith('/api')) {
    const distIndex = path.join(distPath, 'index.html');
    if (fs.existsSync(distIndex)) {
      return res.sendFile(distIndex);
    }
    const rootIndex = path.resolve(process.cwd(), 'index.html');
    if (fs.existsSync(rootIndex)) {
      return res.sendFile(rootIndex);
    }
  }
  res.status(404).json({ error: 'Endpoint Not Found' });
});

// Startup-time sanity check for deterministic engine and environment readiness
function performStartupSanityCheck() {
  console.log('[CyberGuard] Performing deterministic engine sanity checks...');
  try {
    if (!lookupEmailBreaches || !searchCves || !analyzeUrl || !analyzeHash || !analyzeOsint || !calculateShannonEntropy) {
      throw new Error('Core deterministic threat engine exports are missing or incomplete.');
    }
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

if (process.env.NODE_ENV !== 'test') {
  performStartupSanityCheck();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberGuard] Core Threat Engine & UI running on http://localhost:${PORT}`);
    console.log(`[CyberGuard] Deterministic Rule-Based Architecture: 100% AUDITABLE`);
  });
}

export default app;

import path from 'path';
import fs from 'fs';
import express, { Request, Response } from 'express';
import app from './api/index';

const PORT = parseInt(process.env.PORT || '3000', 10);

// In production / local standalone mode, serve Vite built assets from dist/
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

// Start local HTTP server
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberGuard] Core Threat Engine running on http://0.0.0.0:${PORT}`);
    console.log(`[CyberGuard] VirusTotal v3 Threat Intelligence: ACTIVE`);
  });
}

export default app;

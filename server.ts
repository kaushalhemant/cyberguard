import path from 'path';
import fs from 'fs';
import express, { Request, Response } from 'express';
import handler from './api/[...path]';

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

// Serve frontend SPA in production
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
    console.log(`[CyberGuard] Core Threat Engine running on http://0.0.0.0:${PORT}`);
    console.log(`[CyberGuard] VirusTotal v3 Threat Intelligence: ACTIVE`);
  });
}

export default app;

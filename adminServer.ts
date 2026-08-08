import express from 'express';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || '3001', 10);
const MAIN_APP_URL = process.env.MAIN_APP_URL || 'http://localhost:3000';

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Proxy /api/admin requests to main server on port 3000
app.all('/api/admin/*', async (req, res) => {
  try {
    const targetUrl = `${MAIN_APP_URL}${req.originalUrl}`;
    const headers: Record<string, string> = {
      'content-type': req.headers['content-type'] as string || 'application/json',
    };
    if (req.headers.authorization) {
      headers['authorization'] = req.headers.authorization as string;
    }
    if (req.headers['x-cyberguard-admin-key']) {
      headers['x-cyberguard-admin-key'] = req.headers['x-cyberguard-admin-key'] as string;
    }

    const options: RequestInit = {
      method: req.method,
      headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body)
    };

    const response = await fetch(targetUrl, options);
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await response.json();
      res.status(response.status).json(data);
    } else {
      const text = await response.text();
      res.status(response.status).json({
        error: text.replace(/<[^>]*>/g, '').trim().substring(0, 200) || `Main server returned status ${response.status}`
      });
    }
  } catch (err: any) {
    console.error('[Admin Server Proxy Error]:', err.message || err);
    res.status(500).json({ error: 'Failed to proxy request to main Security Log Hub.' });
  }
});

async function startAdminServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      root: path.join(process.cwd(), 'admin-portal'),
      server: {
        middlewareMode: true,
        watch: {
          ignored: ['**/db.json', '**/db.json.tmp']
        }
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist-admin');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(ADMIN_PORT, '0.0.0.0', () => {
    console.log(`[CyberGuard Master Admin Portal] Live on http://0.0.0.0:${ADMIN_PORT}`);
  });
}

startAdminServer();

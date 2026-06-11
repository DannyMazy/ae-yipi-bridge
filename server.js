/**
 * Production HTTP server — AE → Partner Bridge (v2)
 * Deploy to Render, Railway, or any Node 20+ host.
 * PORT is injected by the platform automatically.
 *
 * Routes (POST, guarded by x-bridge-secret inside bridge.js):
 *   /yipi/submit        submit deal to Yipi (deal type from tags — REQUIRED)
 *   /yipi/withdraw      withdraw ("remove") a submitted Yipi deal
 *   /soldandstay/submit log lead to the Google Sheet only
 *   /stayfrank/submit   stub until StayFrank API spec is final
 *   /  (or anything)    legacy — same as v1 (Yipi submit, YIPI_APP_TYPE fallback)
 */

import { createServer } from 'node:http';
import { route } from './bridge.js';

const PORT = process.env.PORT || 3099;

const server = createServer((req, res) => {
  const path = (req.url || '/').split('?')[0];

  // Health check — Render pings / to verify the service is up
  if (req.method === 'GET' && path === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      service: 'ae-yipi-bridge',
      version: '2.0.0',
      routes: ['POST /yipi/submit', 'POST /yipi/withdraw', 'POST /soldandstay/submit', 'POST /stayfrank/submit'],
    }));
    return;
  }

  // Only accept POST otherwise
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  // Collect body then hand off to the route handler
  let raw = '';
  req.on('data', (chunk) => (raw += chunk));
  req.on('end', async () => {
    req.body = raw;

    // Adapt Node IncomingMessage → bridge's Express-like res interface
    const mockRes = {
      _code: 200,
      status(code) { this._code = code; return this; },
      json(data) {
        res.writeHead(this._code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      },
    };

    try {
      await route(path, req, mockRes);
    } catch (err) {
      console.error('[server] Unhandled error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  });
});

server.listen(PORT, () =>
  console.log(`🌉 AE→Partner Bridge v2 listening on port ${PORT}`)
);

/**
 * Production HTTP server — AE → Yipi Bridge
 * Deploy to Render, Railway, or any Node 20+ host.
 * PORT is injected by the platform automatically.
 */

import { createServer }  from 'node:http';
import { handler }       from './bridge.js';

const PORT = process.env.PORT || 3099;

const server = createServer((req, res) => {

  // Health check — Render pings / to verify the service is up
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'ae-yipi-bridge' }));
    return;
  }

  // Only accept POST to /
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  // Collect body then hand off to bridge handler
  let raw = '';
  req.on('data', (chunk) => (raw += chunk));
  req.on('end', async () => {
    req.body = raw;

    // Adapt Node IncomingMessage → bridge's Express-like res interface
    const mockRes = {
      _code: 200,
      status(code)  { this._code = code; return this; },
      json(data) {
        res.writeHead(this._code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      },
    };

    try {
      await handler(req, mockRes);
    } catch (err) {
      console.error('[server] Unhandled error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  });
});

server.listen(PORT, () =>
  console.log(`🌉  AE→Yipi Bridge listening on port ${PORT}`)
);

/**
 * Production HTTP server — AE → Partner Bridge (v2.1)
 * Deploy to Render, Railway, or any Node 20+ host.
 * PORT is injected by the platform automatically.
 *
 * Routes (guarded by x-bridge-secret inside bridge.js):
 *   GET  /yipi/deals        list deals submitted to Yipi (live status)
 *   POST /yipi/submit       submit deal to Yipi (deal type from tags — REQUIRED)
 *   POST /yipi/withdraw     withdraw a deal — by { dealId } or GHL contact payload
 *   POST /soldandstay/submit log lead to the Google Sheet only
 *   POST /stayfrank/submit  stub until StayFrank API spec is final
 *   POST /  (or anything)   legacy — same as v1 (Yipi submit, YIPI_APP_TYPE fallback)
 *
 * CORS is enabled so the Afford Equity deals dashboard (runs in the
 * Claude desktop app) can call /yipi/deals and /yipi/withdraw directly.
 */

import { createServer } from 'node:http';
import { route } from './bridge.js';

const PORT = process.env.PORT || 3099;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, x-bridge-secret',
  'Access-Control-Max-Age': '86400',
};

const server = createServer((req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  const path = url.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  // Health check — Render pings / to verify the service is up
  if (req.method === 'GET' && path === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...CORS_HEADERS });
    res.end(JSON.stringify({
      status: 'ok',
      service: 'ae-yipi-bridge',
      version: '2.1.0',
      routes: ['GET /yipi/deals', 'POST /yipi/submit', 'POST /yipi/withdraw', 'POST /soldandstay/submit', 'POST /stayfrank/submit'],
    }));
    return;
  }

  if (req.method !== 'POST' && req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json', ...CORS_HEADERS });
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
        res.writeHead(this._code, { 'Content-Type': 'application/json', ...CORS_HEADERS });
        res.end(JSON.stringify(data));
      },
    };

    try {
      await route(path, req, mockRes, url.searchParams);
    } catch (err) {
      console.error('[server] Unhandled error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json', ...CORS_HEADERS });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  });
});

server.listen(PORT, () =>
  console.log(`🌉 AE→Partner Bridge v2.1 listening on port ${PORT}`)
);

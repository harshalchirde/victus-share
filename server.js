'use strict';
/* Victus Share — signaling server (Developed by Harshal Chirde)
   Serves victus-share.html and relays WebRTC signaling over WebSocket.
   It never receives, stores, or logs file contents. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const env = process.env;
const PORT = +env.PORT || 3000;
const PAIR_TTL = (+env.SESSION_TTL_SECONDS || 600) * 1000;   // time allowed to pair
const LIVE_TTL = 2 * 60 * 60 * 1000;                          // hard cap once paired
const ALLOWED = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const TRUST_PROXY = env.TRUST_PROXY === '1';

const iceServers = [{ urls: (env.STUN_URLS || 'stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302').split(',') }];
if (env.TURN_URL) iceServers.push({ urls: env.TURN_URL.split(','), username: env.TURN_USERNAME, credential: env.TURN_CREDENTIAL });

const CONFIG = JSON.stringify({
  iceServers,
  chunkSize: +env.CHUNK_SIZE || 65536,
  maxFiles: +env.MAX_FILES || 100,
  maxFileSize: +env.MAX_FILE_SIZE || 4 * 1024 ** 3,
  ttl: PAIR_TTL / 1000,
});

const html = fs.readFileSync(path.join(__dirname, 'victus-share.html'));
const SEC = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
};

const server = http.createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, SEC); return res.end(); }
  const p = req.url.split('?')[0];
  if (p === '/config') { res.writeHead(200, { ...SEC, 'Content-Type': 'application/json' }); return res.end(CONFIG); }
  if (p === '/healthz') { res.writeHead(200, SEC); return res.end('ok'); }
  if (p === '/ws') { res.writeHead(426, SEC); return res.end(); }
  res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8' }); // no file paths are ever read from the URL
  res.end(html);
});

const sessions = new Map(); // code -> session
const attempts = new Map(); // ip -> {n, reset}

function ipOf(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return req.headers['x-forwarded-for'].split(',')[0].trim();
  return req.socket.remoteAddress || 'x';
}
function limited(ip, max) {
  const now = Date.now(); let a = attempts.get(ip);
  if (!a || a.reset < now) a = { n: 0, reset: now + 60000 };
  a.n++; attempts.set(ip, a);
  return a.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of attempts) if (v.reset < n) attempts.delete(k); }, 60000).unref();

const send = (ws, o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
function newCode() {
  for (;;) { const c = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); if (!sessions.has(c)) return c; }
}
function destroy(s) {
  clearTimeout(s.timer); sessions.delete(s.code);
  if (s.sender) s.sender.session = null;
  if (s.receiver) s.receiver.session = null;
}
function expire(s) {
  send(s.sender, { t: 'expired' }); send(s.receiver, { t: 'expired' });
  const a = s.sender, b = s.receiver; destroy(s);
  if (a) a.close(); if (b) b.close();
}

const wss = new WebSocketServer({
  server, path: '/ws', maxPayload: 64 * 1024,
  verifyClient: ({ origin, req }) => {
    if (ALLOWED.length) return ALLOWED.includes(origin);
    if (!origin) return false;
    try { return new URL(origin).host === req.headers.host; } catch { return false; }
  },
});

wss.on('connection', (ws, req) => {
  ws.ip = ipOf(req); ws.alive = true; ws.session = null;
  ws.on('pong', () => { ws.alive = true; });
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!m || typeof m.t !== 'string') return;
    const s = ws.session;
    if (m.t === 'create') {
      if (s || sessions.size > 5000 || limited(ws.ip, 30)) return send(ws, { t: 'error', code: 'rate' });
      const ns = { code: newCode(), id: crypto.randomBytes(9).toString('base64url'), sender: ws, receiver: null, timer: null };
      ns.timer = setTimeout(() => expire(ns), PAIR_TTL);
      sessions.set(ns.code, ns); ws.session = ns;
      send(ws, { t: 'created', code: ns.code, id: ns.id, ttl: PAIR_TTL / 1000 });
    } else if (m.t === 'join') {
      if (s) return;
      if (limited(ws.ip, 10)) return send(ws, { t: 'error', code: 'rate' });
      const t = typeof m.code === 'string' && /^\d{6}$/.test(m.code) ? sessions.get(m.code) : null;
      if (!t || t.receiver) return send(ws, { t: 'error', code: 'invalid' });
      t.receiver = ws; ws.session = t;
      clearTimeout(t.timer); t.timer = setTimeout(() => expire(t), LIVE_TTL);
      send(ws, { t: 'joined' }); send(t.sender, { t: 'peer-joined' });
    } else if (m.t === 'signal' && s && s.receiver) {
      send(ws === s.sender ? s.receiver : s.sender, { t: 'signal', data: m.data });
    } else if (m.t === 'bye' && s) {
      const peer = ws === s.sender ? s.receiver : s.sender; destroy(s); if (peer) peer.close();
    }
  });
  ws.on('close', () => {
    const s = ws.session; if (!s) return;
    const peer = ws === s.sender ? s.receiver : s.sender;
    destroy(s); send(peer, { t: 'peer-left' });
  });
  ws.on('error', () => {});
});

setInterval(() => {
  wss.clients.forEach(ws => { if (!ws.alive) return ws.terminate(); ws.alive = false; ws.ping(); });
}, 30000).unref();

server.listen(PORT, () => console.log('Victus Share running on http://localhost:' + PORT));
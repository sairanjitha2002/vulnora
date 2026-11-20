'use strict';
/*
 * Deliberately vulnerable PRACTICE website for demonstrating Vulnora's Web application scan.
 * Listens on 127.0.0.1 only, so nothing else on your network can reach it.
 *   Start:  node practice-site.js        then scan  http://127.0.0.1:8901  in Vulnora.
 * Planted issues: no security headers, version banners, session cookie without HttpOnly/SameSite,
 * exposed /.git/HEAD and /.env (fake values), CORS reflecting any origin with credentials, TRACE enabled.
 * Unknown paths answer "200 OK" on purpose, to show that Vulnora does not raise false alarms on soft-404 pages.
 */
const http = require('http');
const PORT = Number(process.env.PRACTICE_PORT) || 8901;
http.createServer((req, res) => {
  res.setHeader('Server', 'Apache/2.4.29 (Ubuntu)');
  res.setHeader('X-Powered-By', 'PHP/7.2.24');
  if (req.headers.origin) { res.setHeader('Access-Control-Allow-Origin', req.headers.origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); }
  if (req.method === 'TRACE') { res.writeHead(200, { 'Content-Type': 'message/http' }); return res.end(`TRACE ${req.url} HTTP/1.1\r\nHost: ${req.headers.host}\r\n`); }
  if (req.url === '/.git/HEAD') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ref: refs/heads/main\n'); }
  if (req.url === '/.env') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('APP_ENV=production\nDB_PASSWORD=FAKE-practice-value\nAPI_KEY=FAKE-practice-value\n'); }
  if (req.url === '/') {
    res.setHeader('Set-Cookie', ['PHPSESSID=practice123; Path=/', 'theme=dark; Path=/; HttpOnly']);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end('<!doctype html><html><head><title>Practice Shop (deliberately insecure)</title></head><body><h1>Practice Shop</h1><p>This site is intentionally insecure for Vulnora demos.</p></body></html>');
  }
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body>Page not found (but status 200)</body></html>');
}).listen(PORT, '127.0.0.1', () => console.log(`\n  Practice site (deliberately insecure) at http://127.0.0.1:${PORT}\n  Scan it with Vulnora > Web application. Press Ctrl+C to stop.\n`));

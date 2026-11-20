'use strict';
/*
 * Vulnora web application checks — passive, low-volume (about 20 requests), zero dependencies.
 * Looks at what any visitor's browser already receives: response headers, cookies, HTTPS/TLS,
 * a handful of well-known sensitive paths, CORS behaviour and the TRACE method.
 * It never submits forms, guesses passwords, fuzzes parameters or sends attack payloads.
 * Only run it against sites you own or have written permission to test.
 */
const http = require('http');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');

const UA = 'Vulnora-WebCheck/1.0 (authorised passive security check)';
const MAX_BODY = 256 * 1024;
const OWASP = {
  A01: 'A01:2025 Broken Access Control', A02: 'A02:2025 Security Misconfiguration', A04: 'A04:2025 Cryptographic Failures',
  A07: 'A07:2025 Authentication Failures', A09: 'A09:2025 Security Logging and Alerting Failures',
};
const MDN = (h) => `https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/${h}`;
const OCS = (n) => `https://cheatsheetseries.owasp.org/cheatsheets/${n}.html`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- one HTTP(S) request, no redirects followed ---------- */
function request(urlStr, { method = 'GET', headers = {}, timeout = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return reject(new Error('Invalid URL')); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, {
      method, timeout, rejectUnauthorized: false, // inspect bad certificates instead of failing on them
      headers: { 'User-Agent': UA, Accept: '*/*', ...headers },
    }, (res) => {
      const chunks = []; let n = 0;
      const sock = res.socket;
      const tlsInfo = sock && sock.encrypted ? {
        protocol: sock.getProtocol && sock.getProtocol(), authorized: sock.authorized, authError: sock.authorizationError ? String(sock.authorizationError) : '',
        cert: (() => { try { return sock.getPeerCertificate(); } catch (e) { return null; } })(),
      } : null;
      res.on('data', (c) => { if (n < MAX_BODY) { chunks.push(c); n += c.length; } });
      res.on('end', () => resolve({ url: u.toString(), status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).slice(0, MAX_BODY), tls: tlsInfo }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Timed out after ' + timeout / 1000 + 's')));
    req.on('error', reject);
    req.end();
  });
}
async function fetchFollow(url, max = 5) {
  const chain = [];
  let cur = url;
  for (let i = 0; i <= max; i++) {
    const r = await request(cur);
    chain.push(`${r.status} ${cur}`);
    if (r.status >= 300 && r.status < 400 && r.headers.location) { cur = new URL(r.headers.location, cur).toString(); continue; }
    return { ...r, chain };
  }
  throw new Error('Too many redirects');
}
function probeOldTls(host, port) { // does the server still accept TLS 1.0 / 1.1?
  return new Promise((resolve) => {
    let done = false;
    const end = (v) => { if (!done) { done = true; try { s.destroy(); } catch (e) { /* ignore */ } resolve(v); } };
    let s;
    try {
      s = tls.connect({ host, port, servername: /^[\d.]+$/.test(host) ? undefined : host, minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0', rejectUnauthorized: false, timeout: 6000 }, () => end(s.getProtocol()));
    } catch (e) { return resolve(null); }
    s.on('error', () => end(null)); s.on('timeout', () => end(null));
  });
}
const isLocal = (host) => /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?$)/.test(host);
const text = (r) => r.body.toString('utf8');
const fingerprint = (r) => `${r.status}|${crypto.createHash('sha1').update(r.body).digest('hex')}`;

/* ---------- the checks ---------- */
async function runWebChecks(target, { log = () => {}, cancelled = () => false } = {}) {
  const t0 = Date.now();
  const findings = [];
  let reqs = 0;
  const get = async (url, opts) => { if (cancelled()) throw new Error('Cancelled'); reqs++; await sleep(120); return request(url, opts); };
  const add = (f) => findings.push({
    target: f.where || target, cls: 'web', type: 'web', id: f.id, ruleId: `${f.cwe} · OWASP ${OWASP[f.owasp]}`,
    title: f.title, description: f.why, message: f.evidence, resolution: f.fix, severity: f.sev, status: 'FAIL', url: f.ref || '',
    cwe: f.cwe, owasp: OWASP[f.owasp],
  });

  log(`Fetching ${target}`);
  reqs++;
  let main;
  try { main = await fetchFollow(target); } catch (e) { throw new Error(`Could not reach ${target}: ${e.message}`); }
  const finalUrl = new URL(main.url);
  const H = main.headers;
  const isHttps = finalUrl.protocol === 'https:';
  const origin = finalUrl.origin;
  log(`Reached ${main.url} (HTTP ${main.status}${main.chain.length > 1 ? `, ${main.chain.length - 1} redirect(s)` : ''})`);

  /* 1. security headers */
  log('Checking security headers');
  const csp = H['content-security-policy'] || '';
  if (isHttps && !H['strict-transport-security']) add({ id: 'WEB-HSTS-MISSING', sev: 'MEDIUM', cwe: 'CWE-319', owasp: 'A04', title: 'Strict-Transport-Security (HSTS) header missing',
    why: 'Without HSTS a browser can be tricked into loading the site over plain HTTP (SSL stripping on public Wi-Fi), exposing cookies and data.',
    evidence: 'No Strict-Transport-Security header on the HTTPS response.', fix: 'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains', ref: MDN('Strict-Transport-Security') });
  else if (isHttps) {
    const ma = Number((/max-age=(\d+)/i.exec(H['strict-transport-security']) || [])[1] || 0);
    if (ma < 15552000) add({ id: 'WEB-HSTS-WEAK', sev: 'LOW', cwe: 'CWE-319', owasp: 'A04', title: 'HSTS max-age is shorter than 180 days',
      why: 'A short max-age lets browsers forget the HTTPS-only rule quickly.', evidence: `Strict-Transport-Security: ${H['strict-transport-security']}`,
      fix: 'Use max-age=31536000 (one year) or more.', ref: MDN('Strict-Transport-Security') });
  }
  if (!csp) add({ id: 'WEB-CSP-MISSING', sev: 'MEDIUM', cwe: 'CWE-693', owasp: 'A02', title: 'Content-Security-Policy header missing',
    why: 'CSP is the main browser-side defence that limits the damage of cross-site scripting (XSS) and data injection.',
    evidence: 'No Content-Security-Policy header on the page.', fix: "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self' — then widen only what the site needs.", ref: MDN('Content-Security-Policy') });
  else {
    const scriptSrc = (/script-src([^;]*)/i.exec(csp) || [])[1] || (/default-src([^;]*)/i.exec(csp) || [])[1] || '';
    if (/'unsafe-inline'/.test(scriptSrc)) add({ id: 'WEB-CSP-UNSAFE-INLINE', sev: 'LOW', cwe: 'CWE-693', owasp: 'A02', title: "CSP allows 'unsafe-inline' scripts",
      why: "'unsafe-inline' lets injected inline <script> run, which removes most of CSP's protection against XSS.", evidence: `Content-Security-Policy: ${csp.slice(0, 300)}`,
      fix: "Remove 'unsafe-inline' from script-src; use nonces or hashes for the inline scripts you need.", ref: MDN('Content-Security-Policy/script-src') });
    if (/'unsafe-eval'/.test(scriptSrc)) add({ id: 'WEB-CSP-UNSAFE-EVAL', sev: 'LOW', cwe: 'CWE-693', owasp: 'A02', title: "CSP allows 'unsafe-eval'",
      why: "'unsafe-eval' allows eval() and similar, a common way to turn injected text into running code.", evidence: `Content-Security-Policy: ${csp.slice(0, 300)}`,
      fix: "Remove 'unsafe-eval' and refactor code that relies on eval/new Function.", ref: MDN('Content-Security-Policy/script-src') });
  }
  if (!H['x-frame-options'] && !/frame-ancestors/i.test(csp)) add({ id: 'WEB-CLICKJACKING', sev: 'MEDIUM', cwe: 'CWE-1021', owasp: 'A02', title: 'Page can be framed by other sites (clickjacking)',
    why: 'An attacker can load this page inside an invisible iframe and trick users into clicking real buttons (delete, pay, change settings).',
    evidence: 'Neither X-Frame-Options nor CSP frame-ancestors is set.', fix: "Send: X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors 'none'", ref: OCS('Clickjacking_Defense_Cheat_Sheet') });
  if (!/nosniff/i.test(H['x-content-type-options'] || '')) add({ id: 'WEB-NOSNIFF-MISSING', sev: 'LOW', cwe: 'CWE-693', owasp: 'A02', title: 'X-Content-Type-Options: nosniff missing',
    why: 'Browsers may "sniff" a file as a different type (for example run an upload as script).', evidence: 'No X-Content-Type-Options: nosniff header.',
    fix: 'Send: X-Content-Type-Options: nosniff', ref: MDN('X-Content-Type-Options') });
  if (!H['referrer-policy']) add({ id: 'WEB-REFERRER-POLICY-MISSING', sev: 'LOW', cwe: 'CWE-200', owasp: 'A02', title: 'Referrer-Policy header missing',
    why: 'Full URLs (which can contain tokens or IDs) may leak to other sites in the Referer header.', evidence: 'No Referrer-Policy header.',
    fix: 'Send: Referrer-Policy: strict-origin-when-cross-origin', ref: MDN('Referrer-Policy') });
  if (!H['permissions-policy']) add({ id: 'WEB-PERMISSIONS-POLICY-MISSING', sev: 'LOW', cwe: 'CWE-693', owasp: 'A02', title: 'Permissions-Policy header missing',
    why: 'Without it, embedded or injected content can ask for camera, microphone or location access.', evidence: 'No Permissions-Policy header.',
    fix: 'Send: Permissions-Policy: camera=(), microphone=(), geolocation=()', ref: MDN('Permissions-Policy') });

  /* 2. information disclosure */
  const banners = [];
  if (H.server && /\d/.test(H.server)) banners.push(`Server: ${H.server}`);
  if (H['x-powered-by']) banners.push(`X-Powered-By: ${H['x-powered-by']}`);
  if (H['x-aspnet-version']) banners.push(`X-AspNet-Version: ${H['x-aspnet-version']}`);
  if (banners.length) add({ id: 'WEB-VERSION-DISCLOSURE', sev: 'LOW', cwe: 'CWE-200', owasp: 'A02', title: 'Server software and version disclosed in headers',
    why: 'Exact product versions let attackers look up known CVEs for this server in seconds.', evidence: banners.join('  |  '),
    fix: 'Hide version banners (e.g. nginx: server_tokens off; Express: app.disable("x-powered-by"); Apache: ServerTokens Prod).', ref: OCS('HTTP_Headers_Cheat_Sheet') });

  /* 3. cookies */
  log('Checking cookies');
  const cookies = [].concat(H['set-cookie'] || []);
  const noSecure = [], noHttpOnly = [], noSameSite = [];
  cookies.forEach((c) => {
    const name = c.split('=')[0].trim(); const attrs = c.toLowerCase();
    if (isHttps && !/;\s*secure/.test(attrs)) noSecure.push(name);
    if (!/;\s*httponly/.test(attrs)) noHttpOnly.push(name);
    if (!/;\s*samesite=/.test(attrs)) noSameSite.push(name);
  });
  const sessionish = (arr) => arr.some((n) => /sess|sid|token|auth|jwt|login/i.test(n));
  if (noSecure.length) add({ id: 'WEB-COOKIE-NO-SECURE', sev: 'MEDIUM', cwe: 'CWE-614', owasp: 'A04', title: 'Cookie set without the Secure flag',
    why: 'The cookie can be sent over plain HTTP, where anyone on the network can read it.', evidence: `Cookies: ${noSecure.join(', ')}`, fix: 'Add the Secure attribute to every cookie on an HTTPS site.', ref: MDN('Set-Cookie') });
  if (noHttpOnly.length) add({ id: 'WEB-COOKIE-NO-HTTPONLY', sev: sessionish(noHttpOnly) ? 'MEDIUM' : 'LOW', cwe: 'CWE-1004', owasp: 'A07', title: 'Cookie set without the HttpOnly flag',
    why: 'JavaScript can read the cookie, so a single XSS bug can steal a logged-in session.', evidence: `Cookies: ${noHttpOnly.join(', ')}`, fix: 'Add HttpOnly to session and authentication cookies.', ref: MDN('Set-Cookie') });
  if (noSameSite.length) add({ id: 'WEB-COOKIE-NO-SAMESITE', sev: 'LOW', cwe: 'CWE-1275', owasp: 'A07', title: 'Cookie set without a SameSite attribute',
    why: 'Explicit SameSite reduces cross-site request forgery (CSRF) risk and avoids browser-default surprises.', evidence: `Cookies: ${noSameSite.join(', ')}`, fix: 'Add SameSite=Lax (or Strict for sensitive cookies).', ref: MDN('Set-Cookie') });

  /* 4. HTTPS / TLS */
  log('Checking HTTPS and TLS');
  const host = finalUrl.hostname;
  if (!isHttps) {
    let httpsOk = false;
    try { await get(`https://${finalUrl.host}/`, { timeout: 6000 }); httpsOk = true; } catch (e) { httpsOk = false; }
    if (httpsOk) add({ id: 'WEB-HTTPS-NOT-ENFORCED', sev: 'MEDIUM', cwe: 'CWE-319', owasp: 'A04', title: 'Site served over HTTP although HTTPS is available',
      why: 'Visitors who type the address land on the unencrypted version.', evidence: `${target} answered over HTTP without redirecting to HTTPS.`, fix: 'Redirect every HTTP request to HTTPS (301) and add HSTS.', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
    else add({ id: 'WEB-NO-HTTPS', sev: isLocal(host) ? 'LOW' : 'HIGH', cwe: 'CWE-319', owasp: 'A04', title: isLocal(host) ? 'No HTTPS (local / development address)' : 'Site does not offer HTTPS',
      why: isLocal(host) ? 'Acceptable for a local tool, but anything reachable on a network should use HTTPS.' : 'All traffic, including passwords and cookies, travels unencrypted.',
      evidence: `HTTPS connection to ${finalUrl.host} failed.`, fix: 'Enable HTTPS with a valid certificate (e.g. Let’s Encrypt) and redirect HTTP to it.', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
  } else {
    const t = main.tls || {};
    if (t.authorized === false && t.authError !== 'CERT_HAS_EXPIRED') add({ id: 'WEB-TLS-CERT-INVALID', sev: 'HIGH', cwe: 'CWE-295', owasp: 'A04', title: 'TLS certificate is not trusted',
      why: 'Browsers show a warning; users who click through can be intercepted without noticing.', evidence: `Certificate check failed: ${t.authError || 'unknown reason'}`,
      fix: 'Install a certificate from a trusted CA that matches the host name, with the full chain.', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
    if (t.cert && t.cert.valid_to) {
      const days = Math.floor((new Date(t.cert.valid_to) - Date.now()) / 864e5);
      if (days < 0) add({ id: 'WEB-TLS-CERT-EXPIRED', sev: 'HIGH', cwe: 'CWE-298', owasp: 'A04', title: 'TLS certificate has expired',
        why: 'Browsers block the site or show a full-page warning.', evidence: `Expired on ${t.cert.valid_to} (${-days} days ago).`, fix: 'Renew the certificate now and automate renewal.', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
      else if (days < 30) add({ id: 'WEB-TLS-CERT-EXPIRING', sev: 'LOW', cwe: 'CWE-298', owasp: 'A04', title: `TLS certificate expires in ${days} days`,
        why: 'An expiring certificate will soon break access for every visitor.', evidence: `Valid until ${t.cert.valid_to}.`, fix: 'Renew it and automate renewal (e.g. certbot timer).', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
    }
    reqs++;
    const old = await probeOldTls(host, Number(finalUrl.port) || 443);
    if (old) add({ id: 'WEB-TLS-OLD-PROTOCOL', sev: 'MEDIUM', cwe: 'CWE-326', owasp: 'A04', title: `Server still accepts ${old}`,
      why: 'TLS 1.0 and 1.1 are deprecated and have known weaknesses; PCI DSS and browsers have dropped them.', evidence: `A ${old} handshake to ${host} succeeded.`,
      fix: 'Allow only TLS 1.2 and TLS 1.3 in the server configuration.', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
    try {
      const plain = await get(`http://${finalUrl.hostname}/`, { timeout: 6000 });
      const loc = plain.headers.location || '';
      if (plain.status < 300 || plain.status >= 400 || !/^https:/i.test(new URL(loc || '/', `http://${finalUrl.hostname}/`).toString())) add({ id: 'WEB-HTTP-NO-REDIRECT', sev: 'MEDIUM', cwe: 'CWE-319', owasp: 'A04', title: 'HTTP version does not redirect to HTTPS',
        why: 'Visitors using http:// stay on the unencrypted site.', evidence: `http://${finalUrl.hostname}/ answered ${plain.status}${loc ? ' → ' + loc : ''}.`,
        fix: 'Return 301 from every http:// URL to its https:// version.', ref: OCS('Transport_Layer_Security_Cheat_Sheet') });
    } catch (e) { /* port 80 closed: fine */ }
  }

  /* 5. sensitive files (content signatures, compared against a not-found baseline) */
  log('Checking for exposed sensitive files');
  let baseline = null;
  try { baseline = fingerprint(await get(`${origin}/vulnora-${crypto.randomBytes(6).toString('hex')}`)); } catch (e) { /* ignore */ }
  const probes = [
    ['/.git/HEAD', (r, b) => /^ref: refs\//.test(b), { id: 'WEB-EXPOSED-GIT', sev: 'CRITICAL', cwe: 'CWE-538', title: 'Git repository exposed (/.git/)', why: 'Anyone can download the full source code and its history, often including passwords and API keys.', fix: 'Block /.git/ in the web server and never deploy the .git folder.' }],
    ['/.env', (r, b) => /^[A-Z][A-Z0-9_]{1,40}\s*=/m.test(b) && !/<html/i.test(b), { id: 'WEB-EXPOSED-ENV', sev: 'CRITICAL', cwe: 'CWE-538', title: 'Environment file exposed (/.env)', why: '.env files usually hold database passwords, API keys and secrets.', fix: 'Remove .env from the web root, block dotfiles, and rotate every secret it contained.' }],
    ['/backup.sql', (r, b) => /(CREATE TABLE|INSERT INTO)/i.test(b), { id: 'WEB-EXPOSED-DB-DUMP', sev: 'CRITICAL', cwe: 'CWE-530', title: 'Database dump downloadable (/backup.sql)', why: 'A database export can contain every user record and password hash.', fix: 'Delete backups from the web root and store them privately.' }],
    ['/phpinfo.php', (r, b) => /phpinfo\(\)|<title>PHP \d/i.test(b), { id: 'WEB-PHPINFO', sev: 'MEDIUM', cwe: 'CWE-200', title: 'phpinfo() page exposed', why: 'Reveals exact versions, paths, modules and sometimes environment secrets.', fix: 'Delete phpinfo.php from production.' }],
    ['/server-status', (r, b) => /Apache Server Status/i.test(b), { id: 'WEB-SERVER-STATUS', sev: 'MEDIUM', cwe: 'CWE-200', title: 'Apache server-status page exposed', why: 'Shows live requests, client IPs and internal URLs.', fix: 'Restrict mod_status to localhost or disable it.' }],
    ['/.DS_Store', (r) => r.body.slice(4, 8).toString('latin1') === 'Bud1', { id: 'WEB-DS-STORE', sev: 'LOW', cwe: 'CWE-538', title: '.DS_Store file exposed', why: 'Lists file and folder names in that directory, helping attackers find hidden files.', fix: 'Delete .DS_Store files and block dotfiles.' }],
  ];
  for (const [path, match, f] of probes) {
    try {
      const r = await get(origin + path, { timeout: 8000 });
      if (r.status === 200 && (!baseline || fingerprint(r) !== baseline) && match(r, text(r).slice(0, 4000))) {
        add({ ...f, owasp: 'A02', where: origin + path, evidence: `GET ${path} → 200, ${r.body.length} bytes; content matches the ${path} signature.`, ref: OCS('Information_Disclosure') });
        log(`  Found: ${path}`);
      }
    } catch (e) { /* unreachable path: fine */ }
  }
  if (/<title>\s*Index of \//i.test(text(main))) add({ id: 'WEB-DIRECTORY-LISTING', sev: 'MEDIUM', cwe: 'CWE-548', owasp: 'A02', title: 'Directory listing enabled',
    why: 'Anyone can browse every file in the folder, including ones never linked from the site.', evidence: 'Page title starts with "Index of /".', fix: 'Disable autoindex / Options -Indexes.', ref: OCS('Information_Disclosure') });

  /* 6. CORS */
  log('Checking CORS behaviour');
  try {
    const evil = 'https://evil.example';
    const r = await get(main.url, { headers: { Origin: evil } });
    const acao = r.headers['access-control-allow-origin'] || ''; const acac = /true/i.test(r.headers['access-control-allow-credentials'] || '');
    if (acao === evil && acac) add({ id: 'WEB-CORS-REFLECT-CREDENTIALS', sev: 'HIGH', cwe: 'CWE-942', owasp: 'A01', title: 'CORS reflects any origin and allows credentials',
      why: 'Any website can read this site’s responses using the visitor’s logged-in session.', evidence: `Origin: ${evil} → Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: true`,
      fix: 'Allow only a fixed list of trusted origins; never reflect the Origin header together with credentials.', ref: MDN('Access-Control-Allow-Origin') });
    else if (acao === evil) add({ id: 'WEB-CORS-REFLECT', sev: 'MEDIUM', cwe: 'CWE-942', owasp: 'A01', title: 'CORS reflects any origin',
      why: 'Any website can read this site’s public responses from a visitor’s browser.', evidence: `Origin: ${evil} → Access-Control-Allow-Origin: ${acao}`,
      fix: 'Return Access-Control-Allow-Origin only for a list of trusted origins.', ref: MDN('Access-Control-Allow-Origin') });
    else if (acao === '*') add({ id: 'WEB-CORS-WILDCARD', sev: 'LOW', cwe: 'CWE-942', owasp: 'A01', title: 'CORS allows every origin (*)',
      why: 'Fine for truly public data, risky for anything user-specific or internal.', evidence: 'Access-Control-Allow-Origin: *', fix: 'Restrict to the origins that need access.', ref: MDN('Access-Control-Allow-Origin') });
  } catch (e) { /* ignore */ }

  /* 7. TRACE method */
  try {
    const r = await get(main.url, { method: 'TRACE' });
    if (r.status === 200 && /^TRACE /m.test(text(r))) add({ id: 'WEB-TRACE-ENABLED', sev: 'LOW', cwe: 'CWE-693', owasp: 'A02', title: 'HTTP TRACE method enabled',
      why: 'TRACE echoes requests back and has been used to steal cookies (cross-site tracing).', evidence: 'TRACE request returned 200 and echoed the request.', fix: 'Disable TRACE (Apache: TraceEnable off).', ref: OCS('HTTP_Headers_Cheat_Sheet') });
  } catch (e) { /* ignore */ }

  /* 8. security.txt (informational) */
  try {
    const r = await get(`${origin}/.well-known/security.txt`, { timeout: 6000 });
    if (!(r.status === 200 && /Contact:/i.test(text(r)))) add({ id: 'WEB-NO-SECURITY-TXT', sev: 'UNKNOWN', cwe: 'CWE-1059', owasp: 'A09', title: 'No security.txt (informational)',
      why: 'security.txt tells researchers how to report vulnerabilities to you (RFC 9116).', evidence: `GET /.well-known/security.txt → ${r.status}`,
      fix: 'Publish /.well-known/security.txt with a Contact: and Expires: line.', ref: 'https://securitytxt.org/' });
  } catch (e) { /* ignore */ }

  const crt = main.tls && main.tls.cert;
  log(`Done: ${findings.length} finding(s) from ${reqs} requests.`);
  return {
    findings,
    meta: {
      artifactType: 'web application', finalUrl: main.url, httpStatus: main.status, redirects: main.chain,
      os: H.server || '-', packages: '-', requests: reqs, durationMs: Date.now() - t0,
      tlsProtocol: main.tls ? main.tls.protocol : 'none (HTTP)', certIssuer: crt && crt.issuer ? (crt.issuer.O || crt.issuer.CN || '') : '', certExpires: crt ? crt.valid_to || '' : '',
      headers: Object.fromEntries(Object.entries(H).filter(([k]) => k !== 'set-cookie').slice(0, 40)),
    },
  };
}

module.exports = { runWebChecks };

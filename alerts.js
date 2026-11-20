'use strict';
/*
 * Vulnora alerts - notify by email (SMTP), Slack or Microsoft Teams when a scan finds serious issues.
 * Zero dependencies: webhooks use https, email uses a minimal SMTP client (SSL/465 or STARTTLS/587).
 */
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const os = require('os');
const { summarize } = require('./public/summary.js');

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const DEFAULTS = {
  enabled: false,
  minSeverity: 'CRITICAL',      // CRITICAL | HIGH
  onlyNew: false,               // only alert on findings not present in the previous scan of the same target
  includeSecrets: true,
  includeMisconfigs: false,
  dashboardUrl: '',             // optional address teammates can reach (e.g. http://192.168.1.20:8787); adds an "Open in Vulnora" link
  email: { enabled: false, host: '', port: 465, security: 'ssl', user: '', pass: '', from: '', to: '' },
  slack: { enabled: false, webhook: '' },
  teams: { enabled: false, webhook: '' },
};
const SECRET_FIELDS = [['email', 'pass'], ['slack', 'webhook'], ['teams', 'webhook']];

function createAlerts({ file, port, getBrand, makePdf = null, log = () => {} }) {
  let cfg = JSON.parse(JSON.stringify(DEFAULTS));
  try {
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    cfg = { ...cfg, ...saved, email: { ...cfg.email, ...saved.email }, slack: { ...cfg.slack, ...saved.slack }, teams: { ...cfg.teams, ...saved.teams } };
  } catch (e) { /* defaults */ }
  const history = []; // last alert deliveries (in memory)

  /* ---------- config ---------- */
  function publicConfig() { // never send secrets back to the browser
    const c = JSON.parse(JSON.stringify(cfg));
    c.email.hasPass = !!cfg.email.pass; c.email.pass = '';
    c.slack.hasWebhook = !!cfg.slack.webhook; c.slack.webhook = mask(cfg.slack.webhook);
    c.teams.hasWebhook = !!cfg.teams.webhook; c.teams.webhook = mask(cfg.teams.webhook);
    c.history = history.slice(0, 15);
    c.defaultDashboardUrl = `http://127.0.0.1:${port}`;
    return c;
  }
  const mask = (u) => (u ? u.replace(/^(https?:\/\/[^/]+\/).*(.{4})$/, '$1••••••$2') : '');
  const str = (v, n) => String(v == null ? '' : v).replace(/[\r\n\0]/g, '').trim().slice(0, n);
  const emailList = (v) => str(v, 1000).split(/[;,\s]+/).filter(Boolean);
  const EMAIL_RE = /^[^\s@<>()"',;:]+@[^\s@<>()"',;:]+\.[^\s@<>()"',;:]+$/;
  function checkWebhook(u, name) {
    if (!u) return '';
    let url;
    try { url = new URL(u); } catch (e) { throw new Error(`${name} webhook is not a valid URL`); }
    const local = /^(127\.0\.0\.1|localhost)$/.test(url.hostname);
    if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) throw new Error(`${name} webhook must start with https://`);
    return url.toString();
  }
  function build(body, base) {
    const next = JSON.parse(JSON.stringify(base));
    if ('enabled' in body) next.enabled = !!body.enabled;
    if ('minSeverity' in body) next.minSeverity = body.minSeverity === 'HIGH' ? 'HIGH' : 'CRITICAL';
    if ('onlyNew' in body) next.onlyNew = !!body.onlyNew;
    if ('includeSecrets' in body) next.includeSecrets = !!body.includeSecrets;
    if ('includeMisconfigs' in body) next.includeMisconfigs = !!body.includeMisconfigs;
    if ('dashboardUrl' in body) {
      const d = str(body.dashboardUrl, 200).replace(/\/+$/, '');
      if (d && !/^https?:\/\/[^\s]+$/i.test(d)) throw new Error('Dashboard URL must start with http:// or https://');
      next.dashboardUrl = d;
    }
    const e = body.email || {};
    if ('enabled' in e) next.email.enabled = !!e.enabled;
    if ('host' in e) { next.email.host = str(e.host, 200); if (next.email.host && !/^[a-z0-9.-]+$/i.test(next.email.host)) throw new Error('SMTP host looks invalid'); }
    if ('port' in e) { const p = Number(e.port); if (!(p > 0 && p < 65536)) throw new Error('SMTP port must be 1-65535'); next.email.port = p; }
    if ('security' in e) next.email.security = ['ssl', 'starttls', 'none'].includes(e.security) ? e.security : 'ssl';
    if ('user' in e) next.email.user = str(e.user, 200);
    if (typeof e.pass === 'string' && e.pass) next.email.pass = str(e.pass, 300); // blank = keep the saved one
    if (e.clearPass) next.email.pass = '';
    if ('from' in e) { next.email.from = str(e.from, 200); if (next.email.from && !EMAIL_RE.test(next.email.from)) throw new Error('"From" must be an email address'); }
    if ('to' in e) {
      const l = emailList(e.to);
      const bad = l.find((x) => !EMAIL_RE.test(x)); if (bad) throw new Error('Not a valid email address: ' + bad);
      if (l.length > 20) throw new Error('At most 20 recipients');
      next.email.to = l.join(', ');
    }
    [['slack', 'Slack'], ['teams', 'Teams']].forEach(([k, n]) => {
      const c = body[k] || {};
      if ('enabled' in c) next[k].enabled = !!c.enabled;
      if (typeof c.webhook === 'string' && c.webhook && !c.webhook.includes('••')) next[k].webhook = checkWebhook(str(c.webhook, 2000), n);
      if (c.clear) next[k].webhook = '';
    });
    return next;
  }
  function update(body) {
    cfg = build(body || {}, cfg);
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    return publicConfig();
  }

  /* ---------- deciding whether a scan should alert ---------- */
  const KEYS = {
    vulns: (v) => `${v.id}|${v.pkg}`, secrets: (x) => `${x.id}|${x.target}|${x.match}`,
    misconfigs: (m) => `${m.id}|${m.target}`,
  };
  function triggering(scan, previous, c = cfg) {
    const lim = RANK[c.minSeverity] ?? 0;
    const types = ['vulns'];
    if (c.includeSecrets) types.push('secrets');
    if (c.includeMisconfigs || scan.module === 'webapp') types.push('misconfigs'); // web findings live in misconfigs
    const out = {};
    types.forEach((t) => {
      let rows = (scan.findings[t] || []).filter((x) => RANK[x.severity] <= lim);
      if (c.onlyNew && previous) {
        const seen = new Set((previous.findings[t] || []).map(KEYS[t]));
        rows = rows.filter((x) => !seen.has(KEYS[t](x)));
      }
      out[t] = rows;
    });
    out.total = types.reduce((n, t) => n + out[t].length, 0);
    return out;
  }

  /* ---------- message building ---------- */
  function message(scan, trig, c = cfg) {
    const brand = getBrand() || {};
    const s = summarize(scan);
    const crit = trig.vulns.filter((v) => v.severity === 'CRITICAL').length + (trig.secrets || []).filter((v) => v.severity === 'CRITICAL').length + (trig.misconfigs || []).filter((v) => v.severity === 'CRITICAL').length;
    const word = c.minSeverity === 'HIGH' ? 'critical/high' : 'critical';
    const parts = [];
    if (trig.vulns.length) parts.push(`${trig.vulns.length} ${word} vulnerabilit${trig.vulns.length === 1 ? 'y' : 'ies'}`);
    if (trig.secrets && trig.secrets.length) parts.push(`${trig.secrets.length} exposed secret${trig.secrets.length === 1 ? '' : 's'}`);
    if (trig.misconfigs && trig.misconfigs.length) parts.push(`${trig.misconfigs.length} ${word} misconfiguration${trig.misconfigs.length === 1 ? '' : 's'}`);
    const isNew = c.onlyNew ? 'New: ' : '';
    const title = `${crit ? '🚨' : '⚠️'} ${isNew}${parts.join(', ')} in ${scan.target}`;
    const counts = {};
    SEVS.forEach((v) => (counts[v] = ['vulns', 'secrets', 'misconfigs', 'licenses'].reduce((n, k) => n + ((scan.summary[k] || {})[v] || 0), 0)));
    const top = [...trig.vulns].sort((a, b) => RANK[a.severity] - RANK[b.severity] || (b.cvss || 0) - (a.cvss || 0)).slice(0, 8)
      .map((v) => ({ sev: v.severity, id: v.id, pkg: v.pkg, ver: v.installed, fix: v.fixed, url: v.url, title: v.title }));
    const secretsList = (trig.secrets || []).slice(0, 5).map((x) => `${x.title || x.id} — ${x.target}${x.line ? ':' + x.line : ''}`);
    // A 127.0.0.1 / localhost link only works on the scanning computer, so it is never sent.
    const base = (c.dashboardUrl || '').replace(/\/+$/, '');
    const shareable = base && !/^https?:\/\/(127(\.\d+){3}|localhost|\[::1\])(:|\/|$)/i.test(base);
    const msg = {
      title, company: brand.company || '', target: scan.target, module: scan.module, when: new Date(scan.createdAt).toLocaleString(),
      risk: s.risk, headline: s.headline, actions: s.actions.slice(0, 4), counts, top, more: Math.max(0, trig.vulns.length - top.length),
      secretsList, link: shareable ? (scan.id ? `${base}/#/report/${scan.id}` : base) : null, host: os.hostname(),
    };
    Object.defineProperty(msg, 'scan', { value: scan }); // used to build the PDF attachment
    return msg;
  }
  const SEVEMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', UNKNOWN: '⚪' };

  function slackPayload(m) {
    const lines = m.top.map((t) => `${SEVEMOJI[t.sev]} *${t.url ? `<${t.url}|${t.id}>` : t.id}* — \`${t.pkg}\` ${t.ver}${t.fix ? ` → fix *${t.fix}*` : ' (no fix yet)'}`);
    if (m.more) lines.push(`_…and ${m.more} more_`);
    const blocks = [
      { type: 'header', text: { type: 'plain_text', text: m.title.slice(0, 150), emoji: true } },
      { type: 'section', text: { type: 'mrkdwn', text: `${m.company ? `*${m.company}*\n` : ''}${m.headline}` } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Target*\n${m.target}` }, { type: 'mrkdwn', text: `*Overall risk*\n${m.risk}` },
        { type: 'mrkdwn', text: `*Findings*\n${SEVS.slice(0, 4).map((v) => `${SEVEMOJI[v]} ${m.counts[v]}`).join('  ')}` }, { type: 'mrkdwn', text: `*Scanned*\n${m.when}` },
      ] },
    ];
    if (lines.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: lines.join('\n').slice(0, 2900) } });
    if (m.secretsList.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: '*Exposed secrets*\n' + m.secretsList.map((x) => '• ' + x).join('\n') } });
    if (m.actions.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: '*What to do*\n' + m.actions.map((a, i) => `${i + 1}. ${a}`).join('\n').slice(0, 2900) } });
    if (m.link) blocks.push({ type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Open in Vulnora' }, url: m.link, style: 'danger' }] });
    else if (m.pdfByEmail) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: ':page_facing_up: *Full PDF report:* attached to the email alert.' } });
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `Vulnora · See Vulnerabilities. Secure Every Layer. · ${m.host}` }] });
    return { text: m.title, blocks };
  }

  function teamsPayload(m) {
    const card = {
      $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4', msteams: { width: 'Full' },
      body: [
        ...(m.company ? [{ type: 'TextBlock', text: m.company, weight: 'Bolder', size: 'Medium', isSubtle: true }] : []),
        { type: 'TextBlock', text: m.title, weight: 'Bolder', size: 'Large', color: 'Attention', wrap: true },
        { type: 'TextBlock', text: m.headline, wrap: true },
        { type: 'FactSet', facts: [
          { title: 'Target', value: m.target }, { title: 'Overall risk', value: m.risk },
          { title: 'Findings', value: SEVS.slice(0, 4).map((v) => `${v[0] + v.slice(1).toLowerCase()} ${m.counts[v]}`).join(' · ') },
          { title: 'Scanned', value: m.when },
        ] },
      ],
      actions: m.link ? [{ type: 'Action.OpenUrl', title: 'Open in Vulnora', url: m.link }] : [],
    };
    if (m.top.length) {
      card.body.push({ type: 'TextBlock', text: 'Top issues', weight: 'Bolder', spacing: 'Medium' });
      m.top.forEach((t) => card.body.push({ type: 'TextBlock', wrap: true, spacing: 'Small', text: `${SEVEMOJI[t.sev]} **${t.url ? `[${t.id}](${t.url})` : t.id}** — ${t.pkg} ${t.ver}${t.fix ? ` → fix **${t.fix}**` : ' (no fix yet)'}` }));
      if (m.more) card.body.push({ type: 'TextBlock', text: `…and ${m.more} more`, isSubtle: true, spacing: 'Small' });
    }
    if (m.secretsList.length) card.body.push({ type: 'TextBlock', text: '**Exposed secrets**\n\n' + m.secretsList.map((x) => '- ' + x).join('\n'), wrap: true });
    if (m.actions.length) card.body.push({ type: 'TextBlock', text: '**What to do**\n\n' + m.actions.map((a, i) => `${i + 1}. ${a}`).join('\n'), wrap: true });
    if (!m.link && m.pdfByEmail) card.body.push({ type: 'TextBlock', text: '📄 **Full PDF report:** attached to the email alert.', wrap: true, spacing: 'Medium' });
    return { type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', contentUrl: null, content: card }] };
  }

  const h = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const HEX = { CRITICAL: '#ff3d71', HIGH: '#ff8a3d', MEDIUM: '#f5c542', LOW: '#38bdf8', UNKNOWN: '#8b93a7' };
  function emailBodies(m) {
    const brand = getBrand() || {};
    const head = /^#[0-9a-f]{6}$/i.test(brand.headerColor || '') ? brand.headerColor : '#0e1126';
    const text = [m.company, m.title, '', m.headline, '', `Target: ${m.target}`, `Overall risk: ${m.risk}`,
      `Findings: ${SEVS.map((v) => `${v} ${m.counts[v]}`).join(', ')}`, `Scanned: ${m.when}`, '',
      ...(m.top.length ? ['Top issues:', ...m.top.map((t) => `- [${t.sev}] ${t.id} ${t.pkg} ${t.ver}${t.fix ? ' -> fix ' + t.fix : ' (no fix yet)'}`), ...(m.more ? [`...and ${m.more} more`] : []), ''] : []),
      ...(m.secretsList.length ? ['Exposed secrets:', ...m.secretsList.map((x) => '- ' + x), ''] : []),
      ...(m.actions.length ? ['What to do:', ...m.actions.map((a, i) => `${i + 1}. ${a}`), ''] : []),
      m.pdf ? `Full report: attached as ${m.pdf.filename} (PDF, ${kb(m.pdf.size)})` : `Full report: ${m.pdfError ? 'the PDF could not be attached (' + m.pdfError + ')' : 'open Vulnora on the scanning computer'}`,
      ...(m.link ? [`Open in Vulnora: ${m.link}`] : [])].filter((x) => x !== undefined).join('\r\n');
    const rows = m.top.map((t) => `<tr><td style="padding:6px 8px"><span style="background:${HEX[t.sev]};color:#10121f;font-weight:700;font-size:11px;padding:2px 7px;border-radius:4px">${t.sev}</span></td><td style="padding:6px 8px;font-family:Consolas,monospace">${t.url ? `<a href="${h(t.url)}">${h(t.id)}</a>` : h(t.id)}</td><td style="padding:6px 8px;font-family:Consolas,monospace">${h(t.pkg)}</td><td style="padding:6px 8px">${h(t.ver)}</td><td style="padding:6px 8px">${t.fix ? `<b>${h(t.fix)}</b>` : '<span style="color:#888">no fix yet</span>'}</td></tr>`).join('');
    const html = `<!doctype html><html><body style="margin:0;background:#f3f4f8;font-family:Segoe UI,Arial,sans-serif;color:#1e223c">
<div style="max-width:680px;margin:0 auto;background:#fff">
<div style="background:${head};color:${isLight(head) ? '#1e223c' : '#fff'};padding:22px 26px">
${m.company ? `<div style="font-size:20px;font-weight:800;margin-bottom:6px">${h(m.company)}</div>` : ''}
<div style="font-size:17px;font-weight:700">${h(m.title)}</div><div style="opacity:.75;font-size:12px;margin-top:4px">${h(m.when)} · ${h(m.module)} scan</div></div>
<div style="height:4px;background:linear-gradient(90deg,#22c3f5,#1f6fff,#6d3df5)"></div>
<div style="padding:22px 26px">
<p style="font-size:15px;font-weight:600;margin:0 0 14px">${h(m.headline)}</p>
<table style="border-collapse:collapse;font-size:13px;margin-bottom:16px"><tr><td style="color:#6e7491;padding:2px 14px 2px 0">Target</td><td><b>${h(m.target)}</b></td></tr><tr><td style="color:#6e7491;padding:2px 14px 2px 0">Overall risk</td><td><b>${h(m.risk)}</b></td></tr>
<tr><td style="color:#6e7491;padding:2px 14px 2px 0">Findings</td><td>${SEVS.slice(0, 4).map((v) => `<span style="color:${HEX[v]};font-weight:700">●</span> ${v[0] + v.slice(1).toLowerCase()} ${m.counts[v]}`).join(' &nbsp; ')}</td></tr></table>
${rows ? `<h3 style="font-size:14px;margin:18px 0 6px">Top issues</h3><table style="border-collapse:collapse;font-size:12.5px;width:100%;border:1px solid #eceef5"><tr style="background:#f6f7fc;text-align:left"><th style="padding:6px 8px">Severity</th><th style="padding:6px 8px">ID</th><th style="padding:6px 8px">Package</th><th style="padding:6px 8px">Installed</th><th style="padding:6px 8px">Fixed in</th></tr>${rows}</table>${m.more ? `<div style="color:#6e7491;font-size:12px;margin-top:4px">…and ${m.more} more</div>` : ''}` : ''}
${m.secretsList.length ? `<h3 style="font-size:14px;margin:18px 0 6px">Exposed secrets</h3><ul style="font-size:13px;margin:0;padding-left:18px">${m.secretsList.map((x) => `<li>${h(x)}</li>`).join('')}</ul>` : ''}
${m.actions.length ? `<h3 style="font-size:14px;margin:18px 0 6px">What to do</h3><ol style="font-size:13px;margin:0;padding-left:18px">${m.actions.map((a) => `<li style="margin:3px 0">${h(a)}</li>`).join('')}</ol>` : ''}
${m.pdf ? `<table role="presentation" style="border-collapse:separate;width:100%;margin:22px 0 4px;background:#eef4ff;border:1px solid #d5def0;border-radius:10px"><tr>
<td style="padding:14px 0 14px 16px;width:44px;vertical-align:middle"><div style="width:40px;height:48px;border-radius:6px;background:#d92d20;color:#fff;font:700 12px Arial,sans-serif;text-align:center;line-height:48px">PDF</div></td>
<td style="padding:14px 16px;vertical-align:middle"><div style="font-size:14px;font-weight:700;color:#0e2a6e">Full report attached</div>
<div style="font-size:13px;color:#3b4560;margin-top:2px">${h(m.pdf.filename)} &middot; ${kb(m.pdf.size)}</div>
<div style="font-size:12px;color:#6b7590;margin-top:4px">Open the attachment to see every finding, the executive summary and the full fix list. No Vulnora install needed.</div></td></tr></table>`
  : `<p style="font-size:13px;color:#6b7590;margin:22px 0 4px">${m.pdfError ? 'The PDF report could not be attached: ' + h(m.pdfError) : 'The full report is available in Vulnora on the scanning computer.'}</p>`}
${m.link ? `<p style="margin:14px 0 4px;font-size:13px"><a href="${h(m.link)}" style="color:#1e6fe0;font-weight:600">Open this scan in Vulnora</a></p>` : ''}
<p style="color:#9aa0b8;font-size:11px;margin-top:18px">Sent by <b>Vulnora</b> on ${h(m.host)}.</p>
</div></div></body></html>`;
    return { text, html };
  }
  const isLight = (hex) => { const n = parseInt(hex.slice(1), 16); return 0.299 * (n >> 16 & 255) + 0.587 * (n >> 8 & 255) + 0.114 * (n & 255) > 160; };

  /* ---------- transports ---------- */
  function postJson(urlStr, payload) {
    return new Promise((resolve, reject) => {
      const url = new URL(urlStr);
      const body = Buffer.from(JSON.stringify(payload));
      const lib = url.protocol === 'http:' ? http : https;
      const req = lib.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': body.length }, timeout: 15000 }, (res) => {
        let d = ''; res.on('data', (c) => { if (d.length < 2000) d += c; });
        res.on('end', () => (res.statusCode >= 200 && res.statusCode < 300 ? resolve(d) : reject(new Error(`HTTP ${res.statusCode}${d ? ': ' + d.slice(0, 200) : ''}`))));
      });
      req.on('timeout', () => req.destroy(new Error('Timed out')));
      req.on('error', reject);
      req.end(body);
    });
  }

  // Minimal SMTP client: EHLO, (STARTTLS), AUTH LOGIN/PLAIN, MAIL, RCPT, DATA
  function sendMail(e, subject, bodies, attachments = []) {
    return new Promise((resolve, reject) => {
      const to = emailList(e.to);
      if (!e.host || !e.from || !to.length) return reject(new Error('Email needs SMTP host, From and To'));
      let sock; let buf = ''; let waiter = null; let done = false;
      const timer = setTimeout(() => fail(new Error('SMTP timed out')), 30000);
      const fail = (err) => { if (done) return; done = true; clearTimeout(timer); try { sock.destroy(); } catch (x) { /* ignore */ } reject(err); };
      const onData = (d) => {
        buf += d.toString('utf8');
        if (!waiter) return; // keep buffering until someone reads
        const lines = buf.split('\r\n');
        for (let i = 0; i < lines.length - 1; i++) {
          if (/^\d{3} /.test(lines[i])) { // final line of a reply
            const reply = lines.slice(0, i + 1).join('\n');
            buf = lines.slice(i + 1).join('\r\n');
            const w = waiter; waiter = null; if (w) w(reply);
            return;
          }
        }
      };
      const read = () => new Promise((res) => { waiter = res; if (buf) onData(''); });
      const cmd = async (line, expect) => {
        if (line != null) sock.write(line + '\r\n');
        const r = await read();
        const code = Number(r.slice(0, 3));
        if (!expect.includes(code)) throw new Error(`SMTP: ${line ? line.split(' ')[0].replace(/^AUTH$/, 'AUTH') : 'connect'} failed - ${r.split('\n').pop()}`);
        return r;
      };
      const attach = (s) => { sock = s; s.on('data', onData); s.on('error', fail); };
      const port = Number(e.port) || (e.security === 'ssl' ? 465 : 587);
      const sni = net.isIP(e.host) ? undefined : e.host;
      const opts = { host: e.host, port, servername: sni };
      const start = async () => {
        try {
          await cmd(null, [220]);
          let ehlo = await cmd('EHLO vulnora', [250]);
          if (e.security === 'starttls') {
            await cmd('STARTTLS', [220]);
            sock.removeListener('data', onData);
            await new Promise((res, rej) => { const t = tls.connect({ socket: sock, servername: sni }, res); t.on('error', rej); attach(t); });
            ehlo = await cmd('EHLO vulnora', [250]);
          }
          if (e.user) {
            if (/AUTH[^\n]*PLAIN/i.test(ehlo) && !/AUTH[^\n]*LOGIN/i.test(ehlo)) {
              await cmd('AUTH PLAIN ' + Buffer.from(`\0${e.user}\0${e.pass}`).toString('base64'), [235]);
            } else {
              await cmd('AUTH LOGIN', [334]);
              await cmd(Buffer.from(e.user).toString('base64'), [334]);
              await cmd(Buffer.from(e.pass || '').toString('base64'), [235]).catch(() => { throw new Error('SMTP login failed - check username and password (Gmail/Outlook need an app password)'); });
            }
          }
          await cmd(`MAIL FROM:<${e.from}>`, [250]);
          for (const r of to) await cmd(`RCPT TO:<${r}>`, [250, 251]);
          await cmd('DATA', [354]);
          sock.write(mime(e.from, to, subject, bodies, attachments) + '\r\n.\r\n');
          await cmd(null, [250]);
          sock.write('QUIT\r\n');
          done = true; clearTimeout(timer); setTimeout(() => { try { sock.end(); } catch (x) { /* ignore */ } }, 200);
          resolve('sent to ' + to.join(', ') + (attachments.length ? ' with the PDF report attached' : ''));
        } catch (err) { fail(err); }
      };
      try {
        if (e.security === 'ssl') attach(tls.connect(opts, start));
        else attach(net.connect(opts, start));
      } catch (err) { fail(err); }
    });
  }
  const kb = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB');
  function mime(from, to, subject, { text, html }, attachments = []) {
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
    const enc = (s) => `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
    const brand = getBrand() || {};
    const boundary = 'vulnora-' + Date.now().toString(36);
    return [
      `From: ${brand.company ? enc(brand.company + ' Security') : 'Vulnora'} <${from}>`,
      `To: ${to.join(', ')}`,
      `Subject: ${enc(subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@vulnora>`,
      'MIME-Version: 1.0',
      ...(attachments.length ? [`Content-Type: multipart/mixed; boundary="${boundary}-m"`, '', `--${boundary}-m`] : []),
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      '', `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64(text),
      `--${boundary}`, 'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64(html),
      `--${boundary}--`,
      ...attachments.flatMap((a) => {
        const name = String(a.filename).replace(/[^A-Za-z0-9._-]/g, '_');
        return ['', `--${boundary}-m`, `Content-Type: ${a.type}; name="${name}"`, `Content-Disposition: attachment; filename="${name}"`,
          'Content-Transfer-Encoding: base64', '', a.content.toString('base64').replace(/.{76}/g, '$&\r\n')];
      }),
      ...(attachments.length ? ['', `--${boundary}-m--`] : []),
    ].join('\r\n');
  }

  /* ---------- dispatch ---------- */
  async function deliver(m, channels, c = cfg) {
    const res = [];
    const jobs = [];
    m.pdfByEmail = channels.includes('email') || !!(c.email && c.email.enabled);
    let attachments = [];
    if (channels.includes('email') && makePdf && m.scan) {
      try {
        const pdf = await makePdf(m.scan);
        if (pdf.buffer.length > 10 * 1048576) m.pdfError = 'the report is larger than 10 MB';
        else { attachments = [{ filename: pdf.filename, type: 'application/pdf', content: pdf.buffer }]; m.pdf = { filename: pdf.filename, size: pdf.buffer.length }; }
      } catch (err) { m.pdfError = err.message; log('PDF for email failed: ' + err.message); }
    }
    if (channels.includes('slack')) jobs.push(['Slack', () => (c.slack.webhook ? postJson(c.slack.webhook, slackPayload(m)).then(() => 'posted') : Promise.reject(new Error('No Slack webhook URL saved')))]);
    if (channels.includes('teams')) jobs.push(['Teams', () => (c.teams.webhook ? postJson(c.teams.webhook, teamsPayload(m)).then(() => 'posted') : Promise.reject(new Error('No Teams webhook URL saved')))]);
    if (channels.includes('email')) jobs.push(['Email', () => sendMail(c.email, m.title.replace(/^\S+\s/, '[Security] '), emailBodies(m), attachments)]);
    await Promise.all(jobs.map(async ([name, fn]) => {
      try { const d = await fn(); res.push({ channel: name, ok: true, detail: d }); }
      catch (err) { res.push({ channel: name, ok: false, error: err.message }); }
    }));
    return res;
  }
  const enabledChannels = (c = cfg) => ['email', 'slack', 'teams'].filter((k) => c[k].enabled);

  // called after every stored scan
  async function onScan(scan, previous) {
    if (!cfg.enabled || scan.module === 'sbom' || scan.engine === 'demo') return null;
    const ch = enabledChannels();
    if (!ch.length) return null;
    const trig = triggering(scan, previous);
    if (!trig.total) return { skipped: true, reason: `no ${cfg.onlyNew ? 'new ' : ''}${cfg.minSeverity === 'HIGH' ? 'critical/high' : 'critical'} findings` };
    const results = await deliver(message(scan, trig), ch);
    history.unshift({ at: new Date().toISOString(), target: scan.target, scanId: scan.id, results });
    history.splice(30);
    results.forEach((r) => log(`Alert via ${r.channel}: ${r.ok ? 'sent' : 'FAILED - ' + r.error}`));
    return { results };
  }

  // "Send test" button: uses the unsaved form values (secrets fall back to saved ones) and a sample scan
  async function test(body, sampleScan) {
    const c = build(body || {}, cfg);
    const channel = body && body.channel;
    if (!['email', 'slack', 'teams'].includes(channel)) throw new Error('Unknown channel');
    const forced = { ...c, minSeverity: 'HIGH', onlyNew: false, includeSecrets: true };
    const trig = triggering(sampleScan, null, forced);
    const m = message({ ...sampleScan, target: sampleScan.target + ' [TEST ALERT]' }, trig, forced);
    m.title = '🧪 Test alert: ' + m.title.replace(/^\S+\s/, '');
    const [r] = await deliver(m, [channel], c);
    return r;
  }

  return { publicConfig, update, onScan, test, triggering, _message: message, _slack: slackPayload, _teams: teamsPayload, _email: emailBodies };
}

module.exports = { createAlerts };

'use strict';
/* Vulnora front-end (vanilla JS, no build step). All scanned data is HTML-escaped before rendering. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const safeUrl = (u) => (/^https?:\/\//i.test(u || '') ? u : '');
const fmt = (n) => Number(n || 0).toLocaleString();
const sevTag = (s) => `<span class="sev" style="--c:var(--${s})">${s}</span>`;
const total = (c) => SEVS.reduce((n, s) => n + (c[s] || 0), 0);

async function api(p, opt = {}) {
  const r = await fetch('/api' + p, { headers: { 'Content-Type': 'application/json' }, ...opt });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 3500);
}
function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: type || 'application/json' }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* ---------- module catalogue ---------- */
const MODS = {
  image: { title: 'Container image scan', ic: '▣', blurb: 'Find CVEs in OS packages and language dependencies inside any container image.', ph: 'ubuntu:latest   or   nginx:1.27   or   registry.example.com/app:1.0', scanners: true },
  fs: { title: 'Filesystem / project scan', ic: '▤', blurb: 'Scan a local project folder: lock files (npm, pip, Maven, Go, Cargo…), IaC and secrets.', ph: 'C:\\Projects\\my-app', scanners: true },
  repo: { title: 'Git repository scan', ic: '⑂', blurb: 'Clone and scan a remote Git repository for vulnerabilities, secrets and misconfigurations.', ph: 'https://github.com/org/repo', scanners: true },
  config: { title: 'Misconfiguration (IaC) scan', ic: '⚙', blurb: 'Check Dockerfile, Kubernetes, Terraform, CloudFormation and Helm for insecure settings.', ph: 'C:\\Projects\\infra', scanners: false },
  secret: { title: 'Secret scan', ic: '⚿', blurb: 'Detect hard-coded API keys, tokens, passwords and private keys.', ph: 'ubuntu:latest  /  C:\\Projects\\my-app  /  https://github.com/org/repo', scanners: false, pickSource: true },
  license: { title: 'License scan', ic: '§', blurb: 'List package licenses and flag restricted or forbidden ones for compliance.', ph: 'ubuntu:latest  /  C:\\Projects\\my-app', scanners: false, pickSource: true },
  webapp: { title: 'Web application scan', ic: '◎', blurb: 'Passive security checks on a live website you own or are authorised to test: security headers, cookies, HTTPS/TLS, exposed files and CORS. No Docker needed.', ph: 'https://your-app.example.com', scanners: false, web: true },
  sbom: { title: 'SBOM generator', ic: '☰', blurb: 'Produce a Software Bill of Materials (CycloneDX or SPDX) for an image.', ph: 'ubuntu:latest', scanners: false },
};
const SCANNER_LABELS = { vuln: 'Vulnerabilities', secret: 'Secrets', misconfig: 'Misconfigurations', license: 'Licenses' };

/* ---------- state / shell ---------- */
let engine = null;
let pollTimer = null;
let routeSeq = 0; // guards against a slow page overwriting a newer one
const stopPoll = () => { clearInterval(pollTimer); pollTimer = null; };

async function refreshEngine(force) {
  try {
    engine = await api('/status' + (force ? '?force=1' : ''));
    const e = engine;
    const ok = e.engine !== 'none';
    $('#engine-pill').innerHTML = ok
      ? `<span class="dot ok"></span>Engine: <b>${e.engine === 'docker' ? 'Docker' : 'Native Trivy'}</b><br><span class="small">${e.engine === 'docker' ? (e.docker.trivyImageReady ? 'Trivy image ready' : 'Trivy image will be pulled on first scan') : esc(e.native.version || '')}</span>`
      : '<span class="dot bad"></span>No engine found<br><span class="small">Start Docker Desktop</span>';
  } catch (e) { $('#engine-pill').textContent = 'Server unreachable'; }
}
function setCrumb(html) { $('#crumb').innerHTML = html; }
// Vulnora shield that matches the current theme (dark-lettered on light, white-lettered on dark)
const mark = (w = 34) => `<img class="theme-light-only" src="logo-dark.png" width="${w}" alt=""><img class="theme-dark-only" src="logo.png" width="${w}" alt="">`;
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('vn-theme', t); } catch (e) { /* storage blocked: theme lasts for this visit */ }
  const meta = document.querySelector('meta[name=theme-color]'); if (meta) meta.content = t === 'dark' ? '#0a1128' : '#f4f7fc';
  $('#theme-label').textContent = t === 'dark' ? 'Light mode' : 'Dark mode';
  $('#theme').setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}
$('#theme').onclick = () => applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
// Enter / Space activates a focused tab
document.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('tab')) { e.preventDefault(); e.target.click(); } });
function setNav(r) { $$('#nav a').forEach((a) => a.classList.toggle('on', a.dataset.r === r)); $('#side').classList.remove('open'); }
$('#burger').onclick = () => $('#side').classList.toggle('open');

/* ---------- charts ---------- */
function donut(counts, size = 150) {
  const t = total(counts);
  const r = 54, c = 2 * Math.PI * r;
  let off = 0, segs = '';
  if (t) SEVS.forEach((s) => {
    const v = counts[s] || 0; if (!v) return;
    const len = (v / t) * c;
    segs += `<circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--${s})" stroke-width="16" stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-off}" transform="rotate(-90 70 70)"/>`;
    off += len;
  });
  const svg = `<svg width="${size}" height="${size}" viewBox="0 0 140 140"><circle cx="70" cy="70" r="${r}" fill="none" class="track" stroke-width="16"/>${segs}<text class="big" x="70" y="68" text-anchor="middle" font-size="26" font-weight="700">${fmt(t)}</text><text class="lbl" x="70" y="86" text-anchor="middle" font-size="11">findings</text></svg>`;
  const legend = SEVS.map((s) => `<div style="--c:var(--${s})"><i></i>${s[0] + s.slice(1).toLowerCase()}<b>${fmt(counts[s])}</b></div>`).join('');
  return `<div class="donut">${svg}<div class="legend">${legend}</div></div>`;
}
function hbars(items, colorFn) { // items: [{name, value, stack?:{sev:n}}]
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return '<div class="muted">Nothing to show.</div>';
  return `<div class="bars">${items.map((i) => {
    const inner = i.stack
      ? SEVS.map((s) => (i.stack[s] ? `<i style="width:${(i.stack[s] / max) * 100}%;background:var(--${s})"></i>` : '')).join('')
      : `<i style="width:${(i.value / max) * 100}%;background:${colorFn ? colorFn(i) : 'var(--grad)'}"></i>`;
    return `<div class="b"><span class="nm" title="${esc(i.name)}">${esc(i.name)}</span><div class="t">${inner}</div><b>${fmt(i.value)}</b></div>`;
  }).join('')}</div>`;
}
function topPackages(vulns, n = 8) {
  const m = new Map();
  vulns.forEach((v) => {
    const o = m.get(v.pkg) || { name: v.pkg, value: 0, stack: {} };
    o.value++; o.stack[v.severity] = (o.stack[v.severity] || 0) + 1; m.set(v.pkg, o);
  });
  return [...m.values()].sort((a, b) => b.value - a.value).slice(0, n);
}

/* ---------- overview ---------- */
async function viewHome() {
  const my = routeSeq;
  setNav('home'); setCrumb('<b>Overview</b>');
  const scans = await api('/scans');
  if (my !== routeSeq) return;
  const real = scans.filter((s) => s.module !== 'sbom');
  const latest = real[0];
  const crit = latest ? latest.summary.vulns.CRITICAL : 0;
  const high = latest ? latest.summary.vulns.HIGH : 0;
  const allFind = real.reduce((n, s) => n + total(s.summary.vulns) + total(s.summary.secrets) + total(s.summary.misconfigs) + total(s.summary.licenses), 0);
  const offline = engine && engine.engine === 'none';
  let h = `<h1>Security overview</h1><p class="sub">Scan images, code, infrastructure and dependencies from one place.</p>`;
  if (offline) h += `<div class="banner"><b>No scan engine detected.</b> Start Docker Desktop (or install Trivy) and refresh. You can still explore the dashboard with demo data.</div>`;
  h += `<section class="launch" aria-label="Start a scan"><div><h2>What do you want to scan?</h2><p>Pick a target type, paste its name, path or URL, then review the scan options.</p></div>
    <form id="quick"><select id="qmod" aria-label="Target type"><option value="image">Container image</option><option value="fs">Project folder</option><option value="repo">Git repository</option><option value="config">IaC files</option><option value="webapp">Website (URL)</option></select>
    <input type="text" id="qtarget" placeholder="nginx:1.27" aria-label="Target" autocomplete="off"><button class="btn pri" type="submit">Set up scan</button>
    <div class="alt">No Docker yet? <button type="button" id="demo">Load demo data</button> to explore every page.</div></form></section>`;
  h += `<div class="grid g4" style="margin-bottom:16px">
    <div class="card kpi" style="--c:var(--a1)"><div class="l">Scans run</div><div class="n">${fmt(scans.length)}</div></div>
    <div class="card kpi" style="--c:var(--CRITICAL)"><div class="l">Critical (latest)</div><div class="n">${fmt(crit)}</div></div>
    <div class="card kpi" style="--c:var(--HIGH)"><div class="l">High (latest)</div><div class="n">${fmt(high)}</div></div>
    <div class="card kpi" style="--c:var(--a3)"><div class="l">Total findings (all scans)</div><div class="n">${fmt(allFind)}</div></div></div>`;
  if (latest) {
    const trend = real.slice(0, 10).reverse();
    const mx = Math.max(1, ...trend.map((s) => total(s.summary.vulns)));
    h += `<div class="grid g2" style="margin-bottom:16px">
      <div class="card"><h2>Latest scan: vulnerabilities</h2><div class="muted small wrap" style="margin:-6px 0 12px">${esc(latest.target)}</div>${donut(latest.summary.vulns)}</div>
      <div class="card"><h2>Vulnerability trend (last ${trend.length} scans)</h2><div class="trend">${trend.map((s) => {
        const t = total(s.summary.vulns);
        return `<div class="col" data-id="${s.id}" title="${esc(s.target)}: ${t} vulns"><div class="stack" style="height:${(t / mx) * 100}%;min-height:${t ? 4 : 1}px">${SEVS.map((v) => `<div style="flex:${s.summary.vulns[v] || 0};background:var(--${v})"></div>`).join('')}</div><small>${esc(s.target.split('/').pop())}</small></div>`;
      }).join('')}</div></div></div>`;
  }
  h += `<h2 style="margin-top:8px">Modules</h2><div class="grid g4" style="margin-bottom:22px">${Object.entries(MODS).map(([k, m]) => `<a class="card mod-card" href="#/scan/${k}"><div class="ic">${m.ic}</div><b>${m.title}</b><span>${m.blurb}</span></a>`).join('')}</div>`;
  h += `<h2>Recent scans</h2><div class="card pad0">${scanTable(scans.slice(0, 8))}</div>`;
  $('#view').innerHTML = h;
  $('#demo').onclick = async () => { const r = await api('/demo', { method: 'POST' }); location.hash = '#/report/' + r.id; };
  const QPH = { image: 'nginx:1.27', fs: 'C:\\projects\\my-app', repo: 'https://github.com/org/repo', config: 'C:\\projects\\infra', webapp: 'https://your-app.example.com' };
  $('#qmod').onchange = () => ($('#qtarget').placeholder = QPH[$('#qmod').value]);
  $('#quick').onsubmit = (ev) => { ev.preventDefault(); prefillTarget = $('#qtarget').value.trim(); location.hash = '#/scan/' + $('#qmod').value; };
  $$('.trend .col').forEach((c) => (c.onclick = () => (location.hash = '#/report/' + c.dataset.id)));
  bindScanTable();
}
function scanTable(list) {
  if (!list.length) return `<div class="empty">${mark()}<div>No scans yet. Run your first scan or load demo data.</div></div>`;
  return `<div class="tw"><table><thead><tr><th>Target</th><th>Module</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Other</th><th>When</th></tr></thead><tbody>${list.map((s) => {
    const all = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    ['vulns', 'secrets', 'misconfigs', 'licenses'].forEach((k) => SEVS.forEach((v) => (all[v] += s.summary[k][v] || 0)));
    const cell = (v) => (all[v] ? `<span class="sev" style="--c:var(--${v})">${all[v]}</span>` : '<span class="muted">0</span>');
    const extra = s.sbom ? `${fmt(s.sbom.components)} components` : '';
    return `<tr class="r" data-id="${s.id}"><td class="wrap"><b>${esc(s.target)}</b></td><td>${esc(s.module)}${s.engine === 'demo' ? ' <span class="tag">demo</span>' : ''}</td>${s.sbom ? `<td colspan="5" class="muted">${extra}</td>` : `<td>${cell('CRITICAL')}</td><td>${cell('HIGH')}</td><td>${cell('MEDIUM')}</td><td>${cell('LOW')}</td><td>${cell('UNKNOWN')}</td>`}<td class="muted small">${new Date(s.createdAt).toLocaleString()}</td></tr>`;
  }).join('')}</tbody></table></div>`;
}
function bindScanTable() { $$('tr.r[data-id]').forEach((r) => (r.onclick = () => (location.hash = '#/report/' + r.dataset.id))); }

/* ---------- scan form ---------- */
let prefillTarget = '';
function viewScan(mod) {
  const m = MODS[mod]; if (!m) { location.hash = '#/'; return; }
  setNav('scan/' + mod); setCrumb(`Scan modules › <b>${m.title}</b>`);
  const offline = engine && engine.engine === 'none' && !m.web; // web checks run inside Vulnora, no Trivy needed
  let h = `<h1>${m.title}</h1><p class="sub">${m.blurb}</p>`;
  if (offline) h += `<div class="banner"><b>No scan engine detected.</b> Start Docker Desktop, then reload this page.</div>`;
  h += `<div class="grid" style="grid-template-columns:minmax(0,1.4fr) minmax(0,1fr)"><div class="card" id="formcard"><form id="f">`;
  if (m.pickSource) h += `<label class="f">Scan source</label><select id="source"><option value="image">Container image</option><option value="fs">Local folder</option><option value="repo">Git repository</option></select>`;
  h += `<label class="f" id="tlabel">${m.web ? 'Website URL' : mod === 'fs' || mod === 'config' ? 'Folder path on this computer' : mod === 'repo' ? 'Repository URL' : 'Target'}</label><input type="text" id="target" placeholder="${esc(m.ph)}" autocomplete="off" required>`;
  if (m.scanners) {
    const def = ['vuln'];
    h += `<label class="f">What to look for</label>` + Object.entries(SCANNER_LABELS).map(([k, l]) => `<label class="chk"><input type="checkbox" name="sc" value="${k}" ${def.includes(k) ? 'checked' : ''}>${l}</label>`).join('');
  }
  if (mod === 'sbom') h += `<label class="f">Format</label><select id="sbomfmt"><option value="cyclonedx">CycloneDX (JSON)</option><option value="spdx-json">SPDX (JSON)</option></select>`;
  if (m.web) h += `<label class="chk authz"><input type="checkbox" id="authz"><span>I own this website or have <b>written permission</b> to test it. (Testing sites without permission can be illegal.)</span></label>`;
  if (mod !== 'sbom' && !m.web) {
    h += `<label class="f">Severities to include</label><div class="chips" id="sevs">${SEVS.map((s) => `<span class="chip on" data-s="${s}" style="--c:var(--${s})"><i></i>${s}</span>`).join('')}</div>`;
    h += `<label class="chk" style="margin-top:14px"><input type="checkbox" id="unfixed">Hide vulnerabilities with no fix available</label>`;
  }
  h += `<div id="localwrap"><label class="chk"><input type="checkbox" id="local">Use images from my local Docker (mounts the Docker socket)</label></div>`;
  h += `<div class="row" style="margin-top:20px"><button class="btn pri" id="go" ${offline ? 'disabled' : ''}>Start scan</button><span class="muted small">${m.web ? 'About 20 paced requests; usually done in under a minute.' : 'First run downloads the Trivy database (~1–2 min).'}</span></div></form></div>`;
  h += `<div class="card"><h2>About this module</h2><div class="muted" style="font-size:13px">${aboutModule(mod)}</div></div></div><div id="run" style="margin-top:16px"></div>`;
  $('#view').innerHTML = h;
  $$('#sevs .chip').forEach((c) => (c.onclick = () => c.classList.toggle('on')));
  if (prefillTarget) { $('#target').value = prefillTarget; prefillTarget = ''; }
  $('#target').focus();
  const srcSel = $('#source');
  const syncSource = () => {
    const src = srcSel ? srcSel.value : mod === 'fs' || mod === 'config' ? 'fs' : mod === 'repo' ? 'repo' : 'image';
    $('#localwrap').style.display = m.web ? 'none' : src === 'image' && mod !== 'sbom' ? '' : mod === 'sbom' ? '' : 'none';
    if (srcSel) $('#tlabel').textContent = src === 'fs' ? 'Folder path on this computer' : src === 'repo' ? 'Repository URL' : 'Image name';
  };
  if (srcSel) srcSel.onchange = syncSource;
  syncSource();
  $('#f').onsubmit = async (ev) => {
    ev.preventDefault();
    const body = {
      module: mod, target: $('#target').value.trim(), source: srcSel ? srcSel.value : undefined,
      scanners: $$('input[name=sc]:checked').map((x) => x.value),
      severities: $$('#sevs .chip.on').map((c) => c.dataset.s),
      ignoreUnfixed: !!($('#unfixed') && $('#unfixed').checked),
      localImage: !!($('#local') && $('#local').checked && $('#localwrap').style.display !== 'none'),
      sbomFormat: $('#sbomfmt') ? $('#sbomfmt').value : undefined,
      authorized: !!($('#authz') && $('#authz').checked),
    };
    if (m.web && !body.authorized) return toast('Tick the box to confirm you are authorised to test this website');
    if (m.scanners && !body.scanners.length) return toast('Select at least one scanner');
    try {
      $('#go').disabled = true;
      const job = await api('/scan', { method: 'POST', body: JSON.stringify(body) });
      watchJob(job.id, $('#run'), () => ($('#go').disabled = false));
    } catch (e) { $('#go').disabled = false; toast(e.message); }
  };
}
function aboutModule(mod) {
  const t = {
    webapp: 'Vulnora requests the page the way a browser does (about 20 requests, paced) and checks: security headers (HSTS, CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy), version banners, cookie flags (Secure, HttpOnly, SameSite), HTTPS redirect, certificate validity and old TLS versions, well-known sensitive files (/.git, /.env, database dumps, phpinfo, server-status, directory listing), CORS origin reflection and the TRACE method. Each finding has evidence, a CWE, its OWASP Top 10:2025 category and a fix. It never submits forms, logs in, fuzzes or sends attack payloads.',
    image: 'Pulls the image (or reads it from local Docker), detects the OS and language packages, and matches them against the vulnerability database. Enable extra scanners to also find secrets baked into layers, Dockerfile misconfigurations and package licenses.',
    fs: 'Point at a folder on your computer. Trivy parses lock files and manifests (package-lock.json, requirements.txt, pom.xml, go.mod, Cargo.lock…) and Infrastructure-as-Code files. The folder is mounted read-only into the container.',
    repo: 'Trivy clones the remote repository and scans the default branch the same way as a local project.',
    config: 'Runs the built-in policy checks against Dockerfiles, Kubernetes YAML, Helm charts, Terraform, CloudFormation and more, and tells you how to fix each failure.',
    secret: 'Pattern- and entropy-based detection of AWS/GCP/GitHub tokens, private keys, passwords and other credentials in files or image layers. Matches are shown redacted.',
    license: 'Reads license metadata of installed packages and classifies it (permissive, notice, reciprocal, restricted, forbidden) so you can spot compliance risks.',
    sbom: 'Generates a machine-readable inventory of every package in an image. Download it as CycloneDX or SPDX JSON for supply-chain and audit workflows.',
  };
  return t[mod];
}

/* ---------- background scan tracker (non-blocking dock) ----------
   Scans run on the server; this dock just follows them. It never covers the page,
   survives navigation, and picks running scans back up after a refresh. */
const stageText = (log) => {
  const l = [...log].reverse().find((x) => x.trim() && !x.startsWith('$')) || 'Starting…';
  return l.replace(/^\S+\s+(INFO|WARN|ERROR|FATAL)\s+/, '').slice(0, 160);
};
const tracked = new Map(); // id -> { job, open, origin, notified }
let trackTimer = null;
let dockMin = false;
try { dockMin = localStorage.getItem('vn-dock-min') === '1'; } catch (e) { /* storage blocked */ }
const isActive = (j) => !j || j.status === 'running' || j.status === 'queued';
const elapsed = (j) => { const s = Math.max(0, Math.floor(((j.finishedAt || Date.now()) - j.startedAt) / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
function trackJob(id, origin) {
  if (!tracked.has(id)) tracked.set(id, { job: null, open: false, origin: origin || '', notified: false });
  pollJobs();
  if (!trackTimer) trackTimer = setInterval(pollJobs, 1000);
}
// kept for existing callers: start following a job without blocking the page
function watchJob(id, el, done) {
  trackJob(id, location.hash);
  if (done) done();
  toast('Started. You can keep using Vulnora; progress is in the bottom-right corner.');
}
let polling = false;
async function pollJobs() {
  if (polling) return; polling = true;
  try {
    await Promise.all([...tracked].filter(([, t]) => isActive(t.job)).map(async ([id, t]) => {
      try { t.job = await api('/jobs/' + id); } catch (e) { t.job = { id, label: 'Scan', status: 'failed', error: 'Lost track of this job (the server may have restarted).', log: [], startedAt: Date.now(), finishedAt: Date.now() }; }
      if (!isActive(t.job) && !t.notified) finished(id, t);
    }));
  } finally { polling = false; }
  if (![...tracked.values()].some((t) => isActive(t.job))) { clearInterval(trackTimer); trackTimer = null; }
  renderDock();
}
function finished(id, t) {
  t.notified = true;
  const j = t.job;
  if (j.status === 'done') {
    refreshEngine(true);
    if (j.scanId) {
      toast('Scan complete: ' + (j.target || j.label));
      if (location.hash === t.origin) { location.hash = '#/report/' + j.scanId; return; } // still on the form you started from
      const r = (location.hash.slice(2) || 'home').split('/')[0];
      if (r === 'home' || r === '' || r === 'history' || r === 'compare') route(); // refresh lists that show scans
    } else { toast(j.label + ' finished'); t.open = true; }
  } else if (j.status === 'failed') { toast('Scan failed: ' + (j.error || 'see the log')); t.open = true; }
}
const JOB_IC = { running: '<span class="dj-spin" aria-hidden="true"></span>', queued: '<span class="dj-q" aria-hidden="true">◷</span>', done: '<span class="dj-ok" aria-hidden="true">✓</span>', failed: '<span class="dj-bad" aria-hidden="true">✕</span>', cancelled: '<span class="dj-off" aria-hidden="true">–</span>' };
function jobSub(j) {
  if (!j) return 'Starting…';
  if (j.status === 'queued') return `Waiting in queue${j.queuePos ? ` (position ${j.queuePos})` : ''}. Starts when the current scan ends.`;
  if (j.status === 'running') return stageText(j.log || []);
  if (j.status === 'done') return j.scanId ? 'Report ready' : 'Finished';
  if (j.status === 'cancelled') return 'Cancelled';
  return (j.error || 'Failed').replace(/\d{4}-\d\d-\d\dT[\d:.]+Z\s*/g, '').replace(/\s+(FATAL|ERROR)\s+/g, ' ');
}
function renderDock() {
  let dock = $('#dock');
  const items = [...tracked].reverse();
  if (!items.length) { if (dock) dock.remove(); return; }
  if (!dock) {
    dock = document.createElement('aside');
    dock.id = 'dock'; dock.className = 'dock'; dock.setAttribute('aria-label', 'Scans in progress');
    dock.innerHTML = `<div class="dock-h"><span class="dock-dot"></span><b>Scans</b><span class="dock-count small"></span><div class="sp"></div>
      <button class="dock-btn" id="dock-min" type="button"></button></div><div class="dock-list" aria-live="polite"></div>`;
    document.body.appendChild(dock);
    dock.querySelector('#dock-min').onclick = () => { dockMin = !dockMin; try { localStorage.setItem('vn-dock-min', dockMin ? '1' : '0'); } catch (e) { /* ignore */ } renderDock(); };
    dock.querySelector('.dock-list').addEventListener('click', onDockClick);
  }
  const active = items.filter(([, t]) => isActive(t.job));
  const run = active.filter(([, t]) => !t.job || t.job.status === 'running').length, q = active.length - run;
  dock.classList.toggle('min', dockMin);
  dock.querySelector('.dock-dot').classList.toggle('live', active.length > 0);
  dock.querySelector('.dock-count').textContent = active.length ? [run && `${run} running`, q && `${q} queued`].filter(Boolean).join(', ') : 'All finished';
  const mb = dock.querySelector('#dock-min'); mb.textContent = dockMin ? 'Show' : 'Hide'; mb.setAttribute('aria-expanded', String(!dockMin));
  const list = dock.querySelector('.dock-list');
  // keyed update: rebuild an item only when its state changes, so the open log keeps its scroll position
  const keep = new Set();
  items.forEach(([id, t], i) => {
    keep.add(id);
    const j = t.job; const st = j ? j.status : 'running';
    const sig = `${st}|${t.open}|${j && j.scanId}`;
    let el = list.querySelector(`[data-job="${id}"]`);
    if (!el || el.dataset.sig !== sig) {
      const html = `<div class="dj st-${st}" data-job="${id}" data-sig="${esc(sig)}">
        <div class="dj-row">${JOB_IC[st] || JOB_IC.running}<div class="dj-main"><div class="dj-t">${esc(j ? (j.target ? `${(j.module || '').toUpperCase()} · ${j.target}` : j.label) : 'Starting scan…')}</div><div class="dj-s"></div></div><span class="dj-time"></span></div>
        ${isActive(j) ? '<div class="progress"><i></i></div>' : ''}
        <div class="dj-act">
          ${st === 'done' && j.scanId ? `<a class="btn sm pri" href="#/report/${esc(j.scanId)}">Open report</a>` : ''}
          <button class="btn sm" data-act="log" type="button">${t.open ? 'Hide log' : 'Show log'}</button>
          ${isActive(j) ? '<button class="btn sm danger" data-act="cancel" type="button">Cancel</button>' : '<button class="btn sm" data-act="dismiss" type="button">Dismiss</button>'}
        </div>${t.open ? '<pre class="log dj-log"></pre>' : ''}</div>`;
      const tmp = document.createElement('div'); tmp.innerHTML = html; const nel = tmp.firstElementChild;
      if (el) el.replaceWith(nel); else list.insertBefore(nel, list.children[i] || null);
      el = nel;
    }
    el.querySelector('.dj-s').textContent = jobSub(j);
    el.querySelector('.dj-time').textContent = j ? elapsed(j) : '0:00';
    const log = el.querySelector('.dj-log');
    if (log && j) { const stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 20; log.textContent = (j.log || []).join('\n'); if (stick) log.scrollTop = log.scrollHeight; }
  });
  [...list.children].forEach((c) => { if (!keep.has(c.dataset.job)) c.remove(); });
}
async function onDockClick(e) {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const id = b.closest('[data-job]').dataset.job; const t = tracked.get(id); if (!t) return;
  if (b.dataset.act === 'log') { t.open = !t.open; renderDock(); }
  else if (b.dataset.act === 'dismiss') { tracked.delete(id); renderDock(); }
  else if (b.dataset.act === 'cancel') { b.disabled = true; try { await api('/jobs/' + id + '/cancel', { method: 'POST' }); } catch (er) { toast(er.message); } pollJobs(); if (!trackTimer) trackTimer = setInterval(pollJobs, 1000); }
}
// pick up scans that were already running (page refresh, or started in another tab)
api('/jobs').then((list) => list.filter((j) => j.status === 'running' || j.status === 'queued').forEach((j) => trackJob(j.id))).catch(() => {});

/* ---------- report ---------- */
const TABS = [['vall', 'All vulnerabilities'], ['vfix', 'Fix available'], ['vnofix', 'No fix yet'], ['secrets', 'Secrets'], ['misconfigs', 'Misconfigurations'], ['licenses', 'Licenses']];
const isV = (t) => t === 'vall' || t === 'vfix' || t === 'vnofix';
const COLS = {
  vall: [['severity', 'Severity'], ['id', 'CVE / ID'], ['pkg', 'Package'], ['installed', 'Installed'], ['fixed', 'Fixed in'], ['cvss', 'CVSS'], ['target', 'Target']],
  vfix: [['severity', 'Severity'], ['id', 'CVE / ID'], ['pkg', 'Package'], ['installed', 'Installed'], ['fixed', 'Upgrade to'], ['cvss', 'CVSS'], ['target', 'Target']],
  vnofix: [['severity', 'Severity'], ['id', 'CVE / ID'], ['pkg', 'Package'], ['installed', 'Installed'], ['cvss', 'CVSS'], ['target', 'Target']],
  secrets: [['severity', 'Severity'], ['id', 'Rule'], ['title', 'Title'], ['target', 'File'], ['line', 'Line']],
  misconfigs: [['severity', 'Severity'], ['id', 'ID'], ['title', 'Title'], ['target', 'File'], ['message', 'Message']],
  licenses: [['severity', 'Severity'], ['pkg', 'Package'], ['name', 'License'], ['category', 'Category'], ['target', 'Target']],
};
const WEBCOLS = [['severity', 'Severity'], ['title', 'Finding'], ['message', 'Evidence'], ['ruleId', 'CWE · OWASP'], ['target', 'URL']];
async function viewReport(id) {
  const my = routeSeq;
  setNav('history');
  let s;
  try { s = await api('/scans/' + id); if (my !== routeSeq) return; } catch (e) {
    if (my !== routeSeq) return; $('#view').innerHTML = `<div class="empty">Scan not found. <a href="#/history">Back to history</a></div>`; return; }
  setCrumb(`Scan history › <b>${esc(s.target)}</b>`);
  const f = s.findings;
  const D = { vall: f.vulns, vfix: f.vulns.filter((v) => v.fixed), vnofix: f.vulns.filter((v) => !v.fixed), secrets: f.secrets, misconfigs: f.misconfigs, licenses: f.licenses };
  const isWeb = s.module === 'webapp';
  const tabs = isWeb ? [['misconfigs', 'Web findings']] : TABS;
  const st = { tab: isWeb ? 'misconfigs' : TABS.map((t) => t[0]).find((k) => D[k].length) || 'vall', sev: new Set(SEVS), q: '', sort: { k: 'severity', dir: 1 }, limit: 100 };
  const allCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  ['vulns', 'secrets', 'misconfigs', 'licenses'].forEach((k) => SEVS.forEach((v) => (allCounts[v] += s.summary[k][v] || 0)));
  const m = s.meta || {};
  let h = `<div class="row" style="margin-bottom:6px"><div style="min-width:0"><h1 class="wrap">${esc(s.target)} ${s.engine === 'demo' ? '<span class="tag">demo data</span>' : ''}</h1>
    <p class="sub" style="margin:0">${esc(s.module.toUpperCase())} scan · ${new Date(s.createdAt).toLocaleString()} · ${(s.durationMs / 1000).toFixed(1)}s · engine ${esc(s.engine)}</p></div><div class="sp"></div>
    <button class="btn pri" id="pdf">⬇ Download PDF report</button><button class="btn" id="json">JSON</button>${s.sbom ? '' : '<button class="btn" id="cmp">⇄ Compare</button>'}${s.sbom ? `<a class="btn" href="/api/sbom/${s.id}">⬇ SBOM</a>` : ''}<button class="btn danger" id="del">Delete</button></div>`;
  if (s.sbom) {
    h += `<div class="grid g3" style="margin:20px 0"><div class="card kpi" style="--c:var(--a3)"><div class="l">Components</div><div class="n">${fmt(s.sbom.components)}</div></div><div class="card kpi"><div class="l">Format</div><div class="n" style="font-size:20px">${esc(s.sbom.format)}</div></div></div>
      <div class="card"><h2>Software Bill of Materials</h2><p class="muted">The SBOM was generated and stored locally. Use the SBOM button above to download the JSON.</p></div>`;
    $('#view').innerHTML = h; bindHeader(s); return;
  }
  h += `<div class="grid g5" style="margin:20px 0 16px">${SEVS.map((v) => `<div class="card kpi" style="--c:var(--${v})"><div class="l">${v}</div><div class="n">${fmt(allCounts[v])}</div></div>`).join('')}</div>`;
  const sumy = window.TrivySummary.summarize(s);
  const al = s.alerts && s.alerts.results ? `<div class="muted small" style="margin-top:12px">Alerts: ${s.alerts.results.map((r) => `${esc(r.channel)} ${r.ok ? '<span class="down">✓ sent</span>' : `<span class="err" title="${esc(r.error)}">✕ failed</span>`}`).join(' · ')}</div>` : '';
  h += `<div class="card summary risk-${sumy.risk.toLowerCase()}" style="margin-bottom:16px"><div class="row" style="align-items:flex-start"><div style="min-width:0;flex:1"><h2 style="margin-bottom:6px">Summary</h2><div class="headline">${esc(sumy.headline)}</div></div><span class="riskpill">Overall risk: <b>${esc(sumy.risk)}</b></span></div>
    <div class="grid g2" style="margin-top:14px"><div><div class="sh">Key findings</div><ul>${sumy.points.map((p) => `<li>${esc(p)}</li>`).join('') || '<li>No findings.</li>'}</ul></div>
    <div><div class="sh">Recommended actions</div><ol>${sumy.actions.map((a) => `<li>${esc(a)}</li>`).join('')}</ol></div></div>${al}</div>`;
  const fixable = f.vulns.filter((v) => v.fixed).length;
  h += `<div class="grid g3" style="margin-bottom:16px">
    <div class="card"><h2>Severity breakdown</h2>${donut(allCounts)}</div>
    <div class="card"><h2>Findings by type</h2>${hbars([['vulns', 'Vulnerabilities'], ['secrets', 'Secrets'], ['misconfigs', 'Misconfigurations'], ['licenses', 'Licenses']].map(([k, l]) => ({ name: l, value: f[k].length, stack: s.summary[k] })))}<div class="muted small" style="margin-top:10px">${fmt(fixable)} of ${fmt(f.vulns.length)} vulnerabilities have a fix available.</div></div>
    <div class="card"><h2>Most affected packages</h2>${hbars(topPackages(f.vulns))}</div></div>`;
  h += `<div class="card" style="margin-bottom:16px"><h2>Scan details</h2><dl class="kv"><dt>Artifact</dt><dd>${esc(m.artifact || s.target)}</dd>${m.os ? `<dt>OS</dt><dd>${esc(m.os)}</dd>` : ''}<dt>Scanners</dt><dd>${esc((s.scanners || []).join(', ') || '—')}</dd><dt>Severities</dt><dd>${esc((s.severities || []).join(', '))}</dd>${m.packages ? `${s.module === 'webapp' ? `<dt>Final URL</dt><dd>${esc(m.finalUrl || s.target)}</dd><dt>TLS</dt><dd>${esc(m.tlsProtocol || '-')}${m.certExpires ? ' · certificate valid until ' + esc(m.certExpires) : ''}</dd><dt>Requests sent</dt><dd>${fmt(m.requests || 0)}</dd>` : `<dt>Packages</dt><dd>${fmt(m.packages)}</dd>`}` : ''}${m.imageId ? `<dt>Image ID</dt><dd class="mono">${esc(m.imageId)}</dd>` : ''}</dl></div>`;
  h += `<div class="card pad0"><div class="tabs" id="tabs">${tabs.map(([k, l]) => `<div class="tab" role="tab" tabindex="0" data-k="${k}">${l}<em>${fmt(D[k].length)}</em></div>`).join('')}</div>
    <div class="row" style="padding:14px 16px"><input type="text" id="q" placeholder="Search ID, package, file, text…" style="max-width:320px"><div class="chips" id="fsev">${SEVS.map((v) => `<span class="chip on" data-s="${v}" style="--c:var(--${v})"><i></i>${v}</span>`).join('')}</div>
    <div class="sp"></div><button class="btn sm" id="csv">Export CSV</button></div>
    <div class="tw" id="tbl"></div></div>`;
  $('#view').innerHTML = h;
  bindHeader(s);

  const rowText = (r) => Object.values(r).join(' ').toLowerCase();
  const render = () => {
    $$('#tabs .tab').forEach((t) => t.classList.toggle('on', t.dataset.k === st.tab));
    let rows = D[st.tab].filter((r) => st.sev.has(r.severity) && (!st.q || rowText(r).includes(st.q)));
    const { k, dir } = st.sort;
    rows = rows.slice().sort((a, b) => {
      let c;
      if (k === 'severity') c = RANK[a.severity] - RANK[b.severity];
      else if (k === 'cvss' || k === 'line') c = (a[k] || 0) - (b[k] || 0);
      else c = String(a[k] || '').localeCompare(String(b[k] || ''), undefined, { numeric: true });
      return c * dir || RANK[a.severity] - RANK[b.severity];
    });
    st.rows = rows;
    if (!rows.length) { $('#tbl').innerHTML = `<div class="empty">${D[st.tab].length ? 'No rows match the filters.' : st.tab === 'vall' ? 'No vulnerabilities found.' : st.tab === 'vfix' ? 'Nothing here: no vulnerability has a fix available.' : st.tab === 'vnofix' ? 'Nothing here: every vulnerability has a fix available.' : 'No findings of this type (or this scanner was not enabled).'}</div>`; return; }
    const cols = isWeb ? WEBCOLS : COLS[st.tab];
    const shown = rows.slice(0, st.limit);
    $('#tbl').innerHTML = `<table><thead><tr>${cols.map(([c, l]) => `<th class="s" data-k="${c}">${l}${st.sort.k === c ? (st.sort.dir > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('')}</tr></thead><tbody>${shown.map((r, i) => `<tr class="r" data-i="${i}">${cols.map(([c]) => `<td class="wrap ${['id', 'installed', 'fixed', 'pkg'].includes(c) ? 'mono' : ''}">${cell(r, c, st.tab)}</td>`).join('')}</tr>`).join('')}</tbody></table>${rows.length > shown.length ? `<div style="padding:14px;text-align:center"><button class="btn sm" id="more">Show more (${fmt(rows.length - shown.length)} remaining)</button></div>` : ''}`;
    $$('#tbl th.s').forEach((th) => (th.onclick = () => { st.sort = { k: th.dataset.k, dir: st.sort.k === th.dataset.k ? -st.sort.dir : 1 }; render(); }));
    $$('#tbl tr.r').forEach((tr) => (tr.onclick = () => {
      const nx = tr.nextElementSibling;
      if (nx && nx.classList.contains('det')) { nx.remove(); return; }
      const d = document.createElement('tr'); d.className = 'det';
      d.innerHTML = `<td colspan="${cols.length}">${detail(shown[+tr.dataset.i], st.tab)}</td>`;
      tr.after(d);
    }));
    const more = $('#more'); if (more) more.onclick = () => { st.limit += 200; render(); };
  };
  $$('#tabs .tab').forEach((t) => (t.onclick = () => { st.tab = t.dataset.k; st.limit = 100; st.sort = { k: 'severity', dir: 1 }; render(); }));
  $$('#fsev .chip').forEach((c) => (c.onclick = () => { c.classList.toggle('on'); c.classList.contains('on') ? st.sev.add(c.dataset.s) : st.sev.delete(c.dataset.s); render(); }));
  $('#q').oninput = (e) => { st.q = e.target.value.toLowerCase(); render(); };
  $('#csv').onclick = () => {
    const cols = isWeb ? WEBCOLS : COLS[st.tab];
    const q = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    download(`vulnora-${st.tab}-${s.id}.csv`, [cols.map((c) => q(c[1])).join(',')].concat(st.rows.map((r) => cols.map(([c]) => q(r[c])).join(','))).join('\n'), 'text/csv');
  };
  render();
}
function cell(r, c, tab) {
  if (c === 'severity') return sevTag(r.severity);
  if (c === 'id' && isV(tab) && safeUrl(r.url)) return `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${esc(r.id)}</a>`;
  if (c === 'fixed' && !r.fixed) return '<span class="muted">—</span>';
  if (c === 'cvss') return r.cvss ? r.cvss.toFixed(1) : '<span class="muted">—</span>';
  return esc(r[c]);
}
function detail(r, tab) {
  const link = (u, t) => (safeUrl(u) ? ` <a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${t}</a>` : '');
  if (isV(tab)) return `<b>${esc(r.title || r.id)}</b><div style="margin-top:6px">${esc(r.description) || '<span class="muted">No description.</span>'}</div><div class="muted small" style="margin-top:6px">${esc(r.type)} · ${esc(r.cls)}${r.fixed ? ` · upgrade ${esc(r.pkg)} to <b>${esc(r.fixed)}</b>` : ' · no fix available yet'}${link(r.url, 'Advisory ↗')}</div>`;
  if (tab === 'secrets') return `<b>${esc(r.title)}</b> <span class="muted">(${esc(r.category)})</span><pre class="log" style="color:#f5c542">${esc(r.match)}</pre>`;
  if (tab === 'misconfigs' && r.type === 'web') return `<b>${esc(r.title)}</b> <span class="muted small">${esc(r.id)}</span><div style="margin-top:6px">${esc(r.description)}</div><div style="margin-top:6px"><b>Evidence:</b> <span class="mono">${esc(r.message)}</span></div><div style="margin-top:6px"><b>Fix:</b> ${esc(r.resolution)}</div><div class="muted small" style="margin-top:6px">${esc(r.ruleId)}${link(r.url, 'Reference ↗')}</div>`;
  if (tab === 'misconfigs') return `<b>${esc(r.title)}</b><div style="margin-top:6px">${esc(r.description)}</div><div style="margin-top:6px"><b>Fix:</b> ${esc(r.resolution) || '—'}</div><div class="muted small" style="margin-top:6px">${esc(r.type)} · ${esc(r.ruleId)}${link(r.url, 'Details ↗')}</div>`;
  return `<b>${esc(r.name)}</b> · ${esc(r.category)}${r.file ? ' · ' + esc(r.file) : ''}${link(r.link, 'License text ↗')}`;
}
function bindHeader(s) {
  $('#pdf').onclick = async () => {
    const b = $('#pdf'); b.disabled = true; b.textContent = 'Building PDF…';
    try { await window.buildPdfReport(s); toast('PDF downloaded'); }
    catch (e) { console.error(e); toast('PDF failed: ' + e.message); }
    b.disabled = false; b.textContent = '⬇ Download PDF report';
  };
  $('#json').onclick = () => download(`vulnora-${s.id}.json`, JSON.stringify(s, null, 2));
  if ($('#cmp')) $('#cmp').onclick = () => (location.hash = '#/compare/-/' + s.id);
  $('#del').onclick = async () => { if (confirm('Delete this scan?')) { await api('/scans/' + s.id, { method: 'DELETE' }); location.hash = '#/history'; } };
}

/* ---------- history ---------- */
async function viewHistory() {
  setNav('history'); setCrumb('<b>Scan history</b>');
  const my = routeSeq;
  const scans = await api('/scans');
  if (my !== routeSeq) return;
  $('#view').innerHTML = `<h1>Scan history</h1><p class="sub">Every scan is stored locally in the <span class="mono">data</span> folder next to this tool.</p><div class="card pad0">${scanTable(scans)}</div>`;
  bindScanTable();
}

/* ---------- tools & features ---------- */
const FEATURES = [
  ['Vulnerability scanning', 'ok', 'Matches OS packages (Debian, Ubuntu, Alpine, RHEL…) and language dependencies (npm, pip, Maven, Gradle, Go, Cargo, NuGet, Composer, Ruby…) against CVE databases.'],
  ['Misconfiguration detection', 'ok', 'Built-in policies for Dockerfile, Kubernetes, Helm, Terraform, CloudFormation, Azure ARM and more, with remediation hints.'],
  ['Secret detection', 'ok', 'Finds cloud keys, tokens, passwords and private keys in files and image layers.'],
  ['License scanning', 'ok', 'Classifies package licenses (permissive → forbidden) to support compliance reviews.'],
  ['SBOM generation', 'ok', 'Exports CycloneDX or SPDX inventories for supply-chain transparency.'],
  ['Multiple targets', 'ok', 'Container images (remote or local), folders, Git repositories.'],
  ['Severity & fix filters', 'ok', 'Limit results to chosen severities and hide issues that have no fix yet.'],
  ['Reports', 'ok', 'Interactive tables, CSV and JSON export, and a PDF report with your own company name and logo (Report branding).'],
  ['Alerts', 'ok', 'Email, Slack or Microsoft Teams notification when a scan finds critical (or high) issues, optionally only new ones.'],
  ['Scan comparison', 'ok', 'Diff two scans: new, fixed and unchanged findings with severity deltas, CSV and PDF export.'],
  ['Kubernetes cluster scan', 'cli', 'trivy k8s scans a live cluster. Run it from the CLI with kubeconfig access.'],
  ['VM images & SBOM-file scanning', 'cli', 'trivy vm and trivy sbom are available in the Trivy CLI.'],
  ['VEX & ignore policies', 'cli', '.trivyignore and VEX documents suppress accepted risks in CI.'],
  ['CI/CD integration', 'cli', 'Use --exit-code 1 and SARIF / JUnit formats in your pipelines.'],
];
async function viewTools() {
  setNav('tools'); setCrumb('<b>Tools &amp; features</b>');
  const my = routeSeq;
  await refreshEngine(true);
  if (my !== routeSeq) return;
  const e = engine;
  const yn = (b) => (b ? '<span class="tag ok">yes</span>' : '<span class="tag cli">no</span>');
  $('#view').innerHTML = `<h1>Tools &amp; features</h1><p class="sub">Engine health, database maintenance and what Vulnora (with the Trivy engine) can do.</p>
  <div class="grid g3" style="margin-bottom:16px">
    <div class="card"><h2>Docker</h2><dl class="kv"><dt>Available</dt><dd>${yn(e.docker.available)}</dd><dt>Version</dt><dd>${esc(e.docker.version || '—')}</dd><dt>Trivy image</dt><dd>${yn(e.docker.trivyImageReady)} <span class="muted small">${esc(e.docker.image)}</span></dd></dl></div>
    <div class="card"><h2>Native Trivy</h2><dl class="kv"><dt>Installed</dt><dd>${yn(e.native.available)}</dd><dt>Version</dt><dd>${esc(e.native.version || '—')}</dd></dl></div>
    <div class="card"><h2>Active engine</h2><div class="n" style="font-size:26px;font-weight:700">${esc(e.engine)}</div><div class="muted small">Docker is preferred when both exist. Set TRIVY_ENGINE=native to override.</div></div></div>
  <div class="card" style="margin-bottom:22px"><h2>Maintenance</h2><div class="row"><button class="btn" data-t="pull">Pull latest Trivy image</button><button class="btn" data-t="dbupdate">Update vulnerability DB</button><button class="btn" data-t="version">Show version &amp; DB info</button></div><div id="run" style="margin-top:12px"></div></div>
  <h2>What Vulnora can do</h2><div class="grid g3">${FEATURES.map(([n, t, d]) => `<div class="card"><b>${n}</b><span class="tag ${t}">${t === 'ok' ? 'in dashboard' : 'CLI only'}</span><div class="muted" style="margin-top:6px;font-size:13px">${d}</div></div>`).join('')}</div>`;
  $$('[data-t]').forEach((b) => (b.onclick = async () => {
    try { const j = await api('/tools/' + b.dataset.t, { method: 'POST' }); watchJob(j.id, $('#run')); } catch (er) { toast(er.message); }
  }));
}


/* ---------- compare two scans ---------- */
const TYPE_LABEL = { vulns: 'Vulnerability', secrets: 'Secret', misconfigs: 'Misconfig', licenses: 'License' };
// how a finding is identified across two scans (versions/lines may change, the issue is the same)
const KEYS = {
  vulns: (v) => `${v.id}|${v.pkg}`,
  secrets: (x) => `${x.id}|${x.target}|${x.match}`,
  misconfigs: (m) => `${m.id}|${m.target}`,
  licenses: (l) => `${l.pkg}|${l.name}`,
};
const SCANNER_OF = { vulns: 'vuln', secrets: 'secret', misconfigs: 'misconfig', licenses: 'license' };
function toRow(type, x, status, other) {
  const r = { status, type: TYPE_LABEL[type], tkey: type, severity: x.severity, target: x.target, url: x.url || x.link || '', raw: x };
  if (type === 'vulns') {
    r.id = x.id; r.item = x.pkg;
    r.info = other && other.installed !== x.installed ? `${other.installed} → ${x.installed}` : x.installed + (x.fixed ? ` (fix: ${x.fixed})` : '');
  } else if (type === 'secrets') { r.id = x.id; r.item = x.title; r.info = x.line ? 'line ' + x.line : ''; }
  else if (type === 'misconfigs') { r.id = x.id; r.item = x.title; r.info = x.resolution || x.message || ''; }
  else { r.id = x.name; r.item = x.pkg; r.info = x.category; }
  if (other && other.severity !== x.severity) r.info = (r.info ? r.info + ' · ' : '') + `severity ${other.severity} → ${x.severity}`;
  return r;
}
function compareScans(A, B) {
  const rows = [];
  const byType = {};
  Object.keys(KEYS).forEach((t) => {
    const ma = new Map(), mb = new Map();
    (A.findings[t] || []).forEach((x) => ma.set(KEYS[t](x), x));
    (B.findings[t] || []).forEach((x) => mb.set(KEYS[t](x), x));
    const c = { new: 0, fixed: 0, same: 0 };
    mb.forEach((x, k) => { if (ma.has(k)) { rows.push(toRow(t, x, 'same', ma.get(k))); c.same++; } else { rows.push(toRow(t, x, 'new')); c.new++; } });
    ma.forEach((x, k) => { if (!mb.has(k)) { rows.push(toRow(t, x, 'fixed')); c.fixed++; } });
    byType[t] = c;
  });
  const sevOf = (S) => { const o = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 }; Object.keys(KEYS).forEach((t) => SEVS.forEach((v) => (o[v] += S.summary[t][v] || 0))); return o; };
  return { a: A, b: B, rows, byType, sevA: sevOf(A), sevB: sevOf(B) };
}
const scanLabel = (s) => `${s.target} · ${s.module} · ${new Date(s.createdAt).toLocaleString()}`;

async function viewCompare(aId, bId) {
  const my = routeSeq;
  setNav('compare'); setCrumb('Workspace › <b>Compare scans</b>');
  const scans = (await api('/scans')).filter((s) => !s.sbom && s.module !== 'sbom');
  if (my !== routeSeq) return;
  let h = `<h1>Compare scans</h1><p class="sub">Pick two scans of the same target to see which findings are new, which were fixed and which remain. Use it to re-test after a fix or an image upgrade.</p>`;
  if (scans.length < 2) {
    h += `<div class="card"><div class="empty">${mark()}<div>You need at least two scans to compare. Scan the same target twice (e.g. before and after an upgrade), or try it with demo data.</div>
      <div class="row" style="justify-content:center;margin-top:16px"><button class="btn pri" id="demopair">Load demo before/after scans</button></div></div></div>`;
    $('#view').innerHTML = h;
    $('#demopair').onclick = async () => { const r = await api('/demo', { method: 'POST', body: JSON.stringify({ pair: true }) }); location.hash = `#/compare/${r.a}/${r.b}`; };
    return;
  }
  const byId = new Map(scans.map((s) => [s.id, s]));
  let b = byId.get(bId) || scans[0];
  let a = byId.get(aId);
  if (!a || a.id === b.id) {
    const older = scans.filter((s) => s.id !== b.id && new Date(s.createdAt) <= new Date(b.createdAt));
    a = older.find((s) => s.target === b.target) || older[0] || scans.find((s) => s.id !== b.id);
  }
  const opts = (sel) => scans.map((s) => `<option value="${s.id}" ${s.id === sel ? 'selected' : ''}>${esc(scanLabel(s))}${s.engine === 'demo' ? ' (demo)' : ''}</option>`).join('');
  h += `<div class="card" style="margin-bottom:16px"><div class="cmp-pick">
      <div><label class="f">Baseline (before)</label><select id="ca">${opts(a.id)}</select></div>
      <button class="btn" id="swap" title="Swap baseline and current">⇄</button>
      <div><label class="f">Current (after)</label><select id="cb">${opts(b.id)}</select></div></div>
      <div class="muted small" style="margin-top:10px">Tip: open any report and click <b>⇄ Compare</b> to compare it with the previous scan of the same target. <a href="#" id="demopair2">Load demo before/after scans</a></div></div><div id="cmpout"><div class="empty">Loading…</div></div>`;
  $('#view').innerHTML = h;
  const go = () => (location.hash = `#/compare/${$('#ca').value}/${$('#cb').value}`);
  $('#ca').onchange = go; $('#cb').onchange = go;
  $('#swap').onclick = () => (location.hash = `#/compare/${b.id}/${a.id}`);
  $('#demopair2').onclick = async (e) => { e.preventDefault(); const r = await api('/demo', { method: 'POST', body: JSON.stringify({ pair: true }) }); location.hash = `#/compare/${r.a}/${r.b}`; };
  if (a.id === b.id) { $('#cmpout').innerHTML = '<div class="banner">Pick two different scans.</div>'; return; }

  const [A, B] = await Promise.all([api('/scans/' + a.id), api('/scans/' + b.id)]);
  if (my !== routeSeq) return;
  const cmp = compareScans(A, B);
  const { rows } = cmp;
  const cnt = (st) => rows.filter((r) => r.status === st).length;
  const nNew = cnt('new'), nFix = cnt('fixed'), nSame = cnt('same');
  const net = total(cmp.sevB) - total(cmp.sevA);

  const warns = [];
  if (A.target !== B.target) warns.push(`These scans are of <b>different targets</b> (${esc(A.target)} vs ${esc(B.target)}). The comparison still works, but expect many differences.`);
  if (new Date(A.createdAt) > new Date(B.createdAt)) warns.push('The baseline is <b>newer</b> than the current scan, so "new" and "fixed" are reversed. Use ⇄ to swap them.');
  Object.keys(SCANNER_OF).forEach((t) => {
    const ia = (A.scanners || []).includes(SCANNER_OF[t]) || A.findings[t].length, ib = (B.scanners || []).includes(SCANNER_OF[t]) || B.findings[t].length;
    if (!!ia !== !!ib) warns.push(`${TYPE_LABEL[t]} scanning was only enabled in the <b>${ia ? 'baseline' : 'current'}</b> scan, so those ${ia ? '"fixed"' : '"new"'} ${TYPE_LABEL[t].toLowerCase()} findings may just be the scanner setting.`);
  });
  if ((A.severities || []).join() !== (B.severities || []).join()) warns.push('The two scans used <b>different severity filters</b>.');

  const verdict = nNew === 0 && nFix > 0 ? ['good', 'Improved', 'Issues were fixed and nothing new was introduced.']
    : nNew > 0 && nFix === 0 ? ['bad', 'Regressed', 'New issues appeared and nothing was fixed.']
      : nNew === 0 && nFix === 0 ? ['', 'No change', 'Both scans report the same findings.']
        : net < 0 ? ['good', 'Mostly improved', 'More issues were fixed than introduced.'] : ['bad', 'Needs attention', 'More issues were introduced than fixed.'];
  const newCrit = rows.filter((r) => r.status === 'new' && r.severity === 'CRITICAL').length;

  let o = warns.map((w) => `<div class="banner">${w}</div>`).join('');
  o += `<div class="card verdict ${verdict[0]}" style="margin-bottom:16px"><div class="row"><div><h2 style="margin:0">${verdict[1]}</h2><div class="muted">${verdict[2]}${newCrit ? ` <b class="err">${newCrit} new critical.</b>` : ''}</div></div><div class="sp"></div>
    <button class="btn pri" id="cpdf">⬇ Comparison PDF</button><button class="btn" id="ccsv">Export CSV</button></div></div>`;
  o += `<div class="grid g4" style="margin-bottom:16px">
    <div class="card kpi" style="--c:var(--CRITICAL)"><div class="l">New</div><div class="n">${fmt(nNew)}</div></div>
    <div class="card kpi" style="--c:var(--good)"><div class="l">Fixed</div><div class="n">${fmt(nFix)}</div></div>
    <div class="card kpi" style="--c:var(--UNKNOWN)"><div class="l">Unchanged</div><div class="n">${fmt(nSame)}</div></div>
    <div class="card kpi" style="--c:${net > 0 ? 'var(--HIGH)' : 'var(--LOW)'}"><div class="l">Net change</div><div class="n">${net > 0 ? '+' : ''}${fmt(net)}</div></div></div>`;
  const delta = (d) => (d > 0 ? `<span class="up">▲ ${d}</span>` : d < 0 ? `<span class="down">▼ ${-d}</span>` : '<span class="muted">–</span>');
  o += `<div class="grid g2" style="margin-bottom:16px">
    <div class="card pad0"><div style="padding:16px 16px 4px"><h2>By severity</h2></div><div class="tw"><table><thead><tr><th>Severity</th><th>Before</th><th>After</th><th>Change</th><th>New</th><th>Fixed</th></tr></thead><tbody>${SEVS.map((v) => `<tr><td>${sevTag(v)}</td><td>${fmt(cmp.sevA[v])}</td><td>${fmt(cmp.sevB[v])}</td><td>${delta(cmp.sevB[v] - cmp.sevA[v])}</td><td>${fmt(rows.filter((r) => r.status === 'new' && r.severity === v).length)}</td><td>${fmt(rows.filter((r) => r.status === 'fixed' && r.severity === v).length)}</td></tr>`).join('')}</tbody></table></div></div>
    <div class="card pad0"><div style="padding:16px 16px 4px"><h2>By type</h2></div><table><thead><tr><th>Type</th><th>New</th><th>Fixed</th><th>Unchanged</th></tr></thead><tbody>${Object.keys(KEYS).map((t) => `<tr><td>${TYPE_LABEL[t]}</td><td>${cmp.byType[t].new ? `<span class="up">${cmp.byType[t].new}</span>` : '<span class="muted">0</span>'}</td><td>${cmp.byType[t].fixed ? `<span class="down">${cmp.byType[t].fixed}</span>` : '<span class="muted">0</span>'}</td><td>${fmt(cmp.byType[t].same)}</td></tr>`).join('')}</tbody></table>
    <div class="muted small" style="padding:12px 16px">Before: <a href="#/report/${A.id}">${esc(A.target)}</a> · ${new Date(A.createdAt).toLocaleString()}<br>After: <a href="#/report/${B.id}">${esc(B.target)}</a> · ${new Date(B.createdAt).toLocaleString()}</div></div></div>`;
  const CT = [['new', 'New', nNew], ['fixed', 'Fixed', nFix], ['same', 'Unchanged', nSame]];
  o += `<div class="card pad0"><div class="tabs" id="ctabs">${CT.map(([k, l, n]) => `<div class="tab" role="tab" tabindex="0" data-k="${k}">${l}<em>${fmt(n)}</em></div>`).join('')}</div>
    <div class="row" style="padding:14px 16px"><input type="text" id="cq" placeholder="Search ID, package, file…" style="max-width:300px">
    <div class="chips" id="ctype">${Object.keys(KEYS).map((t) => `<span class="chip on" data-t="${t}">${TYPE_LABEL[t]}</span>`).join('')}</div>
    <div class="chips" id="csev">${SEVS.map((v) => `<span class="chip on" data-s="${v}" style="--c:var(--${v})"><i></i>${v}</span>`).join('')}</div></div>
    <div class="tw" id="ctbl"></div></div>`;
  $('#cmpout').innerHTML = o;

  const st = { tab: nNew ? 'new' : nFix ? 'fixed' : 'same', types: new Set(Object.keys(KEYS)), sev: new Set(SEVS), q: '', limit: 200 };
  const filtered = () => rows.filter((r) => r.status === st.tab && st.types.has(r.tkey) && st.sev.has(r.severity) && (!st.q || `${r.id} ${r.item} ${r.info} ${r.target}`.toLowerCase().includes(st.q)))
    .sort((x, y) => RANK[x.severity] - RANK[y.severity] || String(x.id).localeCompare(String(y.id)));
  const render = () => {
    $$('#ctabs .tab').forEach((t) => t.classList.toggle('on', t.dataset.k === st.tab));
    const list = filtered();
    if (!list.length) { $('#ctbl').innerHTML = `<div class="empty">${rows.some((r) => r.status === st.tab) ? 'No rows match the filters.' : st.tab === 'new' ? 'No new findings since the earlier scan.' : st.tab === 'fixed' ? 'Nothing was fixed between these scans.' : 'No findings are shared by both scans.'}</div>`; return; }
    const shown = list.slice(0, st.limit);
    const idCell = (r) => (safeUrl(r.url) ? `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.id)}</a>` : esc(r.id));
    $('#ctbl').innerHTML = `<table><thead><tr><th>Severity</th><th>Type</th><th>ID</th><th>Package / item</th><th>Details</th><th>Target</th></tr></thead><tbody>${shown.map((r) => `<tr class="st-${r.status}"><td>${sevTag(r.severity)}</td><td class="small">${r.type}</td><td class="mono wrap">${idCell(r)}</td><td class="mono wrap">${esc(r.item)}</td><td class="wrap small">${esc(r.info)}</td><td class="wrap small muted">${esc(r.target)}</td></tr>`).join('')}</tbody></table>${list.length > shown.length ? `<div style="padding:14px;text-align:center"><button class="btn sm" id="cmore">Show more (${fmt(list.length - shown.length)} remaining)</button></div>` : ''}`;
    const more = $('#cmore'); if (more) more.onclick = () => { st.limit += 300; render(); };
  };
  $$('#ctabs .tab').forEach((t) => (t.onclick = () => { st.tab = t.dataset.k; st.limit = 200; render(); }));
  $$('#ctype .chip').forEach((c) => (c.onclick = () => { c.classList.toggle('on'); c.classList.contains('on') ? st.types.add(c.dataset.t) : st.types.delete(c.dataset.t); render(); }));
  $$('#csev .chip').forEach((c) => (c.onclick = () => { c.classList.toggle('on'); c.classList.contains('on') ? st.sev.add(c.dataset.s) : st.sev.delete(c.dataset.s); render(); }));
  $('#cq').oninput = (e) => { st.q = e.target.value.toLowerCase(); render(); };
  $('#ccsv').onclick = () => {
    const q = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    const head = ['Status', 'Severity', 'Type', 'ID', 'Package / item', 'Details', 'Target'];
    const order = { new: 0, fixed: 1, same: 2 };
    const all = rows.slice().sort((x, y) => order[x.status] - order[y.status] || RANK[x.severity] - RANK[y.severity]);
    download(`vulnora-compare-${A.id}-vs-${B.id}.csv`, [head.map(q).join(',')].concat(all.map((r) => [r.status === 'same' ? 'unchanged' : r.status, r.severity, r.type, r.id, r.item, r.info, r.target].map(q).join(','))).join('\n'), 'text/csv');
  };
  $('#cpdf').onclick = async () => {
    const btn = $('#cpdf'); btn.disabled = true; btn.textContent = 'Building PDF…';
    try { await window.buildComparePdf(cmp); toast('PDF downloaded'); } catch (e) { console.error(e); toast('PDF failed: ' + e.message); }
    btn.disabled = false; btn.textContent = '⬇ Comparison PDF';
  };
  render();
}

/* ---------- report branding ---------- */
async function viewSettings() {
  const my = routeSeq;
  setNav('settings'); setCrumb('Workspace › <b>Report branding</b>');
  const cfg = await api('/settings');
  if (my !== routeSeq) return;
  const st = { ...cfg };
  $('#view').innerHTML = `<h1>Report branding</h1><p class="sub">Put your company name and logo on every PDF report. Saved locally in the <span class="mono">data</span> folder.</p>
  <div class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1.1fr)">
    <div class="card"><form id="bf">
      <label class="f">Company / organisation name</label><input type="text" id="b-company" maxlength="120" placeholder="e.g. Acme Technologies Pvt Ltd" value="${esc(st.company)}">
      <label class="f">Prepared by (optional)</label><input type="text" id="b-by" maxlength="120" placeholder="e.g. QA Team / your name" value="${esc(st.preparedBy)}">
      <label class="f">Report title</label><input type="text" id="b-title" maxlength="80" value="${esc(st.reportTitle)}">
      <label class="f">Footer text</label><input type="text" id="b-footer" maxlength="120" placeholder="Confidential security report" value="${esc(st.footer)}">
      <label class="f">Logo (PNG, JPG, SVG or WebP)</label>
      <div class="row"><label class="btn sm" for="b-logo" style="margin:0">Choose image…</label><input type="file" id="b-logo" accept="image/png,image/jpeg,image/svg+xml,image/webp" hidden>
        <button type="button" class="btn sm danger" id="b-rmlogo" ${st.logo ? '' : 'style="display:none"'}>Remove logo</button><span class="muted small" id="b-logoinfo">${st.logo ? 'Logo set' : 'No logo set. PDFs use the Vulnora logo.'}</span></div>
      <label class="f">Header colour</label>
      <div class="row"><input type="color" id="b-color" value="${esc(st.headerColor)}"><div class="chips" id="b-presets">${['#0e1126', '#1e3a8a', '#065f46', '#7f1d1d', '#312e81', '#ffffff'].map((c) => `<span class="swatch" data-c="${c}" style="background:${c}" title="${c}"></span>`).join('')}</div></div>
      <label class="chk" style="margin-top:14px"><input type="checkbox" id="b-trivy" ${st.showTrivyLogo !== false ? 'checked' : ''}>Show the Vulnora logo (small mark next to your logo)</label>
      <div class="row" style="margin-top:20px"><button class="btn pri" id="b-save">Save branding</button><button type="button" class="btn" id="b-test">Preview PDF with latest scan</button><button type="button" class="btn sm" id="b-reset">Reset to default</button></div>
    </form></div>
    <div class="card"><h2>Cover preview</h2><div class="muted small" style="margin:-6px 0 12px">How the top of the PDF will look (A4, scaled down).</div><div id="b-prev"></div></div>
  </div>`;
  const read = () => {
    st.company = $('#b-company').value; st.preparedBy = $('#b-by').value; st.reportTitle = $('#b-title').value || 'Security Scan Report';
    st.footer = $('#b-footer').value; st.headerColor = $('#b-color').value; st.showTrivyLogo = $('#b-trivy').checked;
  };
  const light = (hex) => { const n = parseInt(hex.slice(1), 16); return 0.299 * (n >> 16 & 255) + 0.587 * (n >> 8 & 255) + 0.114 * (n & 255) > 160; };
  const preview = () => {
    read();
    const lt = light(st.headerColor);
    const logo = st.logo ? `<img src="${esc(st.logo)}" alt="" class="pv-logo">` : st.showTrivyLogo ? `<img src="${lt ? 'logo-dark.png' : 'logo.png'}" alt="" style="height:48px">` : '';
    $('#b-prev').innerHTML = `<div class="pv"><div class="pv-head" style="background:${esc(st.headerColor)};color:${lt ? '#1e223c' : '#fff'}">
      ${st.logo && st.showTrivyLogo ? `<img src="${lt ? 'logo-dark.png' : 'logo.png'}" alt="" class="pv-mark">` : ''}
      <div class="row" style="gap:12px;flex-wrap:nowrap">${logo}<div style="min-width:0"><div class="pv-title">${esc(st.reportTitle)}</div>${st.company ? `<div class="pv-company">${esc(st.company)}</div><div class="pv-sub" style="color:${lt ? '#5a607d' : '#bec4e1'}">Generated ${new Date().toLocaleString()}</div>` : `<div class="pv-sub" style="color:${lt ? '#5a607d' : '#bec4e1'}">Generated by Vulnora | ${new Date().toLocaleString()}</div>`}</div></div>
      <div class="pv-target">nginx:1.27</div><div class="pv-sub" style="color:${lt ? '#5a607d' : '#bec4e1'}">IMAGE scan | ${new Date().toLocaleDateString()}${st.preparedBy ? ' | Prepared by ' + esc(st.preparedBy) : ''}</div></div>
      <div class="pv-stripe"></div><div class="pv-body"><b>Executive summary</b><div class="pv-lines"><i></i><i></i><i style="width:60%"></i></div></div>
      <div class="pv-foot"><span>${st.company ? `<b>${esc(st.company)}</b>${st.footer ? ' - ' + esc(st.footer) : ''}` : esc(st.footer || 'Vulnora')}</span><span>Page 1 of 4</span></div></div>`;
  };
  $$('#bf input[type=text], #b-color, #b-trivy').forEach((i) => (i.oninput = preview));
  $('#b-trivy').onchange = preview;
  $$('#b-presets .swatch').forEach((sw) => (sw.onclick = () => { $('#b-color').value = sw.dataset.c; preview(); }));
  $('#b-logo').onchange = async (e) => {
    const file = e.target.files[0]; e.target.value = '';
    if (!file) return;
    if (file.size > 5e6) return toast('Image is too large (max 5 MB)');
    try {
      st.logo = await logoToPng(file);
      $('#b-logoinfo').textContent = `${file.name} (saved as PNG)`; $('#b-rmlogo').style.display = '';
      preview();
    } catch (er) { toast('Could not read that image'); }
  };
  $('#b-rmlogo').onclick = () => { st.logo = null; $('#b-rmlogo').style.display = 'none'; $('#b-logoinfo').textContent = 'No logo set. PDFs use the Vulnora logo.'; preview(); };
  const save = async () => { read(); return api('/settings', { method: 'PUT', body: JSON.stringify(st) }); };
  $('#bf').onsubmit = async (ev) => {
    ev.preventDefault();
    try { await save(); toast('Branding saved. New PDFs will use it.'); } catch (er) { toast(er.message); }
  };
  $('#b-reset').onclick = async () => {
    if (!confirm('Reset branding to the default Vulnora look?')) return;
    await api('/settings', { method: 'PUT', body: JSON.stringify({ company: '', preparedBy: '', reportTitle: 'Security Scan Report', footer: 'Confidential security report', headerColor: '#0e1126', logo: null, showTrivyLogo: true }) });
    toast('Branding reset'); viewSettings();
  };
  $('#b-test').onclick = async () => {
    read();
    const list = (await api('/scans')).filter((x) => !x.sbom);
    if (!list.length) return toast('Run a scan (or load demo data on the Overview page) first');
    const btn = $('#b-test'); btn.disabled = true;
    try { await window.buildPdfReport(await api('/scans/' + list[0].id), { ...st }); toast('Preview downloaded. Click Save to keep these settings.'); }
    catch (er) { toast('PDF failed: ' + er.message); }
    btn.disabled = false;
  };
  preview();
}
// Normalise any uploaded image to a PNG no bigger than 600px (keeps settings small, works in jsPDF)
function logoToPng(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      let w = img.naturalWidth || 400, h = img.naturalHeight || 160;
      const sc = Math.min(1, 600 / Math.max(w, h)); w = Math.round(w * sc); h = Math.round(h * sc);
      const c = document.createElement('canvas'); c.width = w; c.height = h;
      c.getContext('2d').drawImage(img, 0, 0, w, h);
      URL.revokeObjectURL(url);
      resolve(c.toDataURL('image/png'));
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('bad image')); };
    img.src = url;
  });
}


/* ---------- alerts ---------- */
async function viewAlerts() {
  const my = routeSeq;
  setNav('alerts'); setCrumb('Workspace › <b>Alerts</b>');
  const c = await api('/alerts');
  if (my !== routeSeq) return;
  const ck = (v) => (v ? 'checked' : '');
  const chan = (k, ic, name, inner) => `<div class="card chan" id="ch-${k}"><div class="row"><span class="chan-ic">${ic}</span><h2 style="margin:0">${name}</h2><div class="sp"></div>
    <label class="switch"><input type="checkbox" id="${k}-on" ${ck(c[k].enabled)}><span></span></label></div><div class="chan-body">${inner}
    <div class="row" style="margin-top:14px"><button type="button" class="btn sm" data-test="${k}">Send test ${name === 'Email' ? 'email' : 'message'}</button><span class="small" id="${k}-res"></span></div></div></div>`;
  const hist = (c.history || []).map((x) => `<tr><td class="small muted">${new Date(x.at).toLocaleString()}</td><td class="wrap">${x.scanId ? `<a href="#/report/${esc(x.scanId)}">${esc(x.target)}</a>` : esc(x.target)}</td><td>${x.results.map((r) => `${esc(r.channel)} ${r.ok ? '<span class="down">✓</span>' : `<span class="err" title="${esc(r.error)}">✕ ${esc(r.error)}</span>`}`).join('<br>')}</td></tr>`).join('');
  $('#view').innerHTML = `<h1>Alerts</h1><p class="sub">Get notified by email, Slack or Microsoft Teams when a scan finds critical issues. Settings are stored locally in <span class="mono">data/alerts.json</span>.</p>
  <form id="af">
  <div class="card" style="margin-bottom:16px"><div class="row"><div><h2 style="margin:0">Alerts are <span id="a-state">${c.enabled ? 'ON' : 'OFF'}</span></h2><div class="muted small">Turn on, choose when to alert, then enable at least one channel below.</div></div><div class="sp"></div><label class="switch big"><input type="checkbox" id="a-on" ${ck(c.enabled)}><span></span></label></div>
    <div class="grid g2" style="margin-top:8px">
      <div><label class="f">Alert when a scan finds</label><select id="a-sev"><option value="CRITICAL" ${c.minSeverity === 'CRITICAL' ? 'selected' : ''}>Critical issues</option><option value="HIGH" ${c.minSeverity === 'HIGH' ? 'selected' : ''}>Critical or high issues</option></select>
        <label class="chk" style="margin-top:12px"><input type="checkbox" id="a-sec" ${ck(c.includeSecrets)}>Also count exposed secrets</label>
        <label class="chk"><input type="checkbox" id="a-mc" ${ck(c.includeMisconfigs)}>Also count misconfigurations</label>
        <label class="chk"><input type="checkbox" id="a-new" ${ck(c.onlyNew)}><span>Only alert on <b>new</b> findings (not already in the previous scan of the same target)</span></label></div>
      <div><div class="pdfnote"><b>Email alerts include the full PDF report as an attachment</b>, so anyone can read it without Vulnora installed. Slack and Teams messages point to that email.</div>
        <label class="f">Optional: shared dashboard address</label><input type="text" id="a-url" placeholder="e.g. http://192.168.1.20:8787 (leave empty)" value="${esc(c.dashboardUrl)}">
        <div class="muted small" style="margin-top:6px">Only fill this in if teammates can reach this computer over the network. It adds an "Open in Vulnora" link. 127.0.0.1 and localhost links are never sent.</div></div></div></div>
  <div class="grid g3">
  ${chan('email', '✉', 'Email', `
    <div class="row" style="gap:6px;margin-top:8px"><span class="muted small">Preset:</span><button type="button" class="btn sm" data-preset="gmail">Gmail</button><button type="button" class="btn sm" data-preset="outlook">Outlook / M365</button></div>
    <div class="grid" style="grid-template-columns:minmax(0,1fr) 90px;gap:10px"><div><label class="f">SMTP server</label><input type="text" id="e-host" placeholder="smtp.gmail.com" value="${esc(c.email.host)}"></div><div><label class="f">Port</label><input type="text" id="e-port" value="${esc(c.email.port)}"></div></div>
    <label class="f">Security</label><select id="e-sec"><option value="ssl" ${c.email.security === 'ssl' ? 'selected' : ''}>SSL/TLS (port 465)</option><option value="starttls" ${c.email.security === 'starttls' ? 'selected' : ''}>STARTTLS (port 587)</option><option value="none" ${c.email.security === 'none' ? 'selected' : ''}>None (local relay only)</option></select>
    <label class="f">Username</label><input type="text" id="e-user" autocomplete="off" placeholder="you@gmail.com" value="${esc(c.email.user)}">
    <label class="f">Password / app password</label><input type="password" id="e-pass" autocomplete="new-password" placeholder="${c.email.hasPass ? '•••••••• saved (leave blank to keep)' : 'App password'}">
    <label class="f">From</label><input type="text" id="e-from" placeholder="you@gmail.com" value="${esc(c.email.from)}">
    <label class="f">Send to (comma separated)</label><input type="text" id="e-to" placeholder="team@company.com, lead@company.com" value="${esc(c.email.to)}">
    <div class="muted small" style="margin-top:8px">Gmail &amp; Outlook need an <b>app password</b> (Google Account → Security → App passwords), not your normal password.</div>`)}
  ${chan('slack', '#', 'Slack', `<label class="f">Incoming webhook URL</label><input type="text" id="s-hook" autocomplete="off" placeholder="https://hooks.slack.com/services/…" value="${esc(c.slack.webhook)}">
    <div class="muted small" style="margin-top:8px">Create one at <b>api.slack.com/apps</b> → your app → <b>Incoming Webhooks</b> → Add New Webhook to Workspace → pick a channel → copy the URL.</div>`)}
  ${chan('teams', 'T', 'Microsoft Teams', `<label class="f">Workflow webhook URL</label><input type="text" id="t-hook" autocomplete="off" placeholder="https://….logic.azure.com/workflows/…  or  …webhook.office.com/…" value="${esc(c.teams.webhook)}">
    <div class="muted small" style="margin-top:8px">In Teams: channel <b>⋯</b> → <b>Workflows</b> → "Post to a channel when a webhook request is received" → copy the URL.</div>`)}
  </div>
  <div class="row" style="margin:18px 0 26px"><button class="btn pri" id="a-save">Save alert settings</button><span class="muted small">Demo-data scans never send alerts. Use "Send test" to check each channel.</span></div>
  </form>
  <h2>Recent alerts</h2><div class="card pad0">${hist ? `<div class="tw"><table><thead><tr><th>When</th><th>Scan</th><th>Delivery</th></tr></thead><tbody>${hist}</tbody></table></div>` : '<div class="empty">No alerts sent since the dashboard started.</div>'}</div>`;

  const sync = () => {
    $('#a-state').textContent = $('#a-on').checked ? 'ON' : 'OFF';
    ['email', 'slack', 'teams'].forEach((k) => $('#ch-' + k).classList.toggle('off', !$(`#${k}-on`).checked));
  };
  $$('#af input[type=checkbox]').forEach((i) => (i.onchange = sync)); sync();
  $$('[data-preset]').forEach((b) => (b.onclick = () => {
    const g = b.dataset.preset === 'gmail';
    $('#e-host').value = g ? 'smtp.gmail.com' : 'smtp.office365.com'; $('#e-port').value = g ? 465 : 587; $('#e-sec').value = g ? 'ssl' : 'starttls';
  }));
  $('#e-sec').onchange = () => { const p = $('#e-port'); if (['465', '587', '25', ''].includes(p.value)) p.value = { ssl: 465, starttls: 587, none: 25 }[$('#e-sec').value]; };
  const form = () => ({
    enabled: $('#a-on').checked, minSeverity: $('#a-sev').value, includeSecrets: $('#a-sec').checked, includeMisconfigs: $('#a-mc').checked, onlyNew: $('#a-new').checked, dashboardUrl: $('#a-url').value,
    email: { enabled: $('#email-on').checked, host: $('#e-host').value, port: $('#e-port').value, security: $('#e-sec').value, user: $('#e-user').value, pass: $('#e-pass').value, from: $('#e-from').value || $('#e-user').value, to: $('#e-to').value },
    slack: { enabled: $('#slack-on').checked, webhook: $('#s-hook').value }, teams: { enabled: $('#teams-on').checked, webhook: $('#t-hook').value },
  });
  $('#af').onsubmit = async (ev) => {
    ev.preventDefault();
    const f = form();
    if (f.enabled && !f.email.enabled && !f.slack.enabled && !f.teams.enabled) return toast('Enable at least one channel (Email, Slack or Teams)');
    try { await api('/alerts', { method: 'PUT', body: JSON.stringify(f) }); toast('Alert settings saved'); viewAlerts(); } catch (er) { toast(er.message); }
  };
  $$('[data-test]').forEach((b) => (b.onclick = async () => {
    const k = b.dataset.test, out = $(`#${k}-res`);
    b.disabled = true; out.className = 'small muted'; out.textContent = 'Sending…';
    try {
      const r = await api('/alerts/test', { method: 'POST', body: JSON.stringify({ ...form(), channel: k }) });
      out.className = 'small ' + (r.ok ? 'down' : 'err'); out.textContent = r.ok ? `✓ ${r.detail === 'posted' ? 'Message posted' : 'Email ' + r.detail}` : '✕ ' + r.error;
    } catch (er) { out.className = 'small err'; out.textContent = '✕ ' + er.message; }
    b.disabled = false;
  }));
}

/* ---------- router ---------- */
async function route() {
  routeSeq++; stopPoll();
  const h = location.hash.replace(/^#\/?/, '');
  const [a, b] = h.split('/');
  try {
    if (!a) await viewHome();
    else if (a === 'scan') viewScan(b);
    else if (a === 'report') await viewReport(b);
    else if (a === 'history') await viewHistory();
    else if (a === 'tools') await viewTools();
    else if (a === 'compare') await viewCompare(b, h.split('/')[2]);
    else if (a === 'settings') await viewSettings();
    else if (a === 'alerts') await viewAlerts();
    else location.hash = '#/';
  } catch (e) { $('#view').innerHTML = `<div class="empty err">Something went wrong: ${esc(e.message)}</div>`; }
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', route);
refreshEngine().then(route);
setInterval(() => refreshEngine(), 30000);

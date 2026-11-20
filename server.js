'use strict';
/*
 * Vulnora - local server (Trivy engine) (zero dependencies, Node 16+)
 * Runs Trivy via Docker (aquasec/trivy) or a native `trivy` binary,
 * normalises the JSON output and serves the dashboard UI on http://127.0.0.1:8787
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

const PORT = Number(process.env.PORT) || 8787;
const HOST = '127.0.0.1'; // local only - never expose this tool on the network
const ROOT = __dirname;
const PUB = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
const SCANS = path.join(DATA, 'scans');
const SBOMS = path.join(DATA, 'sbom');
const INDEX = path.join(DATA, 'index.json');
const SETTINGS = path.join(DATA, 'settings.json');
const ALERTS = path.join(DATA, 'alerts.json');
const TRIVY_IMAGE = process.env.TRIVY_IMAGE || 'aquasec/trivy:latest';
const CACHE_VOLUME = 'trivy-cache';
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const MODULES = ['image', 'fs', 'repo', 'config', 'secret', 'license', 'sbom'];

[DATA, SCANS, SBOMS].forEach((d) => fs.mkdirSync(d, { recursive: true }));

/* ---------- small helpers ---------- */
const stripAnsi = (s) => String(s).replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');
const uid = () => crypto.randomBytes(6).toString('hex');
const send = (res, code, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
};
const readBody = (req, limit = 1e6) =>
  new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) { reject(new Error('Body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (e) { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
const exec = (cmd, args, timeout = 10000) =>
  new Promise((resolve) => {
    execFile(cmd, args, { timeout, windowsHide: true, encoding: 'utf8' }, (err, stdout, stderr) =>
      resolve({ ok: !err, stdout: (stdout || '').trim(), stderr: (stderr || '').trim() })
    );
  });

/* ---------- engine detection ---------- */
let statusCache = null;
let statusAt = 0;
async function getStatus(force) {
  if (!force && statusCache && Date.now() - statusAt < 15000) return statusCache;
  const [nat, dock] = await Promise.all([
    exec('trivy', ['--version']),
    exec('docker', ['version', '--format', '{{.Server.Version}}']),
  ]);
  let imageReady = false;
  if (dock.ok) imageReady = (await exec('docker', ['image', 'inspect', TRIVY_IMAGE, '--format', '{{.Id}}'])).ok;
  const pref = (process.env.TRIVY_ENGINE || 'auto').toLowerCase();
  let engine = 'none';
  if (pref === 'native' && nat.ok) engine = 'native';
  else if (pref === 'docker' && dock.ok) engine = 'docker';
  else if (pref === 'auto') engine = dock.ok ? 'docker' : nat.ok ? 'native' : 'none';
  statusCache = {
    engine,
    docker: { available: dock.ok, version: dock.ok ? dock.stdout : null, trivyImageReady: imageReady, image: TRIVY_IMAGE },
    native: { available: nat.ok, version: nat.ok ? nat.stdout.split('\n')[0] : null },
    node: process.version,
    platform: process.platform,
  };
  statusAt = Date.now();
  return statusCache;
}

function invocation(engine, trivyArgs, opts = {}) {
  if (engine === 'native') return { cmd: 'trivy', args: trivyArgs };
  const a = ['run', '--rm', '--name', opts.name || 'trivy-' + uid(), '-v', CACHE_VOLUME + ':/root/.cache/trivy'];
  if (opts.mount) a.push('-v', opts.mount + ':/scan:ro');
  if (opts.sock) a.push('-v', '/var/run/docker.sock:/var/run/docker.sock');
  a.push(TRIVY_IMAGE, ...trivyArgs);
  return { cmd: 'docker', args: a };
}

/* ---------- jobs ---------- */
const jobs = new Map();
function newJob(kind, label) {
  const job = { id: uid(), kind, label, status: 'running', log: [], startedAt: Date.now(), finishedAt: null, scanId: null, error: null, child: null, container: null };
  jobs.set(job.id, job);
  // keep memory bounded
  if (jobs.size > 60) jobs.delete(jobs.keys().next().value);
  return job;
}
const jlog = (job, line) => {
  const s = stripAnsi(line).replace(/\r/g, '');
  if (!s.trim()) return;
  job.log.push(s);
  if (job.log.length > 2000) job.log.splice(0, 500);
};
const publicJob = (j) => ({ id: j.id, kind: j.kind, label: j.label, status: j.status, log: j.log.slice(-400), startedAt: j.startedAt, finishedAt: j.finishedAt, scanId: j.scanId, error: j.error, target: j.target || null, module: j.module || null, queuePos: j.status === 'queued' ? trivyQueue.indexOf(j) + 1 : 0 });
const jobSummary = (j) => { const p = publicJob(j); p.log = p.log.slice(-2); return p; };

/* One Trivy process at a time: Trivy's database cache is locked by a running scan, so further
   scans wait in this queue instead of failing or fighting over the lock. */
const trivyQueue = []; // jobs waiting, in order
let trivyBusy = null;  // job currently holding the engine
function withTrivy(job, fn) {
  return new Promise((resolve) => {
    const run = async () => {
      if (job.cancelled) return resolve({ cancelled: true }); // cancelled while queued: never touches the engine
      trivyBusy = job;
      job.status = 'running';
      try { resolve(await fn()); } finally { trivyBusy = null; next(); }
    };
    job.runNext = run;
    if (!trivyBusy && !trivyQueue.length) return run();
    job.status = 'queued';
    trivyQueue.push(job);
    jlog(job, 'Queued: waiting for the scan that is already running to finish.');
  });
}
function next() {
  const j = trivyQueue.shift();
  if (j) { jlog(j, 'Starting now.'); j.runNext(); }
}

function runProcess(job, inv, { collect = true, timeoutMs = 35 * 60 * 1000 } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(inv.cmd, inv.args, { windowsHide: true }); }
    catch (e) { resolve({ code: -1, stdout: Buffer.alloc(0), err: e.message }); return; }
    job.child = child;
    const out = [];
    let errBuf = '';
    const timer = setTimeout(() => { jlog(job, 'Timed out - stopping scan'); stopJob(job); }, timeoutMs);
    child.stdout.on('data', (d) => { if (collect) out.push(d); else d.toString().split('\n').forEach((l) => jlog(job, l)); });
    child.stderr.on('data', (d) => {
      errBuf += d.toString();
      const parts = errBuf.split('\n');
      errBuf = parts.pop();
      parts.forEach((l) => jlog(job, l));
    });
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, stdout: Buffer.alloc(0), err: e.code === 'ENOENT' ? `"${inv.cmd}" was not found. Install Docker Desktop (or Trivy) and try again.` : e.message }); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (errBuf.trim()) jlog(job, errBuf);
      resolve({ code, stdout: Buffer.concat(out) });
    });
  });
}
function stopJob(job) {
  if (job.container) exec('docker', ['rm', '-f', job.container], 15000);
  if (job.child) { try { job.child.kill(); } catch (e) { /* ignore */ } }
}
const finish = (job, error) => {
  job.finishedAt = Date.now();
  if (job.cancelled) { job.status = 'cancelled'; job.error = 'Cancelled'; }
  else if (error) { job.status = 'failed'; job.error = error; }
  else job.status = 'done';
};

/* ---------- normalisation of Trivy JSON ---------- */
const sevOf = (s) => (SEVS.includes(String(s).toUpperCase()) ? String(s).toUpperCase() : 'UNKNOWN');
const clip = (s, n) => (s ? String(s).slice(0, n) : '');
const countBy = (arr) => {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  arr.forEach((x) => { c[x.severity] = (c[x.severity] || 0) + 1; });
  return c;
};
function maxCvss(v) {
  let m = 0;
  if (v && v.CVSS) Object.values(v.CVSS).forEach((c) => { m = Math.max(m, c.V3Score || 0, c.V2Score || 0); });
  return m || null;
}
function normalize(raw) {
  const vulns = [], secrets = [], misconfigs = [], licenses = [];
  (raw.Results || []).forEach((r) => {
    const base = { target: r.Target, cls: r.Class || '', type: r.Type || '' };
    (r.Vulnerabilities || []).forEach((v) => vulns.push({
      ...base, id: v.VulnerabilityID, pkg: v.PkgName, installed: v.InstalledVersion || '', fixed: v.FixedVersion || '',
      severity: sevOf(v.Severity), title: clip(v.Title, 200), description: clip(v.Description, 500),
      url: v.PrimaryURL || (v.References && v.References[0]) || '', cvss: maxCvss(v), status: v.Status || '',
    }));
    (r.Secrets || []).forEach((s) => secrets.push({
      ...base, id: s.RuleID, category: s.Category || '', severity: sevOf(s.Severity), title: clip(s.Title, 200),
      line: s.StartLine || 0, match: clip(s.Match, 200),
    }));
    (r.Misconfigurations || []).forEach((m) => misconfigs.push({
      ...base, id: m.AVDID || m.ID, ruleId: m.ID, title: clip(m.Title, 200), description: clip(m.Description, 500),
      message: clip(m.Message, 400), resolution: clip(m.Resolution, 400), severity: sevOf(m.Severity),
      status: m.Status || 'FAIL', url: m.PrimaryURL || '',
    }));
    (r.Licenses || []).forEach((l) => licenses.push({
      ...base, pkg: l.PkgName || '', name: l.Name, severity: sevOf(l.Severity), category: l.Category || '',
      file: l.FilePath || '', link: l.Link || '',
    }));
  });
  const md = raw.Metadata || {};
  return {
    findings: { vulns, secrets, misconfigs, licenses },
    summary: { vulns: countBy(vulns), secrets: countBy(secrets), misconfigs: countBy(misconfigs), licenses: countBy(licenses) },
    meta: {
      artifact: raw.ArtifactName || '', artifactType: raw.ArtifactType || '',
      os: md.OS ? `${md.OS.Family || ''} ${md.OS.Name || ''}`.trim() : '',
      imageId: md.ImageID || '', tags: md.RepoTags || [], digests: md.RepoDigests || [],
      packages: (raw.Results || []).reduce((n, r) => n + (r.Packages ? r.Packages.length : 0), 0),
      targets: (raw.Results || []).length,
    },
  };
}

/* ---------- scan index / storage ---------- */
let index = [];
try { index = JSON.parse(fs.readFileSync(INDEX, 'utf8')); } catch (e) { index = []; }
const saveIndex = () => fs.writeFileSync(INDEX, JSON.stringify(index));
function storeScan(rec) {
  fs.writeFileSync(path.join(SCANS, rec.id + '.json'), JSON.stringify(rec));
  const { findings, ...slim } = rec; // eslint-disable-line no-unused-vars
  index.unshift(slim);
  saveIndex();
}

/* ---------- report branding settings ---------- */
const DEFAULT_SETTINGS = { company: '', preparedBy: '', reportTitle: 'Security Scan Report', footer: 'Confidential security report', headerColor: '#0e1126', logo: null, showTrivyLogo: true };
let settings = { ...DEFAULT_SETTINGS };
try { settings = { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS, 'utf8')) }; } catch (e) { /* defaults */ }
function updateSettings(body) {
  const str = (v, n) => String(v == null ? '' : v).replace(/[\r\n\0]/g, ' ').trim().slice(0, n);
  const next = { ...settings };
  if ('company' in body) next.company = str(body.company, 120);
  if ('preparedBy' in body) next.preparedBy = str(body.preparedBy, 120);
  if ('reportTitle' in body) next.reportTitle = str(body.reportTitle, 80) || DEFAULT_SETTINGS.reportTitle;
  if ('footer' in body) next.footer = str(body.footer, 120);
  if ('headerColor' in body) {
    if (!/^#[0-9a-f]{6}$/i.test(String(body.headerColor))) throw new Error('Header colour must look like #1a2b3c');
    next.headerColor = String(body.headerColor).toLowerCase();
  }
  if ('showTrivyLogo' in body) next.showTrivyLogo = !!body.showTrivyLogo;
  if ('logo' in body) {
    if (body.logo === null || body.logo === '') next.logo = null;
    else {
      const l = String(body.logo);
      if (!/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(l)) throw new Error('Logo must be a PNG or JPEG image');
      if (l.length > 1.5e6) throw new Error('Logo is too large (max ~1 MB)');
      next.logo = l;
    }
  }
  settings = next;
  fs.writeFileSync(SETTINGS, JSON.stringify(settings));
  return settings;
}

/* ---------- alerts (email / Slack / Teams) ---------- */
const { createAlerts } = require('./alerts');
const { scanPdf } = require('./pdfgen');
const alerts = createAlerts({ file: ALERTS, port: PORT, getBrand: () => settings, makePdf: (scan) => scanPdf(scan, settings), log: (l) => console.log('  ' + l) });
function previousScan(rec) { // the scan of the same target that came before this one
  const prev = index.find((x) => x.id !== rec.id && x.target === rec.target && x.module === rec.module && new Date(x.createdAt) <= new Date(rec.createdAt));
  if (!prev) return null;
  try { return JSON.parse(fs.readFileSync(path.join(SCANS, prev.id + '.json'), 'utf8')); } catch (e) { return null; }
}
async function runAlerts(rec) {
  try {
    const r = await alerts.onScan(rec, previousScan(rec));
    if (!r) return;
    rec.alerts = { at: new Date().toISOString(), ...r };
    fs.writeFileSync(path.join(SCANS, rec.id + '.json'), JSON.stringify(rec));
    const ix = index.find((x) => x.id === rec.id); if (ix) { ix.alerts = rec.alerts; saveIndex(); }
  } catch (e) { console.error('Alert error:', e.message); }
}

/* ---------- scan runner ---------- */
function validate(body) {
  const mod = String(body.module || '');
  if (!MODULES.includes(mod)) throw new Error('Unknown module');
  const target = String(body.target || '').trim();
  if (!target) throw new Error('Target is required');
  if (target.length > 500 || /[\r\n\0]/.test(target)) throw new Error('Invalid target');
  if (target.startsWith('-')) throw new Error('Target must not start with "-"');
  let source = String(body.source || '');
  if (mod === 'image' || mod === 'sbom') source = 'image';
  else if (mod === 'fs' || mod === 'config') source = 'fs';
  else if (mod === 'repo') source = 'repo';
  else if (!['image', 'fs', 'repo'].includes(source)) source = 'image';
  const sev = (Array.isArray(body.severities) ? body.severities : SEVS).map(String).filter((s) => SEVS.includes(s));
  return { mod, target, source, sev: sev.length ? sev : SEVS };
}

/* ---------- web application checks (no Trivy needed) ---------- */
const { runWebChecks } = require('./webscan');
function startWebScan(body) {
  const target = String(body.target || '').trim();
  let u;
  try { u = new URL(/^https?:\/\//i.test(target) ? target : 'https://' + target); } catch (e) { throw new Error('Enter a full URL, e.g. https://example.com'); }
  if (!/^https?:$/.test(u.protocol) || target.length > 500 || /\s/.test(target)) throw new Error('Enter a full URL, e.g. https://example.com');
  if (body.authorized !== true) throw new Error('Confirm that you own this site or have written permission to test it.');
  const url = u.toString();
  const job = newJob('scan', `WEB scan: ${url}`);
  job.target = url; job.module = 'webapp';
  jlog(job, `Passive web checks on ${url} (authorised by the user).`);
  (async () => {
    const t0 = Date.now();
    try {
      const res = await runWebChecks(url, { log: (l) => jlog(job, l), cancelled: () => !!job.cancelled });
      if (job.cancelled) return finish(job);
      const id = uid();
      const rec = {
        id, module: 'webapp', source: 'url', target: url, createdAt: new Date().toISOString(), durationMs: Date.now() - t0,
        engine: 'vulnora-web', scanners: ['web'], severities: SEVS, sbom: null, meta: res.meta,
        findings: { vulns: [], secrets: [], misconfigs: res.findings, licenses: [] },
        summary: { vulns: countBy([]), secrets: countBy([]), misconfigs: countBy(res.findings), licenses: countBy([]) },
      };
      storeScan(rec);
      runAlerts(rec);
      job.scanId = id;
      jlog(job, 'Scan stored. Opening report...');
      finish(job);
    } catch (e) {
      jlog(job, 'ERROR ' + e.message);
      finish(job, job.cancelled ? undefined : e.message);
    }
  })();
  return job;
}

async function startScan(body) {
  if (body && body.module === 'webapp') return startWebScan(body);
  const { mod, target, source, sev } = validate(body);
  const st = await getStatus();
  if (st.engine === 'none') throw new Error('Neither Docker nor Trivy was found. Start Docker Desktop (or install Trivy) and retry.');
  const engine = st.engine;
  let scanners = (Array.isArray(body.scanners) ? body.scanners : ['vuln']).filter((s) => ['vuln', 'secret', 'misconfig', 'license'].includes(s));
  if (mod === 'secret') scanners = ['secret'];
  if (mod === 'license') scanners = ['license'];
  if (mod === 'config') scanners = ['misconfig'];
  if (mod === 'sbom') scanners = [];
  if (mod !== 'sbom' && !scanners.length) scanners = ['vuln'];
  const sbomFormat = body.sbomFormat === 'spdx-json' ? 'spdx-json' : 'cyclonedx';

  const opts = {};
  let tgt = target;
  if (source === 'fs') {
    if (engine === 'docker') {
      let p = target.replace(/[\\/]+$/, '');
      if (/^[A-Za-z]:$/.test(p)) p += '\\';
      if (!fs.existsSync(target)) throw new Error('Folder not found on this computer: ' + target);
      opts.mount = p; tgt = '/scan';
    } else if (!fs.existsSync(target)) throw new Error('Folder not found: ' + target);
  }
  if (source === 'image' && body.localImage) opts.sock = true;

  const sub = mod === 'config' ? 'config' : source === 'fs' ? 'fs' : source === 'repo' ? 'repo' : 'image';
  const fmt = mod === 'sbom' ? sbomFormat : 'json';
  const args = [sub, '--format', fmt, '--no-progress', '--timeout', '30m'];
  if (mod !== 'sbom' && sub !== 'config') args.push('--scanners', scanners.join(','));
  if (mod !== 'sbom') args.push('--severity', sev.join(','));
  if (body.ignoreUnfixed && scanners.includes('vuln')) args.push('--ignore-unfixed');
  if (mod === 'license') args.push('--license-full');
  args.push(tgt);

  opts.name = 'trivy-dash-' + uid();
  const inv = invocation(engine, args, opts);
  const job = newJob('scan', `${mod.toUpperCase()} scan: ${target}`);
  if (engine === 'docker') job.container = opts.name;
  jlog(job, `Engine: ${engine}`);
  jlog(job, `$ ${inv.cmd} ${inv.args.join(' ')}`);

  job.target = target; job.module = mod;
  (async () => {
    let t0 = Date.now();
    const r = await withTrivy(job, () => { t0 = Date.now(); return runProcess(job, inv); });
    if (job.cancelled || r.cancelled) return finish(job);
    if (r.err) return finish(job, r.err);
    if (r.code !== 0) {
      const tail = job.log.filter((l) => /FATAL|ERROR|error|denied|not found|unauthorized/i.test(l)).slice(-3).join(' | ');
      return finish(job, `Trivy exited with code ${r.code}. ${tail}`.trim());
    }
    try {
      const id = uid();
      const text = r.stdout.toString('utf8');
      const raw = JSON.parse(text);
      const base = { id, module: mod, source, target, createdAt: new Date().toISOString(), durationMs: Date.now() - t0, engine, scanners, severities: sev, sbom: null };
      if (mod === 'sbom') {
        fs.writeFileSync(path.join(SBOMS, id + '.json'), text);
        const comps = fmt === 'cyclonedx' ? (raw.components || []).length : (raw.packages || []).length;
        const rec = { ...base, summary: { vulns: countBy([]), secrets: countBy([]), misconfigs: countBy([]), licenses: countBy([]) }, meta: { artifact: target }, findings: { vulns: [], secrets: [], misconfigs: [], licenses: [] }, sbom: { format: fmt, components: comps } };
        storeScan(rec);
      } else {
        const n = normalize(raw);
        const rec = { ...base, ...n };
        storeScan(rec);
        runAlerts(rec); // async - does not delay opening the report
      }
      job.scanId = id;
      jlog(job, 'Scan stored. Opening report...');
      finish(job);
    } catch (e) { finish(job, 'Could not parse Trivy output: ' + e.message); }
  })();
  return job;
}

/* utility jobs: pull image, update DB, version */
async function startUtility(kind) {
  const st = await getStatus(true);
  if (st.engine === 'none') throw new Error('Neither Docker nor Trivy was found.');
  const job = newJob(kind, { pull: 'Pull Trivy image', dbupdate: 'Update vulnerability database', version: 'Trivy version & DB info' }[kind]);
  let inv;
  if (kind === 'pull') {
    if (st.engine !== 'docker') throw new Error('Pull applies to the Docker engine only.');
    inv = { cmd: 'docker', args: ['pull', TRIVY_IMAGE] };
  } else if (kind === 'dbupdate') {
    const name = 'trivy-dash-' + uid();
    inv = invocation(st.engine, ['image', '--download-db-only', '--no-progress'], { name });
    if (st.engine === 'docker') job.container = name;
  } else {
    const name = 'trivy-dash-' + uid();
    inv = invocation(st.engine, ['version'], { name });
    if (st.engine === 'docker') job.container = name;
  }
  jlog(job, `$ ${inv.cmd} ${inv.args.join(' ')}`);
  (async () => {
    const go = () => runProcess(job, inv, { collect: false, timeoutMs: 15 * 60 * 1000 });
    const r = kind === 'pull' ? await go() : await withTrivy(job, go);
    statusAt = 0;
    if (job.cancelled || r.cancelled) return finish(job);
    if (r.err) return finish(job, r.err);
    finish(job, r.code === 0 ? null : 'Command exited with code ' + r.code);
  })();
  return job;
}

/* ---------- demo data (lets you explore the UI without Docker) ---------- */
function demoRaw() {
  const V = (id, pkg, ver, fix, sev, title, cvss) => ({ VulnerabilityID: id, PkgName: pkg, InstalledVersion: ver, FixedVersion: fix, Severity: sev, Title: title, Description: title + '. This is demonstration data, not a real finding.', PrimaryURL: 'https://avd.aquasec.com/nvd/' + id.toLowerCase(), CVSS: { nvd: { V3Score: cvss } } });
  return {
    ArtifactName: 'ubuntu:demo', ArtifactType: 'container_image',
    Metadata: { OS: { Family: 'ubuntu', Name: '26.04' }, ImageID: 'sha256:demo0000', RepoTags: ['ubuntu:demo'] },
    Results: [
      { Target: 'ubuntu:demo (ubuntu 26.04)', Class: 'os-pkgs', Type: 'ubuntu', Packages: new Array(87).fill({}), Vulnerabilities: [
        V('CVE-2025-1001', 'openssl', '3.0.13-0ubuntu3', '3.0.13-0ubuntu3.5', 'CRITICAL', 'openssl: remote code execution in X.509 parsing', 9.8),
        V('CVE-2025-1002', 'libc6', '2.39-0ubuntu8', '2.39-0ubuntu8.4', 'HIGH', 'glibc: buffer overflow in iconv', 8.1),
        V('CVE-2025-1003', 'libc-bin', '2.39-0ubuntu8', '2.39-0ubuntu8.4', 'HIGH', 'glibc: heap corruption in nscd', 7.8),
        V('CVE-2025-1004', 'libssl3', '3.0.13-0ubuntu3', '3.0.13-0ubuntu3.5', 'HIGH', 'openssl: timing side channel in RSA decrypt', 7.5),
        V('CVE-2025-1005', 'bash', '5.2.21-2ubuntu4', '', 'MEDIUM', 'bash: improper handling of crafted environment', 5.5),
        V('CVE-2025-1006', 'coreutils', '9.4-3ubuntu6', '9.4-3ubuntu6.1', 'MEDIUM', 'coreutils: race condition in chmod -R', 5.9),
        V('CVE-2025-1007', 'zlib1g', '1:1.3.dfsg-3.1', '1:1.3.dfsg-3.1ubuntu2', 'CRITICAL', 'zlib: integer overflow in inflate', 9.1),
        V('CVE-2025-1008', 'tar', '1.35+dfsg-3', '', 'LOW', 'tar: path traversal with crafted archive', 3.3),
        V('CVE-2025-1009', 'gpgv', '2.4.4-2ubuntu17', '2.4.4-2ubuntu17.2', 'MEDIUM', 'gnupg: signature verification bypass', 6.1),
        V('CVE-2025-1010', 'libsystemd0', '255.4-1ubuntu8', '255.4-1ubuntu8.6', 'HIGH', 'systemd: privilege escalation in tmpfiles', 7.8),
        V('CVE-2025-1011', 'apt', '2.7.14build2', '2.7.14build2.3', 'LOW', 'apt: information disclosure in debug logs', 3.1),
        V('CVE-2025-1012', 'login', '1:4.13+dfsg1-4ubuntu3', '', 'LOW', 'shadow: minor information leak', 2.9),
        V('CVE-2025-1013', 'perl-base', '5.38.2-3.2build2', '5.38.2-3.2build2.1', 'MEDIUM', 'perl: regex denial of service', 5.3),
        V('CVE-2025-1014', 'libgnutls30', '3.8.3-1.1ubuntu3', '3.8.3-1.1ubuntu3.4', 'UNKNOWN', 'gnutls: under analysis', 0),
        V('CVE-2025-1015', 'openssl', '3.0.13-0ubuntu3', '3.0.13-0ubuntu3.4', 'MEDIUM', 'openssl: denial of service via crafted certificate', 5.9),
      ] },
      { Target: 'Python', Class: 'lang-pkgs', Type: 'python-pkg', Vulnerabilities: [
        V('CVE-2025-2001', 'requests', '2.25.0', '2.32.0', 'HIGH', 'requests: credentials leak on redirect', 7.4),
        V('CVE-2025-2002', 'urllib3', '1.26.5', '1.26.19', 'MEDIUM', 'urllib3: proxy-authorization header leak', 5.6),
      ] },
      { Target: 'app/config.env', Class: 'secret', Secrets: [
        { RuleID: 'aws-access-key-id', Category: 'AWS', Severity: 'CRITICAL', Title: 'AWS Access Key ID', StartLine: 4, Match: 'AWS_KEY=********************' },
        { RuleID: 'github-pat', Category: 'GitHub', Severity: 'CRITICAL', Title: 'GitHub Personal Access Token', StartLine: 9, Match: 'GH_TOKEN=ghp_****************' },
        { RuleID: 'private-key', Category: 'AsymmetricPrivateKey', Severity: 'HIGH', Title: 'Asymmetric Private Key', StartLine: 21, Match: '-----BEGIN RSA PRIVATE KEY-----' },
      ] },
      { Target: 'Dockerfile', Class: 'config', Type: 'dockerfile', Misconfigurations: [
        { ID: 'DS002', AVDID: 'AVD-DS-0002', Title: 'Image user should not be root', Description: 'Running containers as root increases the impact of a compromise.', Message: 'Specify at least 1 USER command in Dockerfile with non-root user as argument', Resolution: 'Add USER <non root user name> line to the Dockerfile', Severity: 'HIGH', Status: 'FAIL', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds002' },
        { ID: 'DS026', AVDID: 'AVD-DS-0026', Title: 'No HEALTHCHECK defined', Description: 'Add HEALTHCHECK so the orchestrator can detect unhealthy containers.', Message: 'Add HEALTHCHECK instruction in your Dockerfile', Resolution: 'Add HEALTHCHECK instruction', Severity: 'LOW', Status: 'FAIL', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds026' },
        { ID: 'DS005', AVDID: 'AVD-DS-0005', Title: 'ADD instead of COPY', Description: 'You should use COPY instead of ADD unless you want to extract a tar file.', Message: 'Consider using COPY instead of ADD', Resolution: 'Use COPY', Severity: 'LOW', Status: 'FAIL', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds005' },
        { ID: 'DS029', AVDID: 'AVD-DS-0029', Title: "'apt-get' missing '--no-install-recommends'", Description: 'Avoid pulling unneeded packages.', Message: "'--no-install-recommends' flag is missed", Resolution: "Add '--no-install-recommends' flag", Severity: 'HIGH', Status: 'FAIL', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds029' },
      ] },
      { Target: 'OS Packages', Class: 'license', Licenses: [
        { PkgName: 'bash', Name: 'GPL-3.0-or-later', Severity: 'HIGH', Category: 'restricted', FilePath: '' },
        { PkgName: 'coreutils', Name: 'GPL-3.0-or-later', Severity: 'HIGH', Category: 'restricted', FilePath: '' },
        { PkgName: 'tar', Name: 'GPL-3.0-or-later', Severity: 'HIGH', Category: 'restricted', FilePath: '' },
        { PkgName: 'libc6', Name: 'LGPL-2.1-or-later', Severity: 'MEDIUM', Category: 'reciprocal', FilePath: '' },
        { PkgName: 'zlib1g', Name: 'Zlib', Severity: 'LOW', Category: 'notice', FilePath: '' },
        { PkgName: 'openssl', Name: 'Apache-2.0', Severity: 'LOW', Category: 'notice', FilePath: '' },
      ] },
    ],
  };
}
// "after" variant: some packages upgraded (fixed), a couple of new CVEs, one secret removed
function demoRawAfter() {
  const raw = JSON.parse(JSON.stringify(demoRaw()));
  const os = raw.Results[0];
  const gone = ['CVE-2025-1001', 'CVE-2025-1007', 'CVE-2025-1004', 'CVE-2025-1015', 'CVE-2025-1009'];
  os.Vulnerabilities = os.Vulnerabilities.filter((v) => !gone.includes(v.VulnerabilityID));
  os.Vulnerabilities.forEach((v) => { if (v.PkgName === 'libc6' || v.PkgName === 'libc-bin') v.InstalledVersion = '2.39-0ubuntu8.2'; });
  const V = (id, pkg, ver, fix, sev, title, cvss) => ({ VulnerabilityID: id, PkgName: pkg, InstalledVersion: ver, FixedVersion: fix, Severity: sev, Title: title, Description: title + '. This is demonstration data, not a real finding.', PrimaryURL: 'https://avd.aquasec.com/nvd/' + id.toLowerCase(), CVSS: { nvd: { V3Score: cvss } } });
  os.Vulnerabilities.push(
    V('CVE-2025-3001', 'curl', '8.5.0-2ubuntu10', '8.5.0-2ubuntu10.3', 'HIGH', 'curl: cookie injection via crafted redirect', 7.5),
    V('CVE-2025-3002', 'libxml2', '2.9.14+dfsg-1.3', '', 'MEDIUM', 'libxml2: use-after-free in xmlXIncludeDoProcess', 6.5)
  );
  raw.Results[1].Vulnerabilities = raw.Results[1].Vulnerabilities.filter((v) => v.VulnerabilityID !== 'CVE-2025-2001');
  raw.Results[2].Secrets = raw.Results[2].Secrets.filter((x) => x.RuleID !== 'github-pat');
  raw.Results[3].Misconfigurations = raw.Results[3].Misconfigurations.filter((m) => m.ID !== 'DS002');
  return raw;
}
function addDemo(variant, when) {
  const n = normalize(variant === 'after' ? demoRawAfter() : demoRaw());
  const rec = { id: uid(), module: 'image', source: 'image', target: 'ubuntu:demo (sample data)', createdAt: (when || new Date()).toISOString(), durationMs: 4200, engine: 'demo', scanners: ['vuln', 'secret', 'misconfig', 'license'], severities: SEVS, sbom: null, ...n };
  storeScan(rec);
  return rec.id;
}
function normalizeDemoForTest() {
  return { id: null, module: 'image', source: 'image', target: 'ubuntu:demo', createdAt: new Date().toISOString(), engine: 'demo', scanners: ['vuln', 'secret', 'misconfig', 'license'], ...normalize(demoRaw()) };
}
function addDemoPair() {
  const a = addDemo('before', new Date(Date.now() - 2 * 864e5));
  const b = addDemo('after', new Date());
  return { a, b };
}

/* ---------- HTTP ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };
function serveStatic(req, res) {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUB, p));
  if (!file.startsWith(PUB + path.sep) && file !== PUB) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(buf);
  });
}

async function api(req, res, url) {
  const p = url.pathname;
  const m = req.method;
  let g;
  if (m === 'GET' && p === '/api/status') return send(res, 200, await getStatus(url.searchParams.get('force') === '1'));
  if (m === 'POST' && p === '/api/scan') return send(res, 200, publicJob(await startScan(await readBody(req))));
  if (m === 'POST' && (g = p.match(/^\/api\/tools\/(pull|dbupdate|version)$/))) return send(res, 200, publicJob(await startUtility(g[1])));
  if (m === 'GET' && p === '/api/alerts') return send(res, 200, alerts.publicConfig());
  if (m === 'PUT' && p === '/api/alerts') return send(res, 200, alerts.update(await readBody(req)));
  if (m === 'POST' && p === '/api/alerts/test') return send(res, 200, await alerts.test(await readBody(req), normalizeDemoForTest()));
  if (m === 'GET' && p === '/api/settings') return send(res, 200, settings);
  if (m === 'PUT' && p === '/api/settings') return send(res, 200, updateSettings(await readBody(req, 2e6)));
  if (m === 'POST' && p === '/api/demo') {
    const body = await readBody(req);
    return send(res, 200, body && body.pair ? addDemoPair() : { id: addDemo() });
  }
  if (m === 'GET' && p === '/api/jobs') {
    const since = Date.now() - 15 * 60 * 1000;
    return send(res, 200, [...jobs.values()].filter((j) => j.status === 'running' || j.status === 'queued' || (j.finishedAt || 0) > since).map(jobSummary).reverse());
  }
  if (m === 'GET' && (g = p.match(/^\/api\/jobs\/([a-f0-9]+)$/))) {
    const j = jobs.get(g[1]);
    return j ? send(res, 200, publicJob(j)) : send(res, 404, { error: 'Job not found' });
  }
  if (m === 'POST' && (g = p.match(/^\/api\/jobs\/([a-f0-9]+)\/cancel$/))) {
    const j = jobs.get(g[1]);
    if (!j) return send(res, 404, { error: 'Job not found' });
    j.cancelled = true;
    const qi = trivyQueue.indexOf(j);
    if (qi >= 0) { trivyQueue.splice(qi, 1); j.runNext(); } else stopJob(j);
    return send(res, 200, { ok: true });
  }
  if (m === 'GET' && p === '/api/scans') return send(res, 200, index);
  if ((g = p.match(/^\/api\/scans\/([a-f0-9]+)$/))) {
    const id = g[1];
    const file = path.join(SCANS, id + '.json');
    if (m === 'GET') {
      if (!fs.existsSync(file)) return send(res, 404, { error: 'Scan not found' });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      return fs.createReadStream(file).pipe(res);
    }
    if (m === 'DELETE') {
      [file, path.join(SBOMS, id + '.json')].forEach((f) => { try { fs.unlinkSync(f); } catch (e) { /* ignore */ } });
      index = index.filter((s) => s.id !== id); saveIndex();
      return send(res, 200, { ok: true });
    }
  }
  if (m === 'GET' && (g = p.match(/^\/api\/sbom\/([a-f0-9]+)$/))) {
    const file = path.join(SBOMS, g[1] + '.json');
    if (!fs.existsSync(file)) return send(res, 404, { error: 'SBOM not found' });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="sbom-${g[1]}.json"` });
    return fs.createReadStream(file).pipe(res);
  }
  return send(res, 404, { error: 'Unknown endpoint' });
}

const server = http.createServer(async (req, res) => {
  // Security headers on EVERY response (set first, so error pages carry them too)
  res.setHeader('X-Frame-Options', 'DENY');                          // anti-clickjacking: never show Vulnora inside another site's frame
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'"); // modern equivalent of the above (CSP Level 2+)
  res.setHeader('X-Content-Type-Options', 'nosniff');                // browsers must not guess file types
  res.setHeader('Referrer-Policy', 'no-referrer');                     // never leak dashboard URLs to other sites
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); // the dashboard needs no device access
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    // basic DNS-rebinding / cross-site protection: only accept our own host
    const hostOk = /^(127\.0\.0\.1|localhost)(:\d+)?$/.test(req.headers.host || '');
    if (!hostOk) { res.writeHead(403); return res.end('Forbidden host'); }
    if (url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET') {
        const o = req.headers.origin;
        if (o && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(o)) return send(res, 403, { error: 'Cross-origin request blocked' });
      }
      return await api(req, res, url);
    }
    return serveStatic(req, res);
  } catch (e) {
    if (!res.headersSent) send(res, 400, { error: e.message });
    else res.end();
  }
});
server.on('error', (e) => {
  console.error(e.code === 'EADDRINUSE' ? `Port ${PORT} is already in use. Close the other instance or set PORT=xxxx.` : e.message);
  process.exit(1);
});
server.listen(PORT, HOST, () => {
  console.log(`\n  Vulnora running at  http://${HOST}:${PORT}\n  Press Ctrl+C to stop.\n`);
});
process.on('SIGINT', () => { jobs.forEach(stopJob); process.exit(0); });

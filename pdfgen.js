'use strict';
/*
 * Server-side PDF reports for email alerts.
 * Runs the SAME code the browser uses (vendored jsPDF + AutoTable, summary.js, report.js) inside an
 * isolated vm context, so an emailed PDF is identical to one downloaded from the dashboard.
 */
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const PUB = path.join(__dirname, 'public');
let ctx = null;
const dataUrl = (f) => 'data:image/png;base64,' + fs.readFileSync(path.join(PUB, f)).toString('base64');

function load() {
  if (ctx) return ctx;
  const sandbox = {
    console, setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    atob, btoa, TextEncoder, TextDecoder, URL,
    navigator: { userAgent: 'node' },
  };
  sandbox.window = sandbox; sandbox.self = sandbox;
  vm.createContext(sandbox);
  for (const f of ['vendor/jspdf.umd.min.js', 'vendor/jspdf.plugin.autotable.min.js', 'summary.js', 'report.js']) {
    vm.runInContext(fs.readFileSync(path.join(PUB, f), 'utf8'), sandbox, { filename: f });
  }
  const logos = { light: dataUrl('logo.png'), dark: dataUrl('logo-dark.png') };
  sandbox.__vulnoraLogo = async (dark) => (dark ? logos.dark : logos.light);
  ctx = sandbox;
  return ctx;
}

// -> { filename, buffer }
async function scanPdf(scan, brand) {
  const c = load();
  const doc = await c.createScanPdf(scan, { ...brand });
  return { filename: c.scanPdfName(scan), buffer: Buffer.from(doc.output('arraybuffer')) };
}

module.exports = { scanPdf };

'use strict';
/* Plain-English summary of a scan: overall risk, key findings and a prioritised action list.
 * Shared by the dashboard, the PDF report and the server-side alerts (UMD). Returns plain text only. */
(function (root) {
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
  const RISK = ['Critical', 'High', 'Medium', 'Low', 'Low'];
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
  const list = (arr, n) => (arr.length > n ? arr.slice(0, n).join(', ') + ` and ${arr.length - n} more` : arr.join(', '));

  function summarize(scan) {
    const f = scan.findings || { vulns: [], secrets: [], misconfigs: [], licenses: [] };
    const V = f.vulns || [], S = f.secrets || [], MC = f.misconfigs || [], L = f.licenses || [];
    const all = [...V, ...S, ...MC, ...L];
    const worst = all.reduce((w, x) => Math.min(w, RANK[x.severity] ?? 4), 4);
    const risk = all.length ? RISK[worst] : 'None';
    const cnt = (arr, s) => arr.filter((x) => x.severity === s).length;
    const critAll = cnt(V, 'CRITICAL') + cnt(S, 'CRITICAL') + cnt(MC, 'CRITICAL');
    const highAll = cnt(V, 'HIGH') + cnt(S, 'HIGH') + cnt(MC, 'HIGH');

    /* ---- headline ---- */
    let headline;
    if (!all.length) headline = 'No security issues were found in this scan.';
    else if (critAll) headline = `Action required: ${plural(critAll, 'critical issue')}${highAll ? ` and ${plural(highAll, 'high severity issue')}` : ''} need attention before this goes to production.`;
    else if (highAll) headline = `Attention recommended: no critical issues, but ${plural(highAll, 'high severity issue')} should be fixed soon.`;
    else headline = 'Low risk: no critical or high severity issues. Remaining findings can be handled in normal maintenance.';

    /* ---- key findings ---- */
    const points = [];
    if (V.length) {
      const pk = new Set(V.map((v) => v.pkg)).size;
      const fix = V.filter((v) => v.fixed).length;
      points.push(`${plural(V.length, 'vulnerability', 'vulnerabilities')} in ${plural(pk, 'package')} (${cnt(V, 'CRITICAL')} critical, ${cnt(V, 'HIGH')} high). ${fix} of them (${Math.round((fix / V.length) * 100)}%) can be fixed just by upgrading.`);
      const topCrit = V.filter((v) => v.severity === 'CRITICAL').sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
      if (topCrit.length) points.push(`Most serious: ${list(topCrit.map((v) => `${v.id} in ${v.pkg}${v.cvss ? ` (CVSS ${v.cvss.toFixed(1)})` : ''}`), 3)}.`);
    } else if ((scan.scanners || []).includes('vuln')) points.push('No known vulnerabilities in the scanned packages.');
    if (S.length) points.push(`${plural(S.length, 'exposed secret')} found (${list([...new Set(S.map((x) => x.title || x.id))], 3)}). Treat these credentials as compromised.`);
    const web = scan.module === 'webapp';
    if (MC.length) points.push(`${plural(MC.length, web ? 'web security finding' : 'misconfiguration')} (${cnt(MC, 'CRITICAL') + cnt(MC, 'HIGH')} high or critical), e.g. ${list([...new Set(MC.sort((a, b) => RANK[a.severity] - RANK[b.severity]).map((m) => m.title))], 2)}.`);
    const restricted = L.filter((l) => /forbidden|restricted/i.test(l.category));
    if (L.length) points.push(`${plural(L.length, 'license finding')}${restricted.length ? `, ${restricted.length} restricted or forbidden (${list([...new Set(restricted.map((l) => l.name))], 3)})` : ''}.`);

    /* ---- recommended actions (most urgent first) ---- */
    const actions = [];
    if (S.length) actions.push(`Rotate and remove the ${plural(S.length, 'exposed secret')} in ${list([...new Set(S.map((x) => x.target))], 2)}, then purge them from git history / image layers.`);
    // upgrades: group by package, rank by worst severity then number of issues fixed
    const up = new Map();
    V.filter((v) => v.fixed).forEach((v) => {
      const o = up.get(v.pkg) || { pkg: v.pkg, worst: 4, n: 0, c: 0, h: 0, to: v.fixed };
      if (RANK[v.severity] < o.worst) { o.worst = RANK[v.severity]; o.to = v.fixed; }
      o.n++; if (v.severity === 'CRITICAL') o.c++; if (v.severity === 'HIGH') o.h++;
      up.set(v.pkg, o);
    });
    const ups = [...up.values()].filter((o) => o.worst <= 1).sort((a, b) => a.worst - b.worst || b.n - a.n);
    ups.slice(0, 3).forEach((o) => {
      const what = [o.c && `${o.c} critical`, o.h && `${o.h} high`].filter(Boolean).join(', ');
      actions.push(`Upgrade ${o.pkg} to ${String(o.to).split(',')[0].trim()} or later (fixes ${what}${o.n > o.c + o.h ? `, ${o.n} in total` : ''}).`);
    });
    if (ups.length > 3) actions.push(`Upgrade ${plural(ups.length - 3, 'more package')} with critical/high fixes (see the "Fix available" list), or rebuild on a newer base image.`);
    const noFix = V.filter((v) => !v.fixed && RANK[v.severity] <= 1);
    if (noFix.length) actions.push(`${plural(noFix.length, 'critical/high vulnerability', 'critical/high vulnerabilities')} have no fix yet: monitor them, or switch to a different base image or package.`);
    const badMc = MC.filter((m) => RANK[m.severity] <= 1).sort((a, b) => RANK[a.severity] - RANK[b.severity]);
    badMc.slice(0, web ? 4 : 2).forEach((m) => actions.push(`${m.type === 'web' ? m.title : m.target}: ${String(m.resolution || m.title).replace(/\.+$/, '')}.`));
    if (restricted.length) actions.push(`Review ${plural(restricted.length, 'package')} with restricted licenses with your legal/compliance team.`);
    if (!actions.length && all.length) actions.push('No urgent action. Upgrade the remaining medium/low items during routine maintenance and rescan regularly.');
    if (!all.length) actions.push('Nothing to fix. Keep scanning after every build to catch new CVEs.');

    return { risk, headline, points, actions: actions.slice(0, 6), counts: { critical: critAll, high: highAll } };
  }

  const api = { summarize, SEVS, RANK };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.TrivySummary = api;
})(typeof window !== 'undefined' ? window : this);

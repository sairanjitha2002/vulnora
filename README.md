<p align="center"><img src="public/vulnora-full.png" alt="Vulnora" width="520"></p>

# Vulnora
**See Vulnerabilities. Secure Every Layer.**

Vulnora is a local web dashboard for security scanning, powered by the open-source
[Trivy](https://github.com/aquasecurity/trivy) engine (Aqua Security).

## Run
1. Install Docker Desktop (and Node.js LTS) - or a native Trivy install.
2. Double-click **start.bat**. The dashboard opens at http://127.0.0.1:8787.

Scans use `docker run --rm -v trivy-cache:/root/.cache/trivy aquasec/trivy:latest ...`
(the same cache volume as your manual command, so the DB is reused).

## Modules
Container image · Filesystem/project · Git repository · Misconfiguration (IaC) · Secrets · Licenses · SBOM (CycloneDX/SPDX)

## Reports
Open any scan -> **Download PDF report** (also JSON, CSV per table, SBOM download).
History is stored in the `data` folder.

## Compare scans
Sidebar -> **Compare scans**, or open a report and click **Compare** (picks the previous scan of the same target).
Shows new / fixed / unchanged findings, a before-vs-after severity table, and exports CSV or a comparison PDF.
Findings are matched by CVE + package (vulns), rule + file (secrets/misconfigs) and package + license, so a version bump that
still has the same CVE counts as "unchanged". Warnings appear if the scans used different targets, scanners or severity filters.

## Report branding
Sidebar -> **Report branding**: company name, "prepared by", report title, footer text, logo (PNG/JPG/SVG/WebP,
auto-converted to PNG) and header colour. A live preview shows the PDF cover; settings are saved in `data/settings.json`
and apply to both scan and comparison PDFs.

## Look and feel
Light theme by default (navy, pale blue and the severity colours from the Vulnora VAPT document), with a
**Dark mode** switch in the top-right corner. Your choice is remembered in this browser; on first visit the
portal follows your operating system's light/dark setting. The Overview page has a quick scan launcher:
pick a target type, paste the image, folder or repo, and press **Set up scan**.

## Scans run in the background
Starting a scan never blocks the page. A **Scans** panel in the bottom-right corner shows each scan's progress,
current stage and elapsed time, with **Show log**, **Cancel**, **Open report** and **Dismiss** buttons. You can keep
browsing reports, history or settings while it runs; **Hide** collapses the panel. If you are still on the scan form
when it finishes, the report opens automatically. Refreshing the page picks running scans back up.
Scans run one at a time (Trivy locks its database while scanning); extra scans wait in a queue and show their position.

## Report summary
Every report (dashboard and PDF) starts with a plain-English summary: overall risk, key findings and a numbered list of
recommended actions (rotate secrets, which packages to upgrade to which version, misconfigurations to fix).
If you set a company name under Report branding, it appears in bold on the PDF cover and footer.

## Alerts (email / Slack / Teams)
Sidebar -> **Alerts**. Turn alerts on, choose the trigger (critical, or critical + high; optionally secrets/misconfigs;
optionally only findings that are *new* since the previous scan of the same target), then enable one or more channels:
- **Email** - any SMTP server. Presets for Gmail (smtp.gmail.com, 465 SSL) and Outlook/M365 (smtp.office365.com, 587 STARTTLS).
  Gmail/Outlook require an *app password*.
- **Slack** - an Incoming Webhook URL (api.slack.com/apps -> Incoming Webhooks).
- **Microsoft Teams** - a Workflows webhook URL (channel ... -> Workflows -> "Post to a channel when a webhook request is received").
Use **Send test** on each channel. Alerts fire automatically after each real scan (never for demo data); the result is shown
on the report and under "Recent alerts". Settings, including the SMTP password and webhook URLs, are stored in plain text in
`data/alerts.json` on this computer - keep that folder private.


**PDF report in every email alert.** Alert emails carry the full branded PDF report as an attachment (the same PDF as
the dashboard's Download button), so recipients can read it without Vulnora. Slack and Teams webhooks cannot carry files,
so their messages say the PDF was emailed. An "Open in Vulnora" link is added only if you set a *shared dashboard
address* that teammates can reach (e.g. http://192.168.1.20:8787); 127.0.0.1 / localhost links are never sent.

## Web application scan (new in v2.5)
Sidebar -> **Web application**. Enter a URL you own or are authorised to test and tick the authorisation box.
Vulnora runs passive checks itself (no Docker or Trivy needed, about 20 paced requests):
security headers (HSTS, CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy), version banners,
cookie flags (Secure, HttpOnly, SameSite), HTTPS / redirect / certificate validity / TLS 1.0-1.1, exposed files
(/.git, /.env, database dumps, phpinfo, server-status, .DS_Store, directory listing), CORS reflection and TRACE.
Every finding has evidence, a CWE, its OWASP Top 10:2025 category and a fix, and flows into the summary, PDF,
compare, history and alerts. It never logs in, submits forms, fuzzes or sends attack payloads.

**Live demo:** run `node practice-site.js` (a deliberately insecure site on 127.0.0.1:8901), then scan
`http://127.0.0.1:8901`. Expect 2 critical, 1 high and several medium/low findings.

## Security headers
Every response carries `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'` (no other site can
show Vulnora in a frame, which blocks clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`
and `Permissions-Policy`. Vulnora's own Web application scan of itself reports only the expected local-tool items
(no HTTPS on 127.0.0.1, no security.txt).

## Notes
- Server binds to 127.0.0.1 only. No data leaves your machine except what Trivy itself downloads.
- Env vars: `PORT` (default 8787), `TRIVY_ENGINE` (auto | docker | native), `TRIVY_IMAGE`.
- "Load demo data" on the Overview page lets you explore the UI without scanning.

# Changelog

## 0.3.0

- `pxta diff OLD NEW`: compares two audits' `findings.json` and lists new
  and gone findings, tracker changes per pass (`started`, `stopped`,
  `more-pages`, `fewer-pages`, `other-pages`) and banner changes.
- Leaks are matched by rule and parameter (batch line numbers left out),
  sensitive pages by category and search terms by term, never by value, so
  client IDs that change every run don't show up as changes and staging
  compares with production.
- Findings on pages or passes only one audit covered are listed as not
  compared, never as fixed. They count as new when nothing like them
  happened anywhere in the old audit; `--new-pages` counts every finding on
  a page the old audit never reached as new.
- Exit codes 0 no change, 1 changes, 2 usage or a redacted audit against an
  unredacted one, 3 unreadable or unwritable file. `--fail-on` exits 1 for a
  new finding at a severity or above, and always for a lost consent pass,
  an audit that visited nothing, or a banner that's gone or can no longer
  be answered.
- Output as text, JSON (`--format json`, `--out`), GitHub annotations and a
  Markdown summary built from public fields only.
- GitHub Action: `baseline` and `baseline-fail-on` inputs run the diff after
  the check; with `baseline-fail-on`, the comparison decides the step, so
  problems the baseline already has don't fail it. Outputs `diff-exit-code`
  and `changes`; `diff.json` in the report artifact.

## 0.2.0

- `pxta check`: audit a site, or judge a saved `findings.json`, and exit 1
  when it breaks the rules. Exit codes 0, 1, 2 (usage or rules file),
  3 (audit could not run), 130.
- Rules file (JSON): `fail_on` severity, `fail_codes`, tracker allow and
  block lists, `require_banner`, and `allow` exceptions with a required
  reason and an optional `until` date. Defaults fail on medium and above and
  on `banner-not-handled`.
- Output as text, GitHub Actions annotations (`--format github`) and a
  Markdown summary (`--summary`), plus `check.json` in the report folder.
- `--redact` on `audit` and `check`: personal values replaced by REDACTED in
  every report file, in every encoding PXTA reads, with a scan of the written
  files that fails the run, and removes the report and working files, if one
  is left. PXTA's own probe values stay.
- With `--format github`, annotations, the job summary and the log describe
  each problem from its code, tracker, page path and pass and never quote
  captured data, since anyone who can see the run reads them.
- GitHub Action (`uses: softdevstudio/pxta@v0.2.0`), described in ACTION.md.
  It runs the pxta release it is pinned to and uploads only the report files.
  Tested on Linux and macOS runners with real audits, and on Windows with
  saved findings.
- New problem codes in check results: `tracker-not-allowed`,
  `tracker-blocked`, `no-banner`. Finding codes are unchanged.

## 0.1.0

First release.

- `pxta audit <url>` crawls a site in headless Chrome, Chromium or Edge and
  loads every page three times: with the consent banner unanswered, after
  rejecting, and after accepting.
- Records every request a page sends, including requests from iframes and
  workers and beacons sent while the page is being left.
- Recognises ten trackers: Meta Pixel, Google Analytics 4, Google Ads,
  Google Tag Manager, TikTok Pixel, LinkedIn Insight Tag, Microsoft UET,
  Pinterest Tag, Snap Pixel and the X Pixel. Other third-party beacons are
  listed as unclassified.
- Handles OneTrust, Cookiebot, Didomi and Usercentrics banners, and generic
  banners by the words on their buttons, in the page or in an iframe.
- Finds email addresses in any encoding (plain, URL-encoded, double-encoded,
  base64, inside JSON, inside the page address), hashes of known addresses,
  hashed customer fields, phone numbers, names, user IDs, search terms, and
  page addresses about health, money trouble or customer accounts.
- Reads Google Consent Mode from requests and flags "granted" after a
  reject, and "denied" with personal data still sent.
- Writes a self-contained `report.html`, `findings.json` and `requests.har`.
- Restarts the browser if it crashes mid-crawl; `--resume` carries on an
  interrupted audit.
- Answers `alert()`, `confirm()`, `prompt()` and leave-page dialogs, and
  gives every page one deadline, so a page can't stall the audit.
- Follows a start address that redirects (to `www.`, or from http to https)
  and keeps crawling the site where it landed.
- Keeps at most 5,000 requests per page load and 256 KB of each request
  body, so a hostile page can't fill memory.
- The unanswered pass always runs, since it finds the pages; `--passes`
  picks which passes are reported.

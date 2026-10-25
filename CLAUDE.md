# PXTA: where the next session starts

PXTA (Pixel Tracking Audit) crawls a site in headless Chrome, loads every
page with the consent banner unanswered, after reject and after accept, and
reports what tracking pixels send. Go, standard library only, one binary.

- `cdp.go` is a small WebSocket + DevTools client (no chromedp: the Go
  module proxy is blocked in Claude's sandbox, and stdlib keeps the binary
  simple). `browser.go` finds and starts Chrome/Chromium/Edge.
- `capture.go` records every request of a page, its iframes and workers
  (flattened auto-attach), fires the leave events before navigating away.
- `consent.go` holds the in-page JavaScript that finds and answers banners
  (OneTrust, Cookiebot, Didomi, Usercentrics, generic, in any frame).
- `audit.go` runs the crawl and the passes, checkpoints to `state.json`
  after every page (`--resume`), restarts a crashed browser.
- `catalog/*.json` is the tracker catalog (embedded). `decode.go` unpacks
  values, `rules.go` finds leaks, `analyze.go` makes findings,
  `output.go` + `report.html.tmpl` write report.html, findings.json and
  requests.har. `cmd/pxta` is the CLI.
- Browser tests (`browser_test.go`) audit fixture sites in `testdata/hosts`
  through `fixtures_test.go`: a local TLS server answers for every host and
  Chrome is pointed at it with `--host-resolver-rules`. Stand-in tracker and
  consent scripts copy endpoints, IDs and APIs; they are not vendor code.

Site repo: github.com/photozeitgeist/pxta.com (Hugo, Launch template,
content and config values only; never touch the theme).

## Workflow (low maintenance)

- Pull before working: ChatGPT/Codex also works on this repo (see AGENTS.md).
- The owner does not publish releases. Raise the version in `VERSION` and
  `version.go`, add a `CHANGELOG.md` section, push to main. When CI is
  green, `release.yml` builds Linux/macOS/Windows archives, smoke-tests them
  (including a real audit in the runner's Chrome), tags `vX.Y.Z` and
  publishes. Then watch the run, check the release files and links, and run
  a downloaded binary.
- Chrome: Claude's sandbox has Chrome for Testing at /opt/google/chrome/chrome
  (not on PATH; FindBrowser finds it). The sandbox has an HTTPS proxy in the
  environment, so the fixtures start Chrome with `--no-proxy-server`.
- Every number on the site comes from `test/results/`, written by
  `scripts/record-results.sh` (needs a browser). Re-record after any change
  that could move a number, and update the site from the new files. The
  gallery reports on pxta.com are copied from `test/results/gallery`.
- An independent review agent looks at code and site before a release is
  called done.
- main is the default branch. No side branches.
- GitHub job logs can't be downloaded from these sessions, but annotations
  can. Workflows print `::error::` lines for that reason. Read the real
  error before any rerun; at most two fix-and-retry rounds on one failure,
  then stop and report what's known and the options.
- Don't push to main while a release run is going (the release must tag
  main's head).
- Finding codes in `analyze.go` are a public interface: never rename one.
  Add new codes instead, and document them in README.md.

## State

0.1.0 (2026-10-25): audit with three consent passes, ten trackers,
four consent platforms plus generic and iframe banners, data rules,
Consent Mode, report.html/findings.json/requests.har, crash restart and
resume, sample report gallery. Before release, an independent review
found dialogs hanging the audit, a lone OK button taken for a banner, false
sensitive words, redirecting start addresses crawling one page, image names
read as emails and substring search matches; all fixed with tests.

## Gaps and to-do

Known gaps, not planned yet:

- No `pxta check`, `pxta diff` or logged-in pages yet (see Next).
- No form submission.
- No `pxta browser install`: users need Chrome, Chromium or Edge installed.
- Server-side tracking is invisible to a browser by design.
- Sensitive-word lists are English with a few other languages, built in;
  no `--words` file yet.
- First-party proxied trackers (server-side GTM on the site's own domain)
  are not recognised unless they carry personal data to another site.
- The catalog's plan document said YAML; it is JSON, because the standard
  library has no YAML parser.

## Next

Approved by the owner on 2026-10-25, in this order:

1. `pxta check`: CI exit codes and a rules file, so a build fails when a
   tag fires before consent or personal data goes out. Ship a GitHub
   Action wrapper with it, and `--redact` for reports that get shared.
2. `pxta diff`: compare two audits (findings.json) and list what's new,
   what's gone and which trackers changed behaviour.
3. Logged-in pages: sign in with a recorded session or cookie file and
   audit pages behind a login (form submission stays out unless the
   owner asks).

Each is its own release, through the normal workflow above. Ask the owner
before starting each one.

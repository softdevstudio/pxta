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
- The release runs after *any* CI run on main completes, and builds the
  commit that CI run tested. Raise VERSION only in a commit you want
  released.
- While `scripts/record-results.sh` runs, don't `git pull --autostash` or
  stash in this repo: it rewrites test/results under the running tests and
  the log ends up in a deleted file.
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
Released as v0.1.0 on 2026-10-25 (tag on b5d2b33; the commits after it only add
test results, the release workflow and a README wording change). The
released Linux binary was downloaded, checked against SHA256SUMS and run
for a real audit.

## Done: 0.2.0, `pxta check`, rules file, `--redact`, Action (released 2026-10-31)

Approved by YK on 2026-10-31 as item 1, Phase A of softdev-plan.md in
photozeitgeist/jollyroger.biz. Phase B (`pxta diff`) waits for his go.

What and why: a build should fail when a tag fires before consent or
personal data goes out, and reports from CI get shared, so they need a mode
with the personal values taken out.

Design decisions:
- `pxta check <url> [audit options]` runs an audit then judges it;
  `pxta check --findings findings.json` judges an earlier audit (no browser).
  Exit codes: 0 pass, 1 rule broken, 2 usage or rules-file error,
  3 the audit could not run, 130 stopped.
- Rules file is JSON (stdlib only, like the catalog): `fail_on` severity
  (default medium: anything before consent or after reject fails),
  `fail_codes` (default banner-not-handled, so a check that could not run
  its reject pass never passes quietly), `trackers.allow` / `trackers.block`,
  `require_banner`, and `allow` exceptions that must carry a `reason` and
  may carry `until` (YYYY-MM-DD; expired ones stop matching and are listed).
  Unknown fields, codes or severities are errors, not ignored.
- Output: text, `--format github` (::error annotations), `--summary FILE`
  (Markdown, appended, for $GITHUB_STEP_SUMMARY), check.json in --out.
- `--redact` (audit and check): personal values found anywhere in the
  results (email addresses other than PXTA's own probe, their hashes,
  hashed customer fields, phone numbers, names, user and client IDs,
  addresses given with --email) are replaced by REDACTED in findings.json,
  report.html and requests.har, in raw, URL-encoded, JSON-escaped and
  base64-carried forms. Values under 8 characters match only as whole
  words; names under 3 and IDs under 6 characters are not redacted. PXTA's
  fixed fields (codes, tracker IDs, timestamps) are never touched. Page
  addresses are redacted before Analyze shortens them for sentences. The probe values
  PXTA types itself (pxta-probe@example.com, Pat Probe, +1 555 0100 123) stay:
  they are the evidence. After writing, every file is scanned again and the
  run fails rather than leave a value behind. Finding counts don't change.
  In prose (page titles, sentences) only values of 8+ characters, email
  addresses and personal unclassified hosts are replaced; query keys are
  never redacted (they are the tag's field names).
- Public CI output (annotations, step summary, the job log with
  `--format github`) is built by `PublicLine` from code, tracker, page path
  (`PublicPath`) and pass, never from a sentence; unclassified trackers show
  as "unclassified". Second review (2026-10-31) found the sentence filter
  leaking; this replaced it.
- GitHub Action: action.yml in the repo root, downloads the release for the
  runner, checks SHA256SUMS, runs `pxta check`, writes the step summary,
  uploads the report as an artifact. ACTION.md describes the pattern so
  other projects copy it (softdev-plan.md section 3).
- go.mod stays at go 1.24: Claude's sandbox has only Go 1.24.7 and can't
  download a newer toolchain, and release builds already use the current
  stable Go. Raise it when the sandbox has 1.26.

Steps:
1. [x] check.go: rules, evaluation, outputs; unit tests
2. [x] redact.go: redaction and the after-write scan; unit tests
3. [x] CLI: `check`, `--redact` on audit and check; CLI tests
4. [x] browser tests: shop fails check, bakery passes, redacted shop and
       encodings reports hold no personal value
5. [x] action.yml, ACTION.md, action test workflow
6. [x] README, CHANGELOG, independent review (two rounds), fixes, recording
       (2026-10-31: 90 tests and subtests passed, gallery numbers unchanged)
7. [x] release 0.2.0 through the workflow (its first real run), check assets
       (v0.2.0 on e71524f; Linux binary checked against SHA256SUMS and run;
       action-test download job passed, pinned and latest)
8. [x] pxta.com post, softdevstudio.com note, softdev-plan.md status

All steps done. Next is Phase B, `pxta diff`; ask YK first.

## In progress: 0.3.0, `pxta diff`

Approved by YK on 2026-10-31 ("Phase b"), item 1 Phase B of softdev-plan.md.

What and why: a tag-manager change or a deploy can start a tag before
consent without anyone touching the code. `pxta diff old.json new.json`
says what changed between two audits, so a team can see what the change
added or fixed, and CI can fail on what is new rather than on old,
accepted problems.

Design decisions:
- Input: two findings.json files (`ReadResult`). Pages are compared by
  path, so staging against production works; different sites give a
  warning, not an error. A redacted and an unredacted file are refused
  (exit 2): pages wouldn't match and diff.json would mix their data.
- Findings are matched by code, pass, page path, tracker, and for leaks
  the rule plus the parameter shape (personal data; `paramShape` drops
  `body.N>` and `[N]`), the category (sensitive page; the value is the full
  address or title) or the term (search). Consent Mode findings are keyed
  without leaks, as Analyze keys them. Values like client IDs change every
  run, so they are not part of the match. `tracker-present` rows are left
  to the tracker section.
- Sections: new findings; gone findings; findings on pages only one audit
  visited in that pass ("not compared", never new or fixed; `--new-pages`
  counts pages no old pass reached as new); coverage problems (a pass the
  old audit ran and the new one didn't, a new audit with no good page);
  tracker behaviour per pass (new tracker, gone tracker, starts or stops
  sending data in a pass, more or fewer pages); banner changes (found,
  platform, problems); counts by severity, old and new.
- Exit codes: 0 no change, 1 changes, 2 usage, 3 a file couldn't be read.
  `--fail-on SEVERITY` exits 1 for a new finding at that severity or
  above, and at any threshold for a coverage problem, a banner that's gone,
  a new banner problem or a new banner-not-handled. Other tracker and
  banner changes report without failing.
- Output: text; `--format json` (diff.json shape, stable keys);
  `--format github` (an annotation per new finding, built with
  `PublicLine`); `--summary FILE` (Markdown, from public lines only).
- Action: inputs `baseline` (an earlier findings.json) and
  `baseline-fail-on`; after the check, the action diffs the new audit
  against the baseline, adds it to the job summary and sets outputs
  `diff-exit-code` and `changes`. With `baseline-fail-on`, the diff
  decides the step (the check's own verdict is ignored, so known problems
  don't fail it); without it, the diff only reports.
- First review (2026-10-31) found staging/production and batched-hit
  noise, the Action failing on known problems, broken audits passing, new
  pages counted as new, wrong tracker kinds, Consent Mode flapping and an
  unredacted baseline reaching diff.json; all fixed with tests.
- A finding on a page the old audit didn't reach in that pass is new
  (`Unseen`) when its page-free signature (code, pass, tracker, leak shape)
  is nowhere in the old audit; otherwise not compared. Second review
  (2026-10-31) found that without this the Action missed a new leak on a
  new page. Gaining a banner (lost no-banner pass) is not lost coverage.
- Planted-change fixture: www.tidewaterbakery-next.test, the bakery with
  one change: the X Pixel loads on /menu without waiting for consent. The
  browser test diffs the two audits and expects exactly that change.

Steps:
1. [x] diff.go: matching, sections, outputs; unit tests
2. [x] CLI `diff`; CLI tests
3. [x] fixture and browser test (exactly the planted change)
4. [x] Action inputs and action-test cases
5. [ ] README, ACTION.md, CHANGELOG, independent review, fixes, recording
6. [ ] release 0.3.0 through the workflow, check assets, download job
7. [ ] pxta.com post and pages, softdevstudio.com note, softdev-plan.md

## Gaps and to-do

Known gaps, not planned yet:

- No `pxta diff` yet (see Next).
- Check problems about trackers (`tracker-not-allowed`, `tracker-blocked`,
  `no-banner`) are judged once per site, not per page or pass.
- No logged-in pages or form submission: the owner left these out of the
  plan on 2026-10-25.
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

1. Done in 0.2.0: `pxta check`, rules file, GitHub Action, `--redact`.
2. `pxta diff`: compare two audits (findings.json) and list what's new,
   what's gone and which trackers changed behaviour.

Each is its own release, through the normal workflow above. Ask the owner
before starting each one.

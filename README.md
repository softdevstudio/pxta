# PXTA: Pixel Tracking Audit

PXTA crawls a website in a real browser and writes down what every tracking
pixel sends, where it sends it, and whether it fired before the visitor
answered the cookie banner. It answers three questions about any site:

1. Which tracking pixels are on which pages?
2. What fires before the consent banner is answered, and what still fires
   after the visitor says no?
3. What data actually leaves the browser?

The answer is evidence, not a score. A finding reads like this:

> On /checkout/confirm?order=10442&email=jane@example.com, the Meta Pixel
> sent an email address inside the page address before the consent banner
> was answered.

Each finding comes with the request that carried the data, every decoded
field, the time, the consent state at that moment, and a command that
reproduces it. PXTA is one program, free and open source under the Apache
License 2.0. Site: [pxta.com](https://pxta.com).

## Install

Download the archive for your system from the
[latest release](https://github.com/softdevstudio/pxta/releases/latest),
unpack it and put `pxta` on your PATH. PXTA drives a browser you already
have: Google Chrome, Chromium or Microsoft Edge. It finds the usual install
locations by itself; otherwise pass `--browser /path/to/chrome` or set
`PXTA_BROWSER`.

Or build it with Go 1.24 or later. PXTA uses only the Go standard library:

```sh
go install github.com/softdevstudio/pxta/cmd/pxta@latest
```

## Quick start

```sh
pxta audit https://www.example.com
```

PXTA visits up to 20 pages, three links deep, and writes three files to
`pxta-report/`:

| File | What it is |
|---|---|
| `report.html` | The report: findings first, then the trackers on the site, how each one behaves with the consent banner, the pages visited and the method. One file with nothing loaded from anywhere else, so it can be emailed or filed as it is. |
| `findings.json` | The same data for scripts, dashboards and ticket systems. |
| `requests.har` | Every request the pages sent, in the HAR format browsers and proxies read. The report prints its SHA-256, so the evidence can be checked against it later. |

The summary on the terminal looks like this (from the Harbor & Pine sample in
[test/results/gallery](test/results/gallery), shortened):

```
https://www.harborpine.test/: 24 high, 26 medium, 12 low, 9 for information
Consent banner from OneTrust
  HIGH   On /checkout/confirm?order=10442&email=jane@example.com, Google Analytics 4 sent an email address inside the page address before the consent banner was answered.
  HIGH   On /checkout/confirm?order=10442&email=jane@example.com, the Meta Pixel sent an email address inside the page address before the consent banner was answered.
  HIGH   On /checkout/confirm?order=10442&email=jane@example.com, the Meta Pixel sent a SHA-256 hash of the email address jane@example.com before the consent banner was answered.
  ...
Trackers: Google Analytics 4, Meta Pixel, Pinterest Tag
Report: /home/you/pxta-report/report.html
```

## How an audit runs

1. **Crawl.** PXTA starts at the address you give, follows links on the same
   site (and a sitemap if you pass `--sitemap`), and respects robots.txt.
   Links that would sign someone out or download a file are skipped.
2. **Three passes.** If the site shows a consent banner, every page is loaded
   three times, each time in a fresh browser profile:
   - **Banner not answered.** Anything a tracker sends here fired before
     consent.
   - **After reject.** PXTA rejects on the start page, then visits every
     page. Anything sent here fired against the visitor's choice.
   - **After accept.** The baseline of what the site sends with consent.

   With no banner, each page is loaded once.
3. **On each page** PXTA waits until no new request has started for two
   seconds (at most 15 seconds a page), scrolls to the bottom, types the
   marker address `pxta-probe@example.com` into email fields without
   submitting anything, and then fires the events a page gets when the
   visitor leaves, so beacons sent on the way out are recorded too.
   Requests from iframes and workers are included.
4. **Analysis.** Every request is matched against the tracker catalog,
   decoded, and run through the data rules.

## Consent banners

PXTA knows these platforms by their own JavaScript objects and markup:

| Platform | Reject | Accept |
|---|---|---|
| OneTrust | the "Reject All" button, else `OneTrust.RejectAll()` | "Accept All", else `OneTrust.AllowAll()` |
| Cookiebot | the "Deny" button, else `submitCustomConsent(false, false, false)` | "Allow all", else `submitCustomConsent(true, true, true)` |
| Didomi | "Disagree", else `Didomi.setUserDisagreeToAll()` | "Agree", else `Didomi.setUserAgreeToAll()` |
| Usercentrics | "Deny", else `UC_UI.denyAllConsents()` | "Accept All", else `UC_UI.acceptAllConsents()` |

Any other banner is found by the words on its buttons ("Reject all",
"Decline", "Only necessary", "Alle ablehnen", "Tout refuser" and more) next
to text about cookies or consent, in the page, in open shadow roots, or
inside an iframe. Banners that appear a few seconds after the page loads are
waited for (`--banner-wait`, six seconds by default). A real click on the
platform's own button comes first; the platform's API is used when the
button can't be reached, for example inside a closed shadow root.

After answering, PXTA checks the banner has gone. If it can't reject or
accept, it says so in the report (`banner-not-handled`) and leaves that pass
out, rather than guess.

## Trackers

`pxta catalog` lists them. Version 0.1 knows:

| Tracker | Collection endpoint |
|---|---|
| Meta Pixel | `facebook.com/tr` |
| Google Analytics 4 | `google-analytics.com/g/collect`, `analytics.google.com/g/collect` |
| Google Ads conversion tag | `googleads.g.doubleclick.net/pagead/viewthroughconversion/`, `googleadservices.com/pagead/conversion/`, `www.google.com/pagead/1p-conversion/` |
| Google Tag Manager | `www.googletagmanager.com/gtm.js` (loader only) |
| TikTok Pixel | `analytics.tiktok.com/api/v2/pixel` |
| LinkedIn Insight Tag | `px.ads.linkedin.com/collect`, `/wa/` |
| Microsoft Advertising UET | `bat.bing.com/action/` |
| Pinterest Tag | `ct.pinterest.com/v3/`, `/user/` |
| Snap Pixel | `tr.snapchat.com/p` |
| X (Twitter) Pixel | `analytics.twitter.com/i/adsct`, `t.co/i/adsct` |

Each entry is a JSON file in [catalog/](catalog/) that says which hosts and
paths belong to the tracker and what its parameters mean. Every entry ships
with a sample request that the tests decode. To add a tracker, or replace a
built-in entry, put JSON files in a folder and pass `--catalog folder`.

A third-party request that isn't in the catalog is still listed, as
"unclassified", when it looks like a beacon (sendBeacon, a POST, or three or
more parameters) or when it carries personal data. So nothing disappears
because the catalog doesn't know it.

## What the rules look for

Every value in a tracker request is decoded first: query strings, form
bodies, JSON bodies, several events in one body, a URL inside a parameter,
JSON inside a parameter, base64 text, and up to three rounds of
percent-encoding. Then the rules run on every value.

| Rule | Finds |
|---|---|
| Email addresses | plain, URL-encoded, double-encoded, base64, inside JSON, inside the page address |
| Email hashes | SHA-256 and MD5 of any address PXTA knows: the ones you pass with `--email`, the marker address it typed, and addresses shown on the site's pages or seen in other requests |
| Hashed customer fields | fields the tag itself labels as a hashed email, phone or name (Meta advanced matching, TikTok, Pinterest, Snap, UET, Google enhanced conversions) |
| Phone numbers and names | in fields named for them (`ph`, `phone`, `fn`, `last_name` and so on) |
| User IDs | the site's own user ID (Google Analytics `uid`) |
| Search terms | the site-search term from the page address (`q`, `s`, `query`, `search` and similar) found anywhere in the request |
| Sensitive pages | a page address or title about health, money trouble, or a checkout or account, sent to a tracker |
| Consent Mode | Google's `gcs` value: "granted" before an answer or after a reject, or "denied" while personal data still goes out |

## Findings

Finding codes are a public interface: they won't be renamed.

| Code | Severity | Meaning |
|---|---|---|
| `personal-data` | high before an answer or after a reject, low after accept | a tracker request carried personal data |
| `sensitive-page` | high, low after accept | a tracker got the address or title of a page about health, money trouble, or a checkout or account |
| `search-term` | high, low after accept | a tracker got what the visitor searched for |
| `consent-mode-granted` | high after a reject, medium before an answer | Google tags reported consent as granted |
| `consent-mode-mismatch` | high, low after accept | Consent Mode said denied, but personal data was still sent |
| `tracker-after-reject` | medium | a tracker sent data after the visitor rejected |
| `tracker-before-consent` | medium | a tracker sent data before the banner was answered, or on a site with no banner |
| `banner-not-handled` | info | PXTA couldn't reject or accept, so that pass is missing |
| `tracker-present` | info | inventory: a tracker sent data from these pages |

Severity is fixed and documented here so it can be argued with. It is not a
legal judgment: PXTA records network traffic and draws no conclusion about
whether a site complies with any law.

## Options

```
pxta audit <url> [options]
  --out folder          where to write the report (default pxta-report)
  --pages n             most pages to visit (default 20)
  --depth n             links deep from the start page (default 3)
  --sitemap url         add pages from a sitemap
  --passes list         consent passes to report: none,reject,accept (default
                        all three); the unanswered pass always runs, to find pages
  --email address       an address whose hashes to look for (repeatable)
  --no-fill             don't type the marker address into email fields
  --wait 15s            longest time on one page
  --idle 2s             a page is done after this long without a new request
  --banner-wait 6s      how long to look for a consent banner
  --delay 1s            pause between page loads
  --ignore-robots       visit pages robots.txt disallows (your own site only)
  --resume              carry on an interrupted audit from --out
  --browser path        Chrome, Chromium or Edge to use
  --catalog folder      extra tracker catalog files
  --quiet               print only the summary
  --redact              replace personal values in the report with REDACTED
```

PXTA saves its progress after every page. If an audit is interrupted, run
the same command with `--resume`. If the browser crashes in the middle of a
crawl, PXTA starts it again, makes the pass's consent choice again, and
carries on.

`pxta audit` exits with 0 when the audit finished (whatever it found), 2 on
an error, and 130 when interrupted.

## pxta check

`pxta check` runs the same audit and then fails, with exit code 1, when the
site breaks the rules. It is made for CI: a scheduled job, or a job after
each deploy, that goes red when a tag starts firing before consent.

```sh
pxta check https://www.example.com --rules pxta-rules.json
pxta check --findings pxta-report/findings.json --rules pxta-rules.json
```

The second form judges an audit that already ran, with no browser.
`pxta check` takes every `pxta audit` option, plus:

```
  --rules file          rules file (JSON)
  --findings file       judge this findings.json instead of auditing
  --format github       print problems as GitHub Actions annotations too
  --summary file        append a Markdown summary (use $GITHUB_STEP_SUMMARY)
```

Exit codes: 0 the rules hold, 1 a rule is broken, 2 a usage or rules-file
error, 3 the audit could not run, 130 interrupted. After an audit it also
writes `check.json` next to the report.

Without a rules file, a check fails on any medium or high finding (anything
sent before the banner was answered or after a reject, and any personal
data before consent) and on `banner-not-handled`, so a check that couldn't
run its reject pass never passes quietly. A rules file changes that:

```json
{
  "fail_on": "medium",
  "fail_codes": ["banner-not-handled"],
  "require_banner": true,
  "trackers": {
    "allow": ["google-analytics-4", "meta-pixel"],
    "block": ["tiktok-pixel"]
  },
  "allow": [
    {
      "code": "tracker-before-consent",
      "tracker": "google-analytics-4",
      "page": "/blog/*",
      "reason": "Consent Mode cookieless ping, approved by legal (ticket 812)",
      "until": "2026-12-31"
    }
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `fail_on` | `medium` | lowest severity that fails: `high`, `medium`, `low`, `info` or `never` |
| `fail_codes` | `["banner-not-handled"]` | codes that fail whatever their severity; `[]` for none |
| `require_banner` | `false` | fail a site that has trackers but no consent banner (`no-banner`) |
| `trackers.allow` | | when set, any other tracker on the site fails (`tracker-not-allowed`) |
| `trackers.block` | | these trackers fail wherever they appear (`tracker-blocked`) |
| `allow` | | exceptions: `code`, `tracker`, `page` (a path, `*` wildcards, `/blog/*` covers everything under /blog/) and `pass` (`none`, `reject`, `accept` or `nobanner`) narrow it; `reason` is required; `until` (YYYY-MM-DD) is the last day it applies |

Allowed problems are still listed, with their reason. An allow entry past
its `until` date stops matching and is reported, so exceptions don't outlive
the decision behind them. Unknown fields, codes, severities, page patterns
and tracker IDs are errors (`pxta catalog` lists the IDs; a beacon PXTA
doesn't recognise is `unclassified:<host>`, so an allow list needs those
too).

`tracker-not-allowed`, `tracker-blocked` and `no-banner` are judged once per
site, not per page: they carry no pass, and the page they name is the first
page in alphabetical order where the tracker appeared. An allow entry for
them should name the code and tracker only.

### GitHub Action

```yaml
- uses: softdevstudio/pxta@v0.3.0
  with:
    url: https://www.example.com/
    rules: pxta-rules.json
```

The action downloads the PXTA release it is pinned to, checks it against
SHA256SUMS, runs `pxta check`, puts each problem on the run as an
annotation and the summary on the job page, and uploads the report files
(redacted by default). Inputs and outputs are in [ACTION.md](ACTION.md).

With `baseline` set to an earlier `findings.json` (from the last run's
artifact, or one kept in the repo), the action also runs `pxta diff` and
adds the changes to the job summary. With `baseline-fail-on: medium` the
comparison decides the step: a new medium or high finding fails it, and so
does a lost consent pass or a banner that's gone, while problems the
baseline already has don't. Known problems stop blocking the build; new
ones do.

## pxta diff

`pxta diff` compares two audits and lists what changed: a tag-manager
change, a deploy or a new consent setup, seen as findings that are new or
gone, trackers that start or stop sending data in a pass, and banner
changes.

```sh
pxta diff last-month/findings.json pxta-report/findings.json
pxta diff staging/findings.json production/findings.json --fail-on medium
```

```
  --fail-on severity    exit 1 only for a new finding at this severity or
                        above (high, medium, low, info), or never; the
                        default is any change
  --new-pages           count findings on pages the old audit never
                        reached as new
  --format json|github  print the diff as JSON, or as GitHub annotations
  --summary file        append a Markdown summary (use $GITHUB_STEP_SUMMARY)
  --out file            also write the diff as JSON to this file
```

Exit codes: 0 no change, 1 changes (with `--fail-on`, see below), 2 a
usage error or a redacted audit compared with an unredacted one, 3 a file
couldn't be read or written.

How findings are matched. Two findings are the same when they have the
same code, pass, page path and tracker, and, for a leak:

- personal data: the same rule and parameter (`em`, `ud[em]`). Batch line
  and array numbers are left out, so `dl` in a hit's address and
  `body.3>dl` in a batched hit are the same parameter.
- a sensitive page: the same category group ("health" of "health:
  condition") and parameter, not the address or title the tag sent, so
  staging and production compare.
- a search term: the same term.

Client IDs, session IDs and hashes of a test address change from one run
to the next, so values aren't part of the match. Consent Mode findings are
matched without their leaks.

What isn't compared. Pages are compared by path; a warning says when the
sites differ. A finding on a page the other audit didn't visit in the same
pass is listed as not compared, never as fixed, so a crawl that reached
one page more or one page less doesn't look like a change. It still counts
as new when nothing like it (the same code, pass, tracker and leak)
happened on any page of the old audit: a pixel that starts sending email
addresses on a new sign-up page is new, the same pixel firing on one more
blog post isn't. With `--new-pages`, every finding on a page no pass of the
old audit reached counts as new. Run both audits with the same `--passes`:
a pass the new audit didn't run counts as lost (see below). A changed count of the same finding is listed
but isn't a change. A redacted audit can't be compared with an unredacted
one: their pages don't match, and the diff would carry the unredacted
audit's data next to the redacted one's.

What fails `--fail-on`. A new finding at that severity or above, and,
whatever the severity, the things that hide or are consent regressions: a
pass the old audit ran that the new one didn't (a reject or accept button
PXTA can no longer press, or fewer `--passes`), a new audit that visited no
page without an error, a banner that's gone, or a new banner problem. A
site that gains a banner loses its no-banner pass; that is reported as a
banner change and doesn't fail.

Tracker changes have kinds, like finding codes: `started` (sends data in a
pass where it sent none), `stopped`, `more-pages`, `fewer-pages` and
`other-pages` (as many pages, not the same ones). They are in the
`tracker_changes` list of the JSON output. An unclassified tracker is known
by its host, so a collector on a rotating host shows as one gone and one
new.

With `--format github`, the annotations, the summary and the log are built
the same way as `pxta check`'s: from codes, trackers, page paths and
passes, never quoting what the site sent, and with hosts instead of full
start addresses. The JSON output holds the sentences, like `check.json`.

## Redacted reports

A report can hold the personal data the audited site leaked, and reports
from CI get shared. `--redact` (on `audit` and `check`) replaces the
personal values with `REDACTED` in `findings.json`, `report.html`,
`requests.har` and `check.json`: email addresses and their hashes, hashed
customer fields, phone numbers, names, the site's user IDs and tracker
client IDs. Values are found plain, URL-encoded, double encoded, inside
JSON, inside base64 and in URL path segments; a parameter, path segment or
body that hides one in a form PXTA can only decode goes whole. Page
addresses are redacted before they are shortened for sentences, so no
cut-off piece of a value is left.

Short values (first names, short IDs) are replaced only where they stand
as a whole word, so a visitor called Tim doesn't turn "time" into
"REDACTEDe". Names shorter than three letters and IDs shorter than six
characters are left alone. In running text, such as page titles, only
values of eight characters or more and email addresses are replaced, since
a first name like Will can't be told from the word; PXTA's own sentences
never quote a name, phone number or ID.

What stays: the trackers, endpoints, parameter names, page paths, search
terms and sensitive-page words (they describe the site, not a person),
PXTA's own codes, tracker IDs and timestamps, and the marker values PXTA
types itself (`pxta-probe@example.com`, Pat Probe, +1 555 0100 123), which
are the evidence that a tag scraped a form. The findings, their codes and
their counts are the same as without `--redact`.

After writing, PXTA reads the files back and looks again: for long values
and any email address in the raw text in every encoding, for short values
in each JSON string, and in every request of `requests.har` decoded the
way the audit decodes it. If one is left, the audit fails and the report
and the working files (`state.json`, `requests.jsonl`) are removed, rather
than leave a half-redacted report for someone to pass on. An audit
interrupted with Ctrl-C keeps its working files, so `--resume` still works.

GitHub annotations, the job summary and the job log are public to anyone
who can see the run, so with `--format github` `pxta check` never quotes
what the site sent there, with or without `--redact`. Each problem is
written from its code, tracker, page path and pass ("Meta Pixel sent
personal data on /checkout (before an answer)."): queries are cut, a path
part that looks like an address, a hash or an encoded value becomes
`REDACTED`, and an unclassified tracker is named only as unclassified. The
full sentences are in `check.json` and the report.

## What PXTA can't see

- **Server-side tracking.** Data a site sends from its own servers, such as
  conversion APIs and server-side tag managers, never passes through the
  browser.
- **Pages behind a login,** and anything that happens only after a click
  PXTA doesn't make. PXTA doesn't sign in or submit forms.
- **Trackers it doesn't know**, beyond the unclassified-beacon rule above.

The report says this in its Method section, so a clean report is never read
as a clean bill of health.

## Privacy and politeness

PXTA visits public pages the way a visitor would. It identifies itself in
the user agent (`pxta/<version> (+https://pxta.com)`), follows robots.txt unless
told otherwise, waits a second between pages, and sends nothing anywhere
itself: no telemetry, and the reports stay on your machine. The reports can
hold personal data the audited site leaked, so treat them as you would the
site's own logs, or write them with `--redact`.

## How it was tested

The tests run fixture sites in Chrome: a local HTTPS server answers for
every host name, and stand-in scripts send what the real tags send, to the
same endpoints. The stand-ins are written for the tests; they are not the
vendors' code. The fixtures cover a leaky shop, a clinic, a site set up
correctly, a site whose banner fails on reject, each consent platform set
up right and wrong, a banner that shows late and one inside an iframe,
Consent Mode reporting denied while identifiers still go out, an email
address in ten encodings, trackers that load late (after a timer, on scroll,
from a tag manager), requests from an iframe, a worker and a beacon sent on
the way out, a site with no trackers, and a 500-page crawl with the browser
killed in the middle. The recorded results are in
[test/results](test/results), and the sample reports from the fixture sites
are in [test/results/gallery](test/results/gallery).

```sh
go test ./...                      # unit tests, and browser tests if a browser is installed
scripts/record-results.sh          # everything, recorded to test/results
```

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

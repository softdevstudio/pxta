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
```

PXTA saves its progress after every page. If an audit is interrupted, run
the same command with `--resume`. If the browser crashes in the middle of a
crawl, PXTA starts it again, makes the pass's consent choice again, and
carries on.

`pxta audit` exits with 0 when the audit finished (whatever it found), 2 on
an error, and 130 when interrupted.

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
the user agent (`pxta/0.1.0 (+https://pxta.com)`), follows robots.txt unless
told otherwise, waits a second between pages, and sends nothing anywhere
itself: no telemetry, and the reports stay on your machine. The reports can
hold personal data the audited site leaked, so treat them as you would the
site's own logs.

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

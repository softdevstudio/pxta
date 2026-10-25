# Changelog

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

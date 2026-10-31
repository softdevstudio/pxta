package pxta

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// diffFixture is a small audit: three pages in three passes, GA4 after
// accept, the Meta Pixel sending a hashed email on /order before consent.
func diffFixture() *Result {
	var pages []Visit
	for _, pass := range []string{PassNone, PassReject, PassAccept} {
		for i, p := range []string{"/", "/menu", "/order"} {
			u := "https://shop.test" + p
			pages = append(pages, Visit{Pass: pass, Page: i, URL: u, FinalURL: u})
		}
	}
	pd := &Finding{Code: CodePersonalData, Severity: SevHigh, Pass: PassNone, Page: "/order", Tracker: "meta-pixel", Name: "Meta Pixel",
		Sentence: "On /order, the Meta Pixel sent a SHA-256 hash of the email address jane@example.com before the consent banner was answered.", Count: 2,
		Evidence: Evidence{Highlight: []Leak{{Rule: RuleEmailHash, Key: "em", Value: sha("jane@example.com")}}}}
	bc := &Finding{Code: CodeTrackerBeforeConsent, Severity: SevMedium, Pass: PassNone, Page: "/order", Tracker: "meta-pixel", Name: "Meta Pixel",
		Sentence: "On /order, the Meta Pixel sent a PageView event before the consent banner was answered.", Count: 1}
	return &Result{Tool: "pxta", Version: "0.3.0", Site: "https://shop.test/", Started: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		Banner: Banner{Found: true, Platform: "onetrust"}, Passes: []string{PassNone, PassReject, PassAccept}, Pages: pages,
		Analysis: &Analysis{
			Findings: []*Finding{pd, bc,
				{Code: CodeTrackerPresent, Severity: SevInfo, Pass: PassAccept, Tracker: "google-analytics-4", Count: 3}},
			Trackers: []TrackerUse{
				{ID: "google-analytics-4", Name: "Google Analytics 4", Fired: map[string][]string{PassAccept: {"/", "/menu", "/order"}}},
				{ID: "meta-pixel", Name: "Meta Pixel", Fired: map[string][]string{PassNone: {"/order"}, PassAccept: {"/order"}}},
			},
		}}
}

func mustDiff(t *testing.T, old, cur *Result, failOn string) *DiffResult {
	t.Helper()
	d, err := Diff(old, cur, DiffOptions{FailOn: failOn})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDiffSame(t *testing.T) {
	d := mustDiff(t, diffFixture(), diffFixture(), "")
	if d.Changed || d.Fail || len(d.Added)+len(d.Removed)+len(d.Trackers)+len(d.Banner)+len(d.Counted)+len(d.Skipped) != 0 {
		t.Fatalf("identical audits differ: %+v", d)
	}
	var b bytes.Buffer
	d.WriteText(&b, false)
	if !strings.Contains(b.String(), "pxta diff: no change") {
		t.Error(b.String())
	}
}

// The planted change: the X Pixel starts on /menu before consent.
func TestDiffPlanted(t *testing.T) {
	cur := diffFixture()
	cur.Findings = append(cur.Findings, &Finding{Code: CodeTrackerBeforeConsent, Severity: SevMedium, Pass: PassNone, Page: "/menu",
		Tracker: "x-pixel", Name: "X Pixel", Sentence: "On /menu, the X Pixel sent a request before the consent banner was answered.", Count: 1})
	cur.Trackers = append(cur.Trackers, TrackerUse{ID: "x-pixel", Name: "X Pixel", Fired: map[string][]string{PassNone: {"/menu"}}})
	d := mustDiff(t, diffFixture(), cur, "")
	if len(d.Added) != 1 || d.Added[0].Tracker != "x-pixel" || d.Added[0].Page != "/menu" || len(d.Removed) != 0 {
		t.Fatalf("added %+v removed %+v", d.Added, d.Removed)
	}
	if len(d.Trackers) != 1 || d.Trackers[0].Kind != TrackerStarted || d.Trackers[0].Pass != PassNone {
		t.Fatalf("trackers %+v", d.Trackers)
	}
	if !strings.Contains(d.Trackers[0].Sentence, "The X Pixel now sends data before the consent banner was answered, on /menu") {
		t.Errorf("sentence %q", d.Trackers[0].Sentence)
	}
	if !d.Fail {
		t.Error("any change should fail by default")
	}
	if mustDiff(t, diffFixture(), cur, SevHigh).Fail {
		t.Error("fail-on high failed on a medium finding")
	}
	if !mustDiff(t, diffFixture(), cur, SevMedium).Fail {
		t.Error("fail-on medium passed a medium finding")
	}
	if mustDiff(t, diffFixture(), cur, "never").Fail {
		t.Error("never failed")
	}
	// The other way round, the same change is gone.
	back := mustDiff(t, cur, diffFixture(), "")
	if len(back.Removed) != 1 || len(back.Added) != 0 || back.Trackers[0].Kind != TrackerStopped {
		t.Fatalf("reverse: %+v %+v", back.Removed, back.Trackers)
	}
}

// Client IDs and hashes change between runs; the same leak through the same
// parameter is the same finding. Another parameter is a new one.
func TestDiffMatching(t *testing.T) {
	cur := diffFixture()
	cur.Findings[0] = func() *Finding { f := *cur.Findings[0]; return &f }()
	cur.Findings[0].Evidence.Highlight = []Leak{{Rule: RuleEmailHash, Key: "em", Value: sha("someone@example.org")}}
	cur.Findings[0].Count = 5
	d := mustDiff(t, diffFixture(), cur, "")
	if d.Changed || len(d.Counted) != 1 || d.Counted[0].OldCount != 2 || d.Counted[0].Count != 5 {
		t.Fatalf("a new value or count changed the diff: %+v", d)
	}
	cur.Findings[0].Evidence.Highlight[0].Key = "ud[em]"
	if d := mustDiff(t, diffFixture(), cur, ""); len(d.Added) != 1 || len(d.Removed) != 1 {
		t.Fatalf("another parameter: %+v %+v", d.Added, d.Removed)
	}
}

// Findings on pages only one audit reached are not compared, unless the
// page is new to the site (no pass of the old audit visited it).
func TestDiffCoverage(t *testing.T) {
	cur := diffFixture()
	var pages []Visit
	for _, v := range cur.Pages {
		if !(v.Pass == PassNone && v.URL == "https://shop.test/order") {
			pages = append(pages, v)
		}
	}
	cur.Pages = pages
	cur.Findings = cur.Findings[2:] // the /order findings weren't reached
	cur.Trackers[1].Fired = map[string][]string{PassAccept: {"/order"}}
	d := mustDiff(t, diffFixture(), cur, "")
	if len(d.Removed) != 0 || len(d.Skipped) != 2 || len(d.Trackers) != 0 {
		t.Fatalf("unvisited page counted as fixed: removed %+v skipped %+v trackers %+v", d.Removed, d.Skipped, d.Trackers)
	}

	cur = diffFixture()
	for _, pass := range cur.Passes {
		cur.Pages = append(cur.Pages, Visit{Pass: pass, Page: 3, URL: "https://shop.test/careers", FinalURL: "https://shop.test/careers"})
	}
	cur.Findings = append(cur.Findings, &Finding{Code: CodeTrackerBeforeConsent, Severity: SevMedium, Pass: PassNone, Page: "/careers", Tracker: "meta-pixel", Name: "Meta Pixel", Count: 1})
	cur.Trackers[1].Fired[PassNone] = []string{"/order", "/careers"}
	// By default a page the old audit never reached isn't compared when the
	// old audit had the same finding elsewhere: the crawl may simply not
	// have got there.
	d = mustDiff(t, diffFixture(), cur, "")
	if d.Changed || len(d.Skipped) != 1 {
		t.Fatalf("new page compared by default: %+v", d)
	}
	cur.Findings[len(cur.Findings)-1] = &Finding{Code: CodeTrackerAfterReject, Severity: SevHigh, Pass: PassReject, Page: "/careers", Tracker: "meta-pixel", Name: "Meta Pixel", Count: 1}
	cur.Trackers[1].Fired = map[string][]string{PassNone: {"/order"}, PassAccept: {"/order"}, PassReject: {"/careers"}}
	d, _ = Diff(diffFixture(), cur, DiffOptions{NewPages: true})
	if len(d.Added) != 1 || d.Added[0].Page != "/careers" || len(d.Trackers) != 1 || d.Trackers[0].Kind != TrackerStarted {
		t.Fatalf("new page with NewPages: %+v %+v", d.Added, d.Trackers)
	}

	// A pass the old audit ran and the new one didn't is a coverage problem,
	// and fails at any threshold: a broken reject button looks like this.
	cur = diffFixture()
	cur.Passes = []string{PassNone, PassAccept}
	d = mustDiff(t, diffFixture(), cur, SevHigh)
	if len(d.Coverage) != 1 || !strings.Contains(d.Coverage[0], "reject pass") || !d.Fail || len(d.Removed) != 0 {
		t.Fatalf("missing reject pass: %+v", d)
	}
	// So does a new audit that visited nothing.
	cur = diffFixture()
	for i := range cur.Pages {
		cur.Pages[i].Error = "net::ERR_TIMED_OUT"
	}
	cur.Findings = nil
	d = mustDiff(t, diffFixture(), cur, SevHigh)
	if !d.Fail || len(d.Removed) != 0 || len(d.Coverage) != 1 {
		t.Fatalf("all pages errored: %+v", d)
	}
}

func TestDiffBannerAndWarnings(t *testing.T) {
	cur := diffFixture()
	cur.Site = "https://staging.shop-preview.test/?token=jane@example.com"
	cur.Banner = Banner{Found: true, Platform: "cookiebot", Problems: map[string]string{PassReject: "no reject button on /?ref=jane@example.com"}}
	d := mustDiff(t, diffFixture(), cur, "never")
	if len(d.Banner) != 2 || !strings.Contains(d.Banner[0], "from OneTrust to Cookiebot") {
		t.Fatalf("banner %q", d.Banner)
	}
	if len(d.Warnings) != 1 || strings.Contains(d.Warnings[0], "jane") {
		t.Fatalf("warnings %q", d.Warnings)
	}
	if !d.Changed || d.Fail {
		t.Fatalf("changed %v fail %v", d.Changed, d.Fail)
	}
	// A new banner problem, or a banner that's gone, fails at any threshold.
	if !mustDiff(t, diffFixture(), cur, SevHigh).Fail {
		t.Error("a new banner problem passed --fail-on high")
	}
	gone := diffFixture()
	gone.Banner = Banner{}
	if d := mustDiff(t, diffFixture(), gone, SevHigh); !d.Fail || !strings.Contains(d.Banner[0], "is gone") {
		t.Errorf("banner gone: %+v", d.Banner)
	}
	// A redacted audit can't be compared with an unredacted one.
	red := diffFixture()
	red.Redacted = true
	if _, err := Diff(diffFixture(), red, DiffOptions{}); err != ErrRedactionMix {
		t.Errorf("redaction mix: %v", err)
	}
}

// Public output (annotations, summary, the CI log) never quotes captured
// data: not the sentence, not a banner problem, not a page's query.
func TestDiffPublic(t *testing.T) {
	old := diffFixture()
	old.Findings = old.Findings[1:]
	cur := diffFixture()
	cur.Findings[0].Page = "/order?email=jane@example.com"
	for _, r := range []*Result{old, cur} {
		r.Pages = append(r.Pages, Visit{Pass: PassNone, Page: 9, URL: "https://shop.test/order?email=jane@example.com", FinalURL: "https://shop.test/order?email=jane@example.com"})
	}
	cur.Banner.Problems = map[string]string{PassReject: "button text quoted jane@example.com"}
	cur.Trackers[1].Fired[PassReject] = []string{"/order?email=jane@example.com"}
	d := mustDiff(t, old, cur, "")
	var gh, txt bytes.Buffer
	d.WriteGitHub(&gh)
	d.WriteText(&txt, true)
	for name, out := range map[string]string{"annotations": gh.String(), "summary": d.Markdown(), "log": txt.String()} {
		if strings.Contains(out, "jane") || strings.Contains(out, "email=") {
			t.Errorf("%s quotes captured data:\n%s", name, out)
		}
	}
	if !strings.Contains(gh.String(), "::error title=pxta diff new personal-data (meta-pixel)::Meta Pixel sent personal data on /order") {
		t.Errorf("annotations:\n%s", gh.String())
	}
	txt.Reset()
	d.WriteText(&txt, false)
	if !strings.Contains(txt.String(), "jane@example.com") {
		t.Error("the local text lost the sentence")
	}
}

// Second review: matching that must not flap between two audits of the same
// site, and tracker change kinds.
func TestDiffStableMatching(t *testing.T) {
	// A sensitive page is matched by category, not by the address the tag
	// sent, so staging and production compare.
	mk := func(site, value string) *Result {
		r := diffFixture()
		r.Site = site
		r.Findings = append(r.Findings, &Finding{Code: CodeSensitivePage, Severity: SevHigh, Pass: PassNone, Page: "/order", Tracker: "meta-pixel", Count: 1,
			Evidence: Evidence{Highlight: []Leak{{Rule: RuleSensitive, Key: "dl", Value: value, Category: "finance: debt"}}}})
		return r
	}
	if d := mustDiff(t, mk("https://www.shop.test/", "https://www.shop.test/debt-help"), mk("https://staging.shop.test/", "https://staging.shop.test/debt-help"), ""); len(d.Added)+len(d.Removed) != 0 {
		t.Errorf("sensitive page across hosts: %+v %+v", d.Added, d.Removed)
	}
	// Batched GA4 hits: the line that holds the leak varies.
	a, b := diffFixture(), diffFixture()
	a.Findings[0].Evidence.Highlight = []Leak{{Rule: RuleEmail, Key: "body.0>dl"}}
	b.Findings[0] = func() *Finding { f := *b.Findings[0]; return &f }()
	b.Findings[0].Evidence.Highlight = []Leak{{Rule: RuleEmail, Key: "body.3>dl"}}
	if d := mustDiff(t, a, b, ""); len(d.Added)+len(d.Removed) != 0 {
		t.Errorf("batch line: %+v %+v", d.Added, d.Removed)
	}
	for in, want := range map[string]string{"events[2].params.em": "events[].params.em", "body.1>dl": "dl", "dl": "dl", "body.0>ep.email": "ep.email"} {
		if got := paramShape(in); got != want {
			t.Errorf("paramShape(%q) = %q, want %q", in, got, want)
		}
	}
	// Consent Mode mismatches are keyed without their leaks.
	a, b = diffFixture(), diffFixture()
	a.Findings = append(a.Findings, &Finding{Code: CodeConsentModeMismatch, Severity: SevHigh, Pass: PassNone, Page: "/", Tracker: "google-analytics-4", Count: 1,
		Evidence: Evidence{Highlight: []Leak{{Rule: RuleUserID, Key: "uid"}}}})
	b.Findings = append(b.Findings, &Finding{Code: CodeConsentModeMismatch, Severity: SevHigh, Pass: PassNone, Page: "/", Tracker: "google-analytics-4", Count: 1,
		Evidence: Evidence{Highlight: []Leak{{Rule: RuleUserID, Key: "uid"}, {Rule: RuleEmailHash, Key: "em"}}}})
	if d := mustDiff(t, a, b, ""); len(d.Added)+len(d.Removed) != 0 {
		t.Errorf("consent mode mismatch: %+v %+v", d.Added, d.Removed)
	}
}

func TestDiffTrackerKinds(t *testing.T) {
	// The X Pixel sent data after reject on /order before; the new crawl
	// didn't reach /order and the pixel now fires on /menu. It didn't start:
	// it sent data in that pass before.
	old, cur := diffFixture(), diffFixture()
	old.Trackers = append(old.Trackers, TrackerUse{ID: "x-pixel", Name: "X Pixel", Fired: map[string][]string{PassReject: {"/order"}}})
	var pages []Visit
	for _, v := range cur.Pages {
		if !(v.Pass == PassReject && strings.HasSuffix(v.URL, "/order")) {
			pages = append(pages, v)
		}
	}
	cur.Pages = pages
	cur.Trackers = append(cur.Trackers, TrackerUse{ID: "x-pixel", Name: "X Pixel", Fired: map[string][]string{PassReject: {"/menu"}}})
	d := mustDiff(t, old, cur, "")
	if len(d.Trackers) != 1 || d.Trackers[0].Kind != TrackerMoved {
		t.Fatalf("kinds %+v", d.Trackers)
	}
	// Same number of pages, different ones.
	old, cur = diffFixture(), diffFixture()
	old.Trackers[1].Fired[PassNone] = []string{"/order"}
	cur.Trackers[1].Fired[PassNone] = []string{"/menu"}
	d = mustDiff(t, old, cur, "")
	if len(d.Trackers) != 1 || d.Trackers[0].Kind != TrackerMoved || !strings.Contains(d.Trackers[0].Sentence, "on 1 page, was 1; new: /menu; gone: /order") {
		t.Fatalf("moved %+v", d.Trackers)
	}
	if s := d.Trackers[0].publicSentence(); !strings.HasPrefix(s, "The Meta Pixel") {
		t.Errorf("public sentence %q", s)
	}
}

// Second round: a new problem on a page outside the baseline is new when
// nothing like it happened anywhere before; the same pixel on one more page
// isn't. Gaining a banner isn't lost coverage. Tracker kinds follow the
// counts they print.
func TestDiffRoundTwo(t *testing.T) {
	cur := diffFixture()
	cur.Pages = append(cur.Pages, Visit{Pass: PassReject, Page: 7, URL: "https://shop.test/signup", FinalURL: "https://shop.test/signup"})
	cur.Findings = append(cur.Findings,
		&Finding{Code: CodePersonalData, Severity: SevHigh, Pass: PassReject, Page: "/signup", Tracker: "meta-pixel", Count: 1,
			Evidence: Evidence{Highlight: []Leak{{Rule: RuleEmail, Key: "em"}}}},
		// Like /order's before-consent finding: same code, pass, tracker.
		&Finding{Code: CodeTrackerBeforeConsent, Severity: SevMedium, Pass: PassNone, Page: "/signup", Tracker: "meta-pixel", Count: 1})
	cur.Pages = append(cur.Pages, Visit{Pass: PassNone, Page: 7, URL: "https://shop.test/signup", FinalURL: "https://shop.test/signup"})
	d := mustDiff(t, diffFixture(), cur, SevHigh)
	if len(d.Added) != 1 || d.Added[0].Page != "/signup" || !d.Added[0].Unseen || !d.Fail || len(d.Skipped) != 1 {
		t.Fatalf("signup: added %+v skipped %+v fail %v", d.Added, d.Skipped, d.Fail)
	}

	nb := diffFixture()
	nb.Banner = Banner{}
	nb.Passes = []string{PassNoBanner}
	for i := range nb.Pages {
		nb.Pages[i].Pass = PassNoBanner
	}
	nb.Findings = nil
	if d := mustDiff(t, nb, diffFixture(), SevHigh); len(d.Coverage) != 0 || d.Fail || !strings.Contains(strings.Join(d.Banner, " "), "appeared") {
		t.Fatalf("gaining a banner: coverage %q banner %q fail %v", d.Coverage, d.Banner, d.Fail)
	}

	old, cur2 := diffFixture(), diffFixture()
	old.Trackers[1].Fired[PassNone] = []string{"/", "/menu", "/order"}
	cur2.Trackers[1].Fired[PassNone] = []string{"/order", "/new-a", "/new-b", "/new-c"}
	for _, p := range []string{"/new-a", "/new-b", "/new-c"} {
		for _, r := range []*Result{old, cur2} {
			r.Pages = append(r.Pages, Visit{Pass: PassNone, Page: 8, URL: "https://shop.test" + p, FinalURL: "https://shop.test" + p})
		}
	}
	d = mustDiff(t, old, cur2, "")
	if len(d.Trackers) != 1 || d.Trackers[0].Kind != TrackerMore || d.Trackers[0].NewPages != 4 || d.Trackers[0].OldPages != 3 {
		t.Fatalf("kind and counts: %+v", d.Trackers)
	}
}

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

func TestDiffSame(t *testing.T) {
	d := Diff(diffFixture(), diffFixture(), "")
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
	d := Diff(diffFixture(), cur, "")
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
	if Diff(diffFixture(), cur, SevHigh).Fail {
		t.Error("fail-on high failed on a medium finding")
	}
	if !Diff(diffFixture(), cur, SevMedium).Fail {
		t.Error("fail-on medium passed a medium finding")
	}
	if Diff(diffFixture(), cur, "never").Fail {
		t.Error("never failed")
	}
	// The other way round, the same change is gone.
	back := Diff(cur, diffFixture(), "")
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
	d := Diff(diffFixture(), cur, "")
	if d.Changed || len(d.Counted) != 1 || d.Counted[0].OldCount != 2 || d.Counted[0].Count != 5 {
		t.Fatalf("a new value or count changed the diff: %+v", d)
	}
	cur.Findings[0].Evidence.Highlight[0].Key = "ud[em]"
	if d := Diff(diffFixture(), cur, ""); len(d.Added) != 1 || len(d.Removed) != 1 {
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
	d := Diff(diffFixture(), cur, "")
	if len(d.Removed) != 0 || len(d.Skipped) != 2 || len(d.Trackers) != 0 {
		t.Fatalf("unvisited page counted as fixed: removed %+v skipped %+v trackers %+v", d.Removed, d.Skipped, d.Trackers)
	}

	cur = diffFixture()
	for _, pass := range cur.Passes {
		cur.Pages = append(cur.Pages, Visit{Pass: pass, Page: 3, URL: "https://shop.test/careers", FinalURL: "https://shop.test/careers"})
	}
	cur.Findings = append(cur.Findings, &Finding{Code: CodeTrackerAfterReject, Severity: SevHigh, Pass: PassReject, Page: "/careers", Tracker: "meta-pixel", Name: "Meta Pixel", Count: 1})
	cur.Trackers[1].Fired[PassReject] = []string{"/careers"}
	d = Diff(diffFixture(), cur, "")
	if len(d.Added) != 1 || d.Added[0].Page != "/careers" || len(d.Trackers) != 1 || d.Trackers[0].Kind != TrackerStarted {
		t.Fatalf("new page: %+v %+v", d.Added, d.Trackers)
	}

	// A pass only one audit ran is not compared.
	cur = diffFixture()
	cur.Passes = []string{PassNone, PassAccept}
	d = Diff(diffFixture(), cur, "")
	if d.Changed {
		t.Fatalf("missing reject pass changed the diff: %+v", d)
	}
}

func TestDiffBannerAndWarnings(t *testing.T) {
	cur := diffFixture()
	cur.Site = "https://staging.shop-preview.test/"
	cur.Redacted = true
	cur.Banner = Banner{Found: true, Platform: "cookiebot", Problems: map[string]string{PassReject: "no reject button on /?ref=jane@example.com"}}
	d := Diff(diffFixture(), cur, "never")
	if len(d.Banner) != 2 || !strings.Contains(d.Banner[0], "from OneTrust to Cookiebot") {
		t.Fatalf("banner %q", d.Banner)
	}
	if len(d.Warnings) != 2 {
		t.Fatalf("warnings %q", d.Warnings)
	}
	if !d.Changed || d.Fail {
		t.Fatalf("changed %v fail %v", d.Changed, d.Fail)
	}
}

// Public output (annotations, summary, the CI log) never quotes captured
// data: not the sentence, not a banner problem, not a page's query.
func TestDiffPublic(t *testing.T) {
	old := diffFixture()
	old.Findings = old.Findings[1:]
	cur := diffFixture()
	cur.Findings[0].Page = "/order?email=jane@example.com"
	cur.Banner.Problems = map[string]string{PassReject: "button text quoted jane@example.com"}
	cur.Trackers[1].Fired[PassReject] = []string{"/order?email=jane@example.com"}
	d := Diff(old, cur, "")
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
